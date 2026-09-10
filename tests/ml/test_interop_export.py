"""The Croissant/Parquet dataset export end to end (INTEROP-05..12).

Eager Celery over a file-backed sqlite harness with a real ``FilesystemBlobStore``
and JSONL audit chains, seeded with a succeeded TinyTarget-style campaign whose
per-sample slices (``ml.adv_slice`` / ``ml.clean_slice`` / ``ml.control_slice``)
and ``ml.flip_matrix`` are persisted. The tests prove:

* the manifest validates its own structure and every FileObject digest, and each
  shard reads back with the declared columns and row count;
* the exported rows equal the record (the ``flipped`` column equals the run's
  ``flip_matrix`` oracle), the projection guard refuses a mutated row, and no
  banned content leaves;
* the export is audit-first and idempotent (one export per run, byte-identical
  manifest sha256 on re-export);
* fixture-only, non-terminal and slice-less runs are refused with the right code;
* INTEROP-04 end to end: the classification runner's self-describing slices (clean,
  adversarial with per-sample predictions, control), stored under the filesystem
  store's digest-only locations, export as three families with prediction columns;
  legacy slices fall back to the storage-location label and a non-npz slice is
  skipped with a caveat;
* the routes: ``POST /v1/runs/{id}/dataset`` answers the handle with ``status_url``
  / ``dataset_url`` and ``GET /v1/datasets/{id}`` serves the manifest as ld+json.
"""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("pyarrow")

import numpy as np
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
from sqlalchemy.orm import Session, sessionmaker

from redsim.audit.chain import JsonlAuditWriter, verify_chain
from redsim.config import RedsimConfig
from redsim.db.models import Artifact, Base, Job, Organization, Project, Run, Target
from redsim.ml.schema import CampaignRecord
from redsim.storage import FilesystemBlobStore
from redsim.workers.celery_app import app
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.ml

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
ORG_ID = "org-interop"
PROJECT_ID = "project-interop"
TARGET_ID = "tgt-interop"
CREATOR = "user:alice"
N = 8


def fixture_record() -> CampaignRecord:
    return CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))


def _npz(**arrays: Any) -> bytes:
    buf = io.BytesIO()
    np.savez_compressed(buf, **arrays)
    return buf.getvalue()


def _synthesize_slices(record: CampaignRecord, *, consistent: bool, seed: int = 0
                       ) -> tuple[dict[str, dict[str, bytes]], dict[str, Any]]:
    """Return ``({name: {location_tail: bytes}}, flip_matrix)`` for one seeded run.

    When ``consistent`` the per-sample predictions in the adversarial slices agree
    with the flip_matrix; otherwise one flag is flipped so the projection guard
    must refuse the export.
    """
    rng = np.random.default_rng(seed)
    attacks = list(record.config.attack_ids)
    grid = list(record.config.eps_grid)
    indices = np.arange(N)
    y = rng.integers(0, 3, size=N)
    flip: dict[str, Any] = {"attack_ids": attacks, "eps_grid": grid, "n": N,
                            "indices": [int(i) for i in indices], "flipped": {}}
    slices: dict[str, bytes] = {}
    slices["clean_slice.npz"] = _npz(x=rng.random((N, 3, 8, 8)).astype("float32"),
                                     indices=indices, y=y,
                                     y_pred_clean=y.copy(), conf_clean=rng.random(N))
    for attack in attacks:
        flip["flipped"][attack] = {}
        for eps in grid:
            x_adv = rng.random((N, 3, 8, 8)).astype("float32")
            y_pred_clean = y.copy()
            flip_mask = rng.random(N) < 0.4
            y_pred_adv = np.where(flip_mask, (y + 1) % 3, y)
            flipped = [bool(int(y_pred_clean[i]) == int(y[i]) and int(y_pred_adv[i]) != int(y[i]))
                       for i in range(N)]
            flip["flipped"][attack][f"eps{eps:g}"] = flipped
            slices[f"adv_slice/{attack}_eps{eps:g}.npz"] = _npz(
                x_adv=x_adv, indices=indices, y=y, y_pred_clean=y_pred_clean,
                y_pred_adv=y_pred_adv, conf_clean=rng.random(N), conf_adv=rng.random(N))
    for eps in grid:
        slices[f"control_slice/eps{eps:g}.npz"] = _npz(
            x_adv=rng.random((N, 3, 8, 8)).astype("float32"), indices=indices, y=y)
    if not consistent:
        attack0 = attacks[0]
        tag0 = next(iter(flip["flipped"][attack0]))
        flip["flipped"][attack0][tag0][0] = not flip["flipped"][attack0][tag0][0]
    return slices, flip


def _campaign_table(engine: Any) -> Table:
    table = Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True), Column("project_id", String, nullable=False),
        Column("org_id", String), Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False), Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False), Column("settings_hash", String),
        Column("provenance", JSON), Column("score", JSON), Column("limitations", JSON, nullable=False),
        Column("parent_run_id", String),
        Column("reviewer_notes", Text), Column("created_at", DateTime), Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_jsonb_for_sqlite()
        self.tmp_path = tmp_path
        self.engine = create_engine(f"sqlite:///{tmp_path / 'interop.db'}", future=True)
        Base.metadata.create_all(self.engine)
        self.campaigns = _campaign_table(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.store = FilesystemBlobStore(tmp_path / "blobs")
        self.audit_dir = tmp_path / "audit"
        self.record = fixture_record()
        self.config = RedsimConfig(output_dir=str(tmp_path / "out"))

        @contextmanager
        def get_session() -> Iterator[Session]:
            session = self.sessions()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        self.get_session = get_session
        audit_dir = self.audit_dir

        def jsonl_writer(*_a: Any, **_k: Any) -> JsonlAuditWriter:
            return JsonlAuditWriter(audit_dir)

        monkeypatch.delenv("REDSIM_DB_URL", raising=False)
        monkeypatch.setattr("redsim.db.session.get_session", get_session)
        monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", jsonl_writer)
        monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.config.load_config", lambda *_a, **_k: self.config)
        monkeypatch.setattr("redsim.workers.events._redis_client", lambda: None)
        monkeypatch.setitem(app.conf, "task_always_eager", True)
        monkeypatch.setitem(app.conf, "task_eager_propagates", True)
        self.monkeypatch = monkeypatch
        with self.get_session() as session:
            session.add(Organization(id=ORG_ID, name="Interop", slug="interop-org"))
            session.flush()
            session.add(Project(id=PROJECT_ID, org_id=ORG_ID, name="Interop", slug="interop-project"))

    # -- seeding ---------------------------------------------------------------

    def seed_target(self, *, fixture_only: bool = False) -> None:
        with self.get_session() as session:
            if session.get(Target, TARGET_ID) is not None:
                return
            detail: dict[str, Any] = {"modality": "image", "status": "available", "license": "CC0-1.0"}
            if fixture_only:
                detail["fixture_only"] = True
            session.add(Target(id=TARGET_ID, project_id=PROJECT_ID, kind="ml_model_artifact",
                               value="bundled:tiny", verified=True, detail=detail))

    def seed_run(self, run_id: str, *, status: str = "succeeded", with_slices: bool = True,
                 consistent: bool = True, completeness: str = "complete") -> dict[str, Any]:
        record = self.record.model_copy(update={"run_id": run_id, "completeness": completeness})
        record_bytes = record.model_dump_json().encode()
        with self.get_session() as session:
            session.add(Run(id=run_id, project_id=PROJECT_ID, scanner="ml.campaign",
                            target_id=TARGET_ID, status=status, stage_table={}, created_by=CREATOR))
            session.flush()
            ref = self.store.put(f"{PROJECT_ID}/{run_id}/run_record.json", record_bytes,
                                 content_type="application/json")
            session.add(Artifact(id=f"art-rec-{run_id}", run_id=run_id, project_id=PROJECT_ID,
                                 kind="ml.run_record", sha256=hashlib.sha256(record_bytes).hexdigest(),
                                 location=ref.location, content_type="application/json",
                                 size_bytes=len(record_bytes)))
            session.execute(self.campaigns.insert().values(
                run_id=run_id, project_id=PROJECT_ID, target_id=TARGET_ID, kind="attack",
                modality="image", config=record.config.model_dump(mode="json"), limitations=[]))
            flip: dict[str, Any] = {}
            if with_slices:
                slices, flip = _synthesize_slices(record, consistent=consistent)
                flip_bytes = json.dumps(flip).encode()
                fref = self.store.put(f"{PROJECT_ID}/{run_id}/flip_matrix.json", flip_bytes,
                                      content_type="application/json")
                session.add(Artifact(id=f"art-flip-{run_id}", run_id=run_id, project_id=PROJECT_ID,
                                     kind="ml.flip_matrix", sha256=hashlib.sha256(flip_bytes).hexdigest(),
                                     location=fref.location, content_type="application/json",
                                     size_bytes=len(flip_bytes)))
                for i, (name, data) in enumerate(slices.items()):
                    kind = ("ml.clean_slice" if name.startswith("clean") else
                            "ml.control_slice" if name.startswith("control") else "ml.adv_slice")
                    loc = self.store.base / "datasets" / run_id / name
                    loc.parent.mkdir(parents=True, exist_ok=True)
                    loc.write_bytes(data)
                    session.add(Artifact(id=f"art-slice-{run_id}-{i}", run_id=run_id, project_id=PROJECT_ID,
                                         kind=kind, sha256=hashlib.sha256(data).hexdigest(),
                                         location=str(loc), content_type="application/octet-stream",
                                         size_bytes=len(data)))
        return flip

    def seed_from_sink(self, record: CampaignRecord, artifacts_dir: Path, *, run_id: str | None = None,
                       extra: dict[str, bytes] | None = None) -> str:
        """Persist a runner-written artifact tree the way the worker sink does.

        Every file goes through the ``FilesystemBlobStore`` (a pure digest location, no
        name) and gets the worker's ``Artifact.kind`` for its name; ``extra`` adds
        ``{name: bytes}`` rows (a legacy or foreign slice). Returns the run id.
        """
        from redsim.workers.tasks.ml_campaign import artifact_kind

        run_id = run_id or record.run_id
        record_bytes = record.model_dump_json().encode()
        files: dict[str, bytes] = {
            str(path.relative_to(artifacts_dir)).replace("\\", "/"): path.read_bytes()
            for path in sorted(artifacts_dir.rglob("*")) if path.is_file()
        }
        files.update(extra or {})
        files["run_record.json"] = record_bytes
        with self.get_session() as session:
            session.add(Run(id=run_id, project_id=PROJECT_ID, scanner="ml.campaign", target_id=TARGET_ID,
                            status="succeeded", stage_table={}, created_by=CREATOR))
            session.flush()
            session.execute(self.campaigns.insert().values(
                run_id=run_id, project_id=PROJECT_ID, target_id=TARGET_ID, kind="attack",
                modality=record.config.modality, config=record.config.model_dump(mode="json"), limitations=[]))
            seen: set[tuple[str, str]] = set()
            for i, (name, data) in enumerate(files.items()):
                ref = self.store.put(f"{PROJECT_ID}/{run_id}/{name}/{hashlib.sha256(data).hexdigest()}", data,
                                     content_type="application/octet-stream")
                assert name not in ref.location, "the filesystem store keeps a digest-only path"
                kind = artifact_kind(name)
                if (kind, ref.sha256) in seen:
                    continue   # rows are unique on (run, kind, sha256); the worker sink reuses the row too
                seen.add((kind, ref.sha256))
                session.add(Artifact(id=f"art-{run_id}-{i}", run_id=run_id, project_id=PROJECT_ID,
                                     kind=kind, sha256=ref.sha256, location=ref.location,
                                     content_type="application/octet-stream", size_bytes=len(data)))
        return run_id

    def mount_api(self, *, role: str = "admin") -> Any:
        """A ``TestClient`` over this harness with one member of the project (``role``)."""
        from fastapi.testclient import TestClient

        from redsim.api.app import create_app
        from redsim.api.auth import CurrentUser, get_current_user
        from redsim.api.middleware import rate_limit as rl
        from redsim.api.settings import APISettings

        audit_dir = self.audit_dir
        self.monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: JsonlAuditWriter(audit_dir))
        rl._BUCKETS.clear()
        app_ = create_app(APISettings(
            env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
            rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
        ))
        user = CurrentUser(sub="dev:alice", email="alice@test", project_memberships={PROJECT_ID: role})
        app_.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app_)

    # -- running and reading back ---------------------------------------------

    def admit(self, source_run_id: str, *, include_card: bool = True) -> Any:
        from redsim.services.ml_datasets_export import admit_export

        writer = JsonlAuditWriter(self.audit_dir)
        with self.get_session() as session:
            run = session.get(Run, source_run_id)
            return admit_export(session, run, CREATOR, audit_writer=writer,
                                config=self.config, include_card=include_card)

    def export_manifest(self, source_run_id: str) -> dict[str, Any] | None:
        from redsim.services.ml_datasets_export import get_export_manifest

        with self.get_session() as session:
            return get_export_manifest(session, source_run_id)

    def artifacts(self, run_id: str, kind: str | None = None) -> list[Artifact]:
        with self.sessions() as session:
            rows = session.query(Artifact).filter(Artifact.run_id == run_id).all()
        return [a for a in rows if kind is None or a.kind == kind]

    def chain(self, run_id: str) -> list[dict[str, Any]]:
        return list(JsonlAuditWriter(self.audit_dir).read_chain(f"run:{run_id}"))

    def run_task(self, job_id: str) -> Any:
        from redsim.workers.tasks.dataset_export import dataset_export

        return dataset_export.apply(args=[job_id])


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    h = Harness(tmp_path, monkeypatch)
    h.seed_target()
    return h


# --------------------------------------------------------------------------- happy path


def test_export_writes_a_valid_manifest_and_shards(harness: Harness) -> None:
    from redsim.ml.interop import COLUMNS, croissant_validate, read_table

    harness.seed_run("run-export-0001")
    handle = harness.admit("run-export-0001")
    assert handle.status == "queued" and handle.dataset_id == "run-export-0001"

    manifest = harness.export_manifest("run-export-0001")
    assert manifest is not None
    croissant_validate(manifest)

    parquet_rows = harness.artifacts("run-export-0001", "ml.dataset.parquet")
    manifest_rows = harness.artifacts("run-export-0001", "ml.dataset.manifest")
    card_rows = harness.artifacts("run-export-0001", "ml.dataset.card")
    assert len(manifest_rows) == 1 and len(card_rows) == 1
    # one shard per (attack, eps) + the control family + the clean slice
    n_attacks = len(harness.record.config.attack_ids)
    n_eps = len(harness.record.config.eps_grid)
    assert len(parquet_rows) == n_attacks * n_eps + n_eps + 1

    # every FileObject digest equals a shard's bytes; the manifest lists them all.
    file_shas = {fo["sha256"] for fo in manifest["distribution"]}
    assert file_shas == {row.sha256 for row in parquet_rows}
    for row in parquet_rows:
        data = harness.store.get(str(row.location))
        raw = data.encode() if isinstance(data, str) else bytes(data)
        assert hashlib.sha256(raw).hexdigest() == row.sha256
        table = read_table(raw)
        assert list(table.column_names) == list(COLUMNS)
        assert table.num_rows == N

    # the dataset version is the manifest's own sha256.
    manifest_bytes = harness.store.get(str(manifest_rows[0].location))
    manifest_bytes = manifest_bytes.encode() if isinstance(manifest_bytes, str) else bytes(manifest_bytes)
    assert hashlib.sha256(manifest_bytes).hexdigest() == manifest_rows[0].sha256

    # the follow-up run's chain is audit-first and verifies.
    chain = harness.chain(handle.run_id)
    actions = [row["action"] for row in chain]
    assert actions[0] == "dataset.export"
    assert "dataset.export.execute" in actions and actions[-1] == "job.complete"
    assert verify_chain(chain).verified
    execute = next(r for r in chain if r["action"] == "dataset.export.execute")
    assert execute["success"] and execute["detail"]["manifest_sha256"] == manifest_rows[0].sha256
    # audit detail carries ids/digests/counts only, never a URL, key or model bytes.
    text = json.dumps(chain)
    assert "http://" not in text and "https://" not in text and "s3://" not in text


def test_exported_rows_equal_the_flip_matrix(harness: Harness) -> None:
    from redsim.ml.interop import read_table

    flip = harness.seed_run("run-export-rows")
    harness.admit("run-export-rows")
    for row in harness.artifacts("run-export-rows", "ml.dataset.parquet"):
        table = read_table(bytes(harness.store.get(str(row.location))))
        family = table.column("family").to_pylist()[0]
        if family != "adversarial":
            continue
        attack = table.column("attack").to_pylist()[0]
        eps = table.column("eps").to_pylist()[0]
        oracle = dict(zip(flip["indices"], flip["flipped"][attack][f"eps{eps:g}"]))
        for idx, flipped in zip(table.column("sample_index").to_pylist(),
                                table.column("flipped").to_pylist()):
            assert bool(flipped) == bool(oracle[idx])


# --------------------------------------------------------------------------- the projection guard


def test_export_refuses_a_row_that_disagrees_with_the_record(harness: Harness) -> None:
    from redsim.services.ml_datasets_export import ExportJobHandle, admit_export

    harness.seed_run("run-export-bad", consistent=False)
    # Build the follow-up job through admission, then run the task directly so the
    # guard's refusal is observed as a failed job rather than a broker outage.
    harness.monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    writer = JsonlAuditWriter(harness.audit_dir)
    with harness.get_session() as session:
        run = session.get(Run, "run-export-bad")
        handle = admit_export(session, run, CREATOR, audit_writer=writer, config=harness.config)
    assert isinstance(handle, ExportJobHandle) and handle.job_id is not None

    with harness.sessions() as session:
        job = session.get(Job, handle.job_id)
    assert job is not None and job.status == "failed"
    # no manifest was written and the execute row is a refusal.
    assert harness.artifacts("run-export-bad", "ml.dataset.manifest") == []
    assert harness.artifacts("run-export-bad", "ml.dataset.parquet") == []
    chain = harness.chain(handle.run_id)
    execute = [r for r in chain if r["action"] == "dataset.export.execute"]
    assert execute and all(not r["success"] for r in execute)


# --------------------------------------------------------------------------- idempotency


def test_reexport_is_idempotent(harness: Harness) -> None:
    harness.seed_run("run-export-idem")
    first = harness.admit("run-export-idem")
    manifest_rows = harness.artifacts("run-export-idem", "ml.dataset.manifest")
    parquet_rows = harness.artifacts("run-export-idem", "ml.dataset.parquet")
    assert first.status == "queued" and len(manifest_rows) == 1

    second = harness.admit("run-export-idem")
    assert second.status == "exists"
    assert second.manifest_sha256 == manifest_rows[0].sha256
    # no duplicate rows and no second job.
    assert len(harness.artifacts("run-export-idem", "ml.dataset.manifest")) == 1
    assert len(harness.artifacts("run-export-idem", "ml.dataset.parquet")) == len(parquet_rows)
    with harness.sessions() as session:
        export_jobs = session.query(Job).filter(Job.type == "dataset.export").count()
    assert export_jobs == 1


# --------------------------------------------------------------------------- refusals


def test_refusals(harness: Harness) -> None:
    from redsim.api.errors import ApiError

    # not terminal -> export_unavailable
    harness.seed_run("run-running", status="running")
    with pytest.raises(ApiError) as exc_info:
        harness.admit("run-running")
    assert exc_info.value.code == "export_unavailable"

    # succeeded but no retained slices -> export_unavailable
    harness.seed_run("run-no-slices", with_slices=False)
    with pytest.raises(ApiError) as exc_info:
        harness.admit("run-no-slices")
    assert exc_info.value.code == "export_unavailable"

    # a partial run -> fixture_not_exportable
    harness.seed_run("run-partial", completeness="partial")
    with pytest.raises(ApiError) as exc_info:
        harness.admit("run-partial")
    assert exc_info.value.code == "fixture_not_exportable"

    # every refusal wrote a success=False dataset.export row on the project chain.
    project_chain = list(JsonlAuditWriter(harness.audit_dir).read_chain(f"project:{PROJECT_ID}"))
    refusals = [r for r in project_chain if r["action"] == "dataset.export" and not r["success"]]
    assert len(refusals) >= 3


def test_fixture_target_is_never_exported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redsim.api.errors import ApiError

    h = Harness(tmp_path, monkeypatch)
    h.seed_target(fixture_only=True)
    h.seed_run("run-fixture")
    with pytest.raises(ApiError) as exc_info:
        h.admit("run-fixture")
    assert exc_info.value.code == "fixture_not_exportable"


# --------------------------------------------------------------------------- the card is template-only


def test_card_is_template_only(harness: Harness) -> None:
    import inspect

    import redsim.ml.interop.card as card_module

    source = inspect.getsource(card_module)
    assert "narrative" not in source and "redsim.llm" not in source and "pythia" not in source.lower()

    harness.seed_run("run-card")
    harness.admit("run-card")
    card_rows = harness.artifacts("run-card", "ml.dataset.card")
    assert len(card_rows) == 1
    card_text = bytes(harness.store.get(str(card_rows[0].location))).decode()
    for limitation in harness.record.limitations:
        assert limitation in card_text
    assert "CC0-1.0" in card_text
    from redsim.ml.schema import GRADE_STATEMENT, contains_banned_score_word

    assert not contains_banned_score_word(card_text.replace(GRADE_STATEMENT, ""))


# --------------------------------------------------------------------------- INTEROP-04: runner slices


def _tiny_campaign(tmp_path: Path) -> tuple[CampaignRecord, Path]:
    """One real, complete image campaign (fgsm, three eps, control on) on the TinyTarget.

    The explain stage runs the deterministic fake explainer of ``tests/ml/test_campaign.py`` so the
    record is ``complete`` (the export refuses a partial run); everything else is the real runner.
    """
    import sys

    pytest.importorskip("torch")
    pytest.importorskip("art")
    from redsim.ml.artifacts import FilesystemSink
    from redsim.ml.campaign import run_campaign
    from redsim.ml.schema import CampaignConfig
    from redsim.ml.targets.registry import TARGETS
    from tests.ml.fakes import TinyTarget
    from tests.ml.test_campaign import EXPLAIN_MOD, make_fake_explain

    if TARGETS.maybe_get("tiny") is None:
        TARGETS.register(TinyTarget(seed=0))
    config = CampaignConfig(target_id="tiny", modality="image", attack_ids=["fgsm"], eps_grid=[0.01, 0.03, 0.1],
                            reference_eps=0.03, n_samples=16, seed=0, explain_k=4, dataset_id="synthetic")
    sink = FilesystemSink(tmp_path / "campaign")
    before = sys.modules.get(EXPLAIN_MOD, "__absent__")
    sys.modules[EXPLAIN_MOD] = make_fake_explain(shift=0.4)
    try:
        record = run_campaign(config, sink, explain=True)
    finally:
        if before == "__absent__":
            sys.modules.pop(EXPLAIN_MOD, None)
        else:
            sys.modules[EXPLAIN_MOD] = before
    assert record.completeness == "complete", record.missing
    return record, Path(sink.root) / "artifacts"


def test_runner_slices_are_self_describing() -> None:
    """Every slice the classification runner writes labels itself; the legacy path still parses names."""
    from redsim.ml.interop import parse_npz, slice_descriptor_from_arrays, slice_descriptor_from_location
    from redsim.ml.runners.classification import slice_bytes

    x = np.zeros((4, 3, 2, 2), dtype="float32")
    idx = np.arange(4)
    y = np.array([0, 1, 2, 0])
    clean = parse_npz(slice_bytes(family="clean", attack="", eps=None, x=x, indices=idx, y=y,
                                  y_pred_clean=y, conf_clean=np.full(4, 0.9)))
    assert slice_descriptor_from_arrays(clean) == ("clean", "", None)
    assert set(clean) >= {"x", "indices", "y", "y_pred_clean", "conf_clean", "family", "attack"} and "eps" not in clean
    adv = parse_npz(slice_bytes(family="adversarial", attack="fgsm", eps=0.03, x_adv=x, indices=idx, y=y,
                                y_pred_clean=y, y_pred_adv=(y + 1) % 3, conf_clean=np.full(4, 0.9),
                                conf_adv=np.full(4, 0.6)))
    assert slice_descriptor_from_arrays(adv) == ("adversarial", "fgsm", 0.03)
    ctrl = parse_npz(slice_bytes(family="control", attack="noise_control", eps=0.1, x_adv=x, indices=idx, y=y,
                                 y_pred_clean=y, y_pred_adv=y, conf_clean=np.full(4, 0.9), conf_adv=np.full(4, 0.8)))
    assert slice_descriptor_from_arrays(ctrl) == ("control", "control", 0.1)
    # a legacy slice (arrays only) carries no descriptor; the location parse is the fallback
    legacy = parse_npz(_npz(x_adv=x, indices=idx, y=y))
    assert slice_descriptor_from_arrays(legacy) is None
    assert slice_descriptor_from_location("/blobs/p/run/adv_slice/pgd_eps0.1.npz/abcd") == ("adversarial", "pgd", 0.1)
    assert slice_descriptor_from_location("/blobs/ab/abcdef0123") is None
    # garbage descriptors are not guessed
    assert slice_descriptor_from_arrays({"family": np.asarray("adversarial"), "attack": np.asarray("fgsm")}) is None
    assert slice_descriptor_from_arrays({"family": np.asarray("other")}) is None


def test_live_campaign_exports_clean_adversarial_and_control_shards(harness: Harness, tmp_path: Path) -> None:
    """INTEROP-04 end to end: the runner's slices, stored under digest-only locations, export as three families."""
    from redsim.ml.interop import read_table

    record, artifacts_dir = _tiny_campaign(tmp_path)
    names = sorted(str(p.relative_to(artifacts_dir)) for p in artifacts_dir.rglob("*") if p.is_file())
    assert "clean_slice.npz" in names
    assert {n for n in names if n.startswith("control_slice/")} == {f"control_slice/eps{e:g}.npz" for e in [0.01, 0.03, 0.1]}
    assert {n for n in names if n.startswith("adv_slice/")} == {f"adv_slice/fgsm_eps{e:g}.npz" for e in [0.01, 0.03, 0.1]}

    run_id = harness.seed_from_sink(record, artifacts_dir)
    handle = harness.admit(run_id)
    assert handle.status == "queued"
    manifest = harness.export_manifest(run_id)
    assert manifest is not None
    assert {rs["name"] for rs in manifest["recordSet"]} == {"clean", "adversarial", "control"}

    families: dict[str, int] = {}
    flip = json.loads((artifacts_dir / "flip_matrix.json").read_text())
    for row in harness.artifacts(run_id, "ml.dataset.parquet"):
        table = read_table(bytes(harness.store.get(str(row.location))))
        family = table.column("family").to_pylist()[0]
        families[family] = families.get(family, 0) + 1
        assert table.num_rows == 16
        y_pred_clean = table.column("y_pred_clean").to_pylist()
        conf_clean = table.column("conf_clean").to_pylist()
        assert None not in y_pred_clean and all(0.0 <= c <= 1.0 for c in conf_clean)
        if family == "clean":
            assert set(table.column("y_pred_adv").to_pylist()) == {None}
            assert set(table.column("flipped").to_pylist()) == {None}
            continue
        assert None not in table.column("y_pred_adv").to_pylist()
        assert None not in table.column("conf_adv").to_pylist()
        if family == "adversarial":
            # flipped is computed from the retained predictions and equals the run's oracle
            eps = table.column("eps").to_pylist()[0]
            oracle = dict(zip(flip["indices"], flip["flipped"]["fgsm"][f"eps{eps:g}"]))
            for idx, flipped in zip(table.column("sample_index").to_pylist(), table.column("flipped").to_pylist()):
                assert bool(flipped) == bool(oracle[idx])
    assert families == {"clean": 1, "adversarial": 3, "control": 3}

    chain = harness.chain(handle.run_id)
    execute = next(r for r in chain if r["action"] == "dataset.export.execute")
    assert execute["success"] and execute["detail"]["caveats"] == []
    assert execute["detail"]["projection_checked_against"] == "flip_matrix" and execute["detail"]["n_shards"] == 7


def test_foreign_slice_bytes_are_skipped_with_a_caveat_never_guessed(harness: Harness, tmp_path: Path) -> None:
    """A text-runner JSON-lines ``ml.adv_slice`` and an unlabelled legacy npz are skipped, the rest exports."""
    record, artifacts_dir = _tiny_campaign(tmp_path)
    legacy = _npz(x_adv=np.zeros((2, 3, 8, 8), dtype="float32"), indices=np.arange(2), y=np.zeros(2, dtype="int64"))
    run_id = harness.seed_from_sink(record, artifacts_dir, extra={
        "adv_slice/typo_eps0.5.jsonl": b'{"message": "not an npz"}\n',
        "adv_slice/legacy_eps0.5.npz": legacy,
    })
    handle = harness.admit(run_id)
    manifest = harness.export_manifest(run_id)
    assert manifest is not None and len(harness.artifacts(run_id, "ml.dataset.parquet")) == 7
    execute = next(r for r in harness.chain(handle.run_id) if r["action"] == "dataset.export.execute")
    caveats = execute["detail"]["caveats"]
    assert len(caveats) == 2
    assert any("not an npz slice" in c for c in caveats) and any("no slice descriptor" in c for c in caveats)


def test_unlabelled_slices_only_is_a_refusal(harness: Harness) -> None:
    """Slices that cannot be labelled leave nothing to export: success=False execute row, no artifacts."""
    record = harness.record
    legacy = _npz(x_adv=np.zeros((N, 3, 8, 8), dtype="float32"), indices=np.arange(N), y=np.zeros(N, dtype="int64"))
    empty_dir = harness.tmp_path / "empty-artifacts"
    empty_dir.mkdir()
    run_id = harness.seed_from_sink(record, empty_dir, run_id="run-unlabelled", extra={
        "adv_slice/legacy_eps0.03.npz": legacy,
        "flip_matrix.json": json.dumps({"indices": list(range(N)), "flipped": {}}).encode(),
    })
    # eager Celery: the task's failure must read as a failed job, not as a broker outage at admission
    harness.monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    handle = harness.admit(run_id)
    assert handle.status == "queued" and handle.job_id is not None
    assert harness.artifacts(run_id, "ml.dataset.parquet") == [] and harness.export_manifest(run_id) is None
    execute = [r for r in harness.chain(handle.run_id) if r["action"] == "dataset.export.execute"]
    assert len(execute) == 1 and execute[0]["success"] is False
    assert "no labelled slices" in execute[0]["detail"]["reason"]
    with harness.sessions() as session:
        job = session.get(Job, handle.job_id)
    assert job is not None and job.status == "failed"


# --------------------------------------------------------------------------- routes


def test_export_and_manifest_routes_round_trip(harness: Harness) -> None:
    """``POST /v1/runs/{id}/dataset`` -> 202 handle; ``GET /v1/datasets/{id}`` -> the manifest as ld+json."""
    harness.seed_run("run-route-1")
    client = harness.mount_api()

    assert client.get("/v1/datasets/run-route-1").status_code == 404, "no export exists yet"
    resp = client.post("/v1/runs/run-route-1/dataset")
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "queued" and body["dataset_id"] == "run-route-1" and body["source_run_id"] == "run-route-1"
    assert body["job_ids"] == [body["job_id"]] and body["type"] == "dataset.export"
    assert body["status_url"] == f"/v1/runs/{body['run_id']}" and body["run_id"] != "run-route-1"
    assert body["dataset_url"] == "/v1/datasets/run-route-1"

    resp = client.get("/v1/datasets/run-route-1")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("application/ld+json")
    served = json.loads(resp.content)
    assert served == harness.export_manifest("run-route-1")
    assert served["@type"] == "sc:Dataset"

    # one export per run: the second call answers the existing export, no new job
    again = client.post("/v1/runs/run-route-1/dataset")
    assert again.status_code == 202 and again.json()["status"] == "exists"
    assert again.json()["manifest_sha256"] == hashlib.sha256(json.dumps(served, sort_keys=True).encode()).hexdigest() \
        or again.json()["manifest_sha256"] == harness.artifacts("run-route-1", "ml.dataset.manifest")[0].sha256
    with harness.sessions() as session:
        assert session.query(Job).filter(Job.type == "dataset.export").count() == 1

    # a run without slices is the service's typed refusal through the route; unknown ids are 404
    harness.seed_run("run-route-2", with_slices=False)
    refused = client.post("/v1/runs/run-route-2/dataset")
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "export_unavailable"
    assert client.post("/v1/runs/no-such-run/dataset").status_code == 404
    assert client.get("/v1/datasets/no-such-id").status_code == 404



# --------------------------------------------------------------------------- INTEROP-04: text and detection slices


def _text_slices(record: CampaignRecord, *, seed: int = 1) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Self-describing text slices the way ``redsim.ml.runners.text`` writes them (messages, no tensor)."""
    from redsim.ml.runners.base import slice_bytes

    rng = np.random.default_rng(seed)
    attack, eps = record.config.attack_ids[0], record.config.eps_grid[0]
    indices = np.arange(N)
    y = rng.integers(0, 2, size=N)
    texts = np.asarray([f"message number {i} with some words" for i in range(N)], dtype=str)
    adv_texts = np.asarray([f"message number {i} with some terms" for i in range(N)], dtype=str)
    y_pred_adv = np.where(np.arange(N) % 2 == 0, (y + 1) % 2, y)
    flipped = [bool(int(y[i]) == int(y[i]) and int(y_pred_adv[i]) != int(y[i])) for i in range(N)]
    flip = {"attack_ids": [attack], "eps_grid": [eps], "n": N, "indices": [int(i) for i in indices],
            "flipped": {attack: {f"eps{eps:g}": flipped}}}
    slices = {
        "clean_slice.npz": slice_bytes(family="clean", attack="", eps=None, text=texts, indices=indices, y=y,
                                       y_pred_clean=y, conf_clean=rng.random(N)),
        f"adv_slice/{attack}_eps{eps:g}.npz": slice_bytes(
            family="adversarial", attack=attack, eps=eps, text=texts, text_adv=adv_texts, indices=indices, y=y,
            y_pred_clean=y, y_pred_adv=y_pred_adv, conf_clean=rng.random(N), conf_adv=rng.random(N)),
        f"control_slice/eps{eps:g}.npz": slice_bytes(
            family="control", attack="noise_control", eps=eps, text=texts, text_adv=texts, indices=indices, y=y,
            y_pred_clean=y, y_pred_adv=y, conf_clean=rng.random(N), conf_adv=rng.random(N)),
        # the readable JSON lines the text runner keeps beside the npz: not an export slice, skipped with a caveat
        f"adv_slice/{attack}_eps{eps:g}.jsonl": b'{"index": 0, "text": "message", "label": "ham"}\n',
    }
    return slices, flip


def test_shared_slice_writer_labels_every_family_and_never_pickles() -> None:
    from redsim.ml.interop import parse_npz, slice_descriptor_from_arrays
    from redsim.ml.runners.base import slice_bytes

    texts = np.asarray(["a b", "c d"], dtype=object)      # the text runner samples object arrays
    clean = parse_npz(slice_bytes(family="clean", attack="", eps=None, text=texts, indices=np.arange(2),
                                  y=np.array([0, 1])))
    assert slice_descriptor_from_arrays(clean) == ("clean", "", None)
    assert clean["text"].dtype.kind == "U" and clean["text"].tolist() == ["a b", "c d"], "unicode, not pickled objects"
    det = parse_npz(slice_bytes(family="adversarial", attack="dpatch", eps=0.03,
                                x_adv=np.zeros((2, 3, 4, 4), dtype="float32"), indices=np.arange(2), y=np.array([1, 2]),
                                boxes=np.zeros((3, 4)), labels=np.array([1, 1, 2]), offsets=np.array([0, 2, 3])))
    assert slice_descriptor_from_arrays(det) == ("adversarial", "dpatch", 0.03)
    assert set(det) >= {"x_adv", "indices", "y", "boxes", "labels", "offsets", "family", "attack", "eps"}
    ctrl = parse_npz(slice_bytes(family="control", attack="patch_control", eps=0.1,
                                 x_adv=np.zeros((2, 3, 4, 4), dtype="float32"), indices=np.arange(2), y=np.array([1, 2])))
    assert slice_descriptor_from_arrays(ctrl) == ("control", "control", 0.1)


def test_text_slices_export_all_three_families_with_the_message_in_the_text_column(harness: Harness) -> None:
    """A text run's self-describing slices export as clean, adversarial and control shards; ``input`` is null
    (a text model has no numeric input tensor), ``text`` carries the message, ``flipped`` still equals the oracle."""
    from redsim.ml.interop import COLUMNS, read_table

    record = harness.record.model_copy(update={"run_id": "run-text-export"})
    slices, flip = _text_slices(record)
    empty_dir = harness.tmp_path / "text-artifacts"
    empty_dir.mkdir()
    run_id = harness.seed_from_sink(record, empty_dir, run_id="run-text-export",
                                    extra={**slices, "flip_matrix.json": json.dumps(flip).encode()})
    handle = harness.admit(run_id)
    manifest = harness.export_manifest(run_id)
    assert manifest is not None
    assert {rs["name"] for rs in manifest["recordSet"]} == {"clean", "adversarial", "control"}
    text_fields = [f for rs in manifest["recordSet"] for f in rs["field"] if f["name"] == "text"]
    assert len(text_fields) == 3 and all(f["dataType"] == "sc:Text" for f in text_fields)

    families: dict[str, Any] = {}
    for row in harness.artifacts(run_id, "ml.dataset.parquet"):
        table = read_table(bytes(harness.store.get(str(row.location))))
        assert list(table.column_names) == list(COLUMNS) and table.num_rows == N
        family = table.column("family").to_pylist()[0]
        families[family] = table
        assert set(table.column("input").to_pylist()) == {None}, "no numeric input is invented for a message"
        texts = table.column("text").to_pylist()
        assert all(isinstance(t, str) and t.startswith("message number") for t in texts)
    assert set(families) == {"clean", "adversarial", "control"}
    adv = families["adversarial"]
    assert all("terms" in t for t in adv.column("text").to_pylist()), "the adversarial shard carries the perturbed message"
    assert all("words" in t for t in families["clean"].column("text").to_pylist())
    oracle = dict(zip(flip["indices"], flip["flipped"][record.config.attack_ids[0]][f"eps{record.config.eps_grid[0]:g}"]))
    for idx, flipped in zip(adv.column("sample_index").to_pylist(), adv.column("flipped").to_pylist()):
        assert bool(flipped) == bool(oracle[idx])
    execute = next(r for r in harness.chain(handle.run_id) if r["action"] == "dataset.export.execute")
    assert execute["success"] and execute["detail"]["n_shards"] == 3
    assert len(execute["detail"]["caveats"]) == 1 and "not an npz slice" in execute["detail"]["caveats"][0]


def test_detection_shaped_slices_export_with_the_oracle_flipped_and_no_predictions(harness: Harness) -> None:
    """Detection slices carry the image tensor and packed boxes but no per-image predictions: ``input`` is the
    flattened image, ``y_pred_*`` are null and ``flipped`` comes from the run's flip matrix."""
    from redsim.ml.interop import read_table
    from redsim.ml.runners.base import slice_bytes

    record = harness.record.model_copy(update={"run_id": "run-det-export"})
    attack, eps = record.config.attack_ids[0], record.config.eps_grid[1]
    indices = np.arange(N)
    y = np.ones(N, dtype="int64")
    boxes, labels, offsets = np.zeros((N, 4), dtype="float32"), np.ones(N, dtype="int64"), np.arange(N + 1)
    flipped = [i % 3 == 0 for i in range(N)]
    flip = {"indices": [int(i) for i in indices], "flipped": {attack: {f"eps{eps:g}": flipped}}}
    x = np.random.default_rng(2).random((N, 3, 4, 4)).astype("float32")
    extra = {
        "clean_slice.npz": slice_bytes(family="clean", attack="", eps=None, x=x, indices=indices, y=y,
                                       boxes=boxes, labels=labels, offsets=offsets),
        f"adv_slice/{attack}_eps{eps:g}.npz": slice_bytes(family="adversarial", attack=attack, eps=eps, x_adv=x,
                                                          indices=indices, y=y, boxes=boxes, labels=labels,
                                                          offsets=offsets),
        f"control_slice/eps{eps:g}.npz": slice_bytes(family="control", attack="patch_control", eps=eps, x_adv=x,
                                                     indices=indices, y=y, boxes=boxes, labels=labels, offsets=offsets),
        "flip_matrix.json": json.dumps(flip).encode(),
    }
    empty_dir = harness.tmp_path / "det-artifacts"
    empty_dir.mkdir()
    run_id = harness.seed_from_sink(record, empty_dir, run_id="run-det-export", extra=extra)
    harness.admit(run_id)
    manifest = harness.export_manifest(run_id)
    assert manifest is not None and {rs["name"] for rs in manifest["recordSet"]} == {"clean", "adversarial", "control"}
    for row in harness.artifacts(run_id, "ml.dataset.parquet"):
        table = read_table(bytes(harness.store.get(str(row.location))))
        assert all(len(v) == 3 * 4 * 4 for v in table.column("input").to_pylist())
        assert set(table.column("text").to_pylist()) == {None}
        assert set(table.column("y_pred_adv").to_pylist()) == {None}
        if table.column("family").to_pylist()[0] == "adversarial":
            got = dict(zip(table.column("sample_index").to_pylist(), table.column("flipped").to_pylist()))
            assert got == {int(i): flipped[i] for i in range(N)}
