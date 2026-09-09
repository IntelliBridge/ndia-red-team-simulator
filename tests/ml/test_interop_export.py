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
* fixture-only, non-terminal and slice-less runs are refused with the right code.
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
        Column("baseline_run_id", String), Column("parent_run_id", String),
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
