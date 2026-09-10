"""Review #22, models-API track: F1 (soft delete), F3 (dataset binding), F8 (pre-persist checks).

F1: every upload creates an ``ml.ingest`` Run whose ``target_id`` references the
Target, so a hard ``DELETE /v1/models/{id}`` violated the foreign key after the
in-flight check passed. Deletion is now an audited soft delete through
``services.ml_models.delete_model_target``: the row stays for history, the
catalog hides it, campaign launches are refused, the blob goes.

F3: ``redsim ml build-assets`` writes evaluation splits under
``datasets[<id>].splits[<split>].file``, while the worker binding read a flat
``models[*].eval_split`` and refused every valid upload as
``dataset_incompatible``. The binding now resolves through the datasets mapping
(legacy flat entries still accepted).

F8: ``dataset_id`` and ``license_statement`` were coerced to ``""`` and the
blob, Target, Run and Job were written before anything validated them. They
are checked before a byte is persisted and refused with the spec 17.3 codes.

Offline: sqlite harness from ``tests/conftest.py`` with foreign keys enforced,
an in-memory audit writer, a filesystem blob store in ``tmp_path`` and an
asset manifest built with the real ``redsim.ml.assets.manifest`` models.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import InMemoryAuditWriter
from redsim.config import RedsimConfig
from redsim.db.models import Job, Organization, Project, Run, Target
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    SplitEntry,
    sha256_bytes,
    write_manifest,
)
from redsim.services import ml_models
from redsim.storage.blobs import FilesystemBlobStore

PROJECT = "proj-1"
IMAGE_DS = "hf:example/vehicles"
TABULAR_DS = "kaggle:example/urls"
IMAGE_SPLIT_REL = "datasets/hf--example--vehicles/rev1/test_coarse.npz"
IMAGE_CLASSES = ["Air Defense", "BMP", "Tank"]
IMAGE_CAVEATS = ("example/vehicles is a CI / fixture image dataset (spec 11.1): never a demo target.",
                 "Ground-level photographs; no overhead or infrared imagery.")
# First byte 0x08 with an .onnx name is what ``_sniff`` accepts as ONNX.
ONNX_BYTES = b"\x08\x07\x12\x0eredsim-review22"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_split(root: Path, rel: str, payload: bytes) -> FileEntry:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return FileEntry(path=rel, sha256=sha256_bytes(payload), size_bytes=len(payload))


@pytest.fixture
def assets_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A built asset tree in the shape ``redsim ml build-assets`` writes."""
    root = tmp_path / "assets"
    root.mkdir()
    image_file = _write_split(root, IMAGE_SPLIT_REL, b"npz placeholder: digest-checked, never loaded here")
    tabular_file = _write_split(root, "datasets/kaggle--example--urls/rev2/eval.csv",
                                b"f1,f2,label\n0.1,0.2,benign\n")
    manifest = AssetManifest.new()
    manifest.datasets[IMAGE_DS] = DatasetEntry(
        id=IMAGE_DS, source="huggingface", revision="rev1", license="MIT",
        class_names=IMAGE_CLASSES,
        splits={
            "test_coarse": SplitEntry(name="test_coarse", n=3, file=image_file),
            "train_coarse": SplitEntry(name="train_coarse", n=9),
        },
        preprocessing={"resolution": 128, "layout": "NCHW", "channel_order": "RGB"},
        fixture_only=True, caveats=list(IMAGE_CAVEATS),
    )
    manifest.datasets[TABULAR_DS] = DatasetEntry(
        id=TABULAR_DS, source="kaggle", revision="rev2", license="CC0: Public Domain",
        class_names=["benign", "phishing"],
        splits={
            "eval": SplitEntry(name="eval", n=1, seed=0, file=tabular_file),
            "train": SplitEntry(name="train", n=4, seed=0),
        },
        preprocessing={"features": ["f1", "f2"], "extractor": "redsim.ml.datasets.url_features"},
    )
    write_manifest(manifest, root / MANIFEST_NAME)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(root))
    return root


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        assets_root: Path) -> Iterator[SimpleNamespace]:
    """Dev-mode app over the sqlite harness with real foreign-key enforcement."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    engine = sqlite_session_factory.engine
    raw = engine.raw_connection()
    try:
        raw.cursor().execute("PRAGMA foreign_keys=ON")
    finally:
        raw.close()
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)

    # The write-route limiter keeps a process-global bucket table. Reset it on
    # both sides of this fixture (as tests/test_rate_limit.py does) so request
    # counts never leak into or out of these tests, and give this app caps the
    # upload and delete sequences below cannot reach.
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    user = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin"})
    app.dependency_overrides[get_current_user] = lambda: user
    yield SimpleNamespace(
        client=TestClient(app), Session=sqlite_session_factory.Session,
        writer=writer, blobs=blobs, blob_root=blob_root,
    )
    rl._BUCKETS.clear()


def _seed_upload(api: SimpleNamespace, model_id: str = "m-1", payload: bytes = b"model-bytes-1",
                 run_status: str = "succeeded") -> Path:
    """An uploaded, validated model with its ingest Run and Job, as the worker leaves them."""
    ref = api.blobs.put(f"{PROJECT}/models/{model_id}", payload)
    with api.Session() as sess:
        target = Target(id=model_id, project_id=PROJECT, kind="ml_model_artifact",
                        value=ref.location, verified=True)
        target.detail = {
            "source": "upload", "status": "available", "sha256": ref.sha256, "name": "uploaded",
            "modality": "image", "format": "onnx",
            "manifest": {"status": "available", "sha256": ref.sha256, "dataset_id": IMAGE_DS},
        }
        sess.add(target)
        sess.flush()
        sess.add(Run(id=f"run-{model_id}", project_id=PROJECT, target_id=model_id, mode="api",
                     status=run_status, scanner="ml.ingest", stage_table={}))
        sess.flush()
        sess.add(Job(id=f"job-{model_id}", run_id=f"run-{model_id}", project_id=PROJECT,
                     type="model.validate", status=run_status, detail={"target_id": model_id}))
        sess.commit()
    return Path(ref.location)


def _blob_files(api: SimpleNamespace) -> list[Path]:
    return [p for p in api.blob_root.rglob("*") if p.is_file()]


# ---------------------------------------------------------------------------
# F1: audited soft delete
# ---------------------------------------------------------------------------


def test_delete_model_soft_deletes_and_keeps_history(api: SimpleNamespace) -> None:
    blob_path = _seed_upload(api)
    assert blob_path.is_file()

    resp = api.client.delete("/v1/models/m-1")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == "m-1" and body["status"] == "deleted" and body["blob_deleted"] is True
    assert not blob_path.exists()

    with api.Session() as sess:
        target = sess.get(Target, "m-1")
        run = sess.get(Run, "run-m-1")
        job = sess.get(Job, "job-m-1")
    assert target is not None, "the Target row is retained: the ingest Run references it"
    assert target.detail["status"] == "deleted"
    assert target.detail["previous_status"] == "available"
    assert target.detail["deleted_by"] == "user:dev:admin@test"
    assert target.detail["manifest"]["status"] == "available", "the frozen manifest copy is untouched"
    assert run is not None and run.status == "succeeded" and run.target_id == "m-1"
    assert job is not None and job.status == "succeeded"

    listing = api.client.get("/v1/models", params={"project": PROJECT})
    assert listing.status_code == 200
    assert "m-1" not in {row["id"] for row in listing.json()["models"]}
    assert api.client.get("/v1/models/m-1", params={"project": PROJECT}).status_code == 404
    assert api.client.delete("/v1/models/m-1").status_code == 404

    events = [event for event in api.writer.events if event.action == "target.manage"]
    assert len(events) == 1
    event = events[0]
    assert event.success and event.project_id == PROJECT and event.allowlist_check == "n/a"
    assert event.detail["op"] == "delete"
    assert event.detail["target_id"] == "m-1"
    assert event.detail["kind"] == "ml_model_artifact"
    assert event.detail["soft_delete"] is True

    launch = api.client.post("/v1/models/m-1/attacks", json={"attack_ids": ["fgsm"]})
    assert launch.status_code == 409, launch.text
    assert launch.json()["detail"]["code"] == "model_load_refused"


def test_delete_service_audits_before_mutating_the_row(api: SimpleNamespace) -> None:
    _seed_upload(api, model_id="m-2", payload=b"model-bytes-2")
    seen: dict[str, Any] = {}

    class _Writer(InMemoryAuditWriter):
        def append(self, **event: Any) -> Any:
            with api.Session() as sess:
                seen["status_at_audit"] = sess.get(Target, "m-2").detail["status"]
            return super().append(**event)

    writer = _Writer()
    result = ml_models.delete_model_target(
        target_id="m-2", actor="user:tester", config=RedsimConfig(),
        audit_writer=writer, blob_store=api.blobs,
    )
    assert seen["status_at_audit"] == "available", "the audit event precedes the row change"
    assert result["deleted"] == "m-2" and result["blob_deleted"] is True
    assert [event.action for event in writer.events] == ["target.manage"]
    with pytest.raises(LookupError, match="model_not_found"):
        ml_models.delete_model_target(
            target_id="m-2", actor="user:tester", config=RedsimConfig(),
            audit_writer=writer, blob_store=api.blobs,
        )


def test_delete_model_refuses_while_a_campaign_is_in_flight(api: SimpleNamespace) -> None:
    blob_path = _seed_upload(api, model_id="m-3", payload=b"model-bytes-3", run_status="running")

    resp = api.client.delete("/v1/models/m-3")
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "campaign_in_flight"
    assert blob_path.is_file()
    with api.Session() as sess:
        assert sess.get(Target, "m-3").detail["status"] == "available"
    assert not [event for event in api.writer.events if event.action == "target.manage"]


def test_delete_keeps_a_blob_shared_with_another_live_model(api: SimpleNamespace) -> None:
    first = _seed_upload(api, model_id="m-4", payload=b"identical-bytes")
    second = _seed_upload(api, model_id="m-5", payload=b"identical-bytes")
    assert first == second, "the store is content-addressed"

    resp = api.client.delete("/v1/models/m-4")
    assert resp.status_code == 200 and resp.json()["blob_deleted"] is False
    assert first.is_file()

    resp = api.client.delete("/v1/models/m-5")
    assert resp.status_code == 200 and resp.json()["blob_deleted"] is True
    assert not first.exists()


# ---------------------------------------------------------------------------
# F8: dataset and licence validated before anything is persisted
# ---------------------------------------------------------------------------


def _upload(api: SimpleNamespace, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "source": "upload", "project_id": PROJECT, "name": "review22", "declared_format": "onnx",
        "modality": "image", "license_statement": "MIT, see LICENSE", "dataset_id": IMAGE_DS,
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return api.client.post(
        "/v1/models", data=fields,
        files={"file": ("review22.onnx", ONNX_BYTES, "application/octet-stream")},
    )


def _assert_nothing_persisted(api: SimpleNamespace, reason: str) -> None:
    with api.Session() as sess:
        assert sess.query(Target).count() == 0
        assert sess.query(Run).count() == 0
        assert sess.query(Job).count() == 0
    assert _blob_files(api) == []
    # Wave 2 (G-ASSET11): a refused upload leaves exactly one ``model.register``
    # ``success=False`` row on the project chain, carrying the reason and no bytes.
    assert [(event.action, event.success) for event in api.writer.events] == [("model.register", False)]
    assert api.writer.events[0].project_id == PROJECT
    assert api.writer.events[0].detail["reason"] == reason


@pytest.mark.parametrize(
    ("overrides", "code", "field"),
    [
        ({"license_statement": None}, "license_required", "license_statement"),
        ({"license_statement": "   "}, "license_required", "license_statement"),
        ({"dataset_id": None}, "dataset_incompatible", "dataset_id"),
        ({"dataset_id": "hf:nobody/unknown"}, "dataset_incompatible", "dataset_id"),
        ({"dataset_id": TABULAR_DS}, "dataset_incompatible", "dataset_id"),
        ({"dataset_split": "train_coarse"}, "dataset_incompatible", "dataset_split"),
    ],
    ids=["no-license", "blank-license", "no-dataset", "unknown-dataset", "modality-mismatch",
         "split-without-bundled-file"],
)
def test_upload_is_refused_before_anything_is_persisted(
    api: SimpleNamespace, overrides: dict[str, Any], code: str, field: str,
) -> None:
    resp = _upload(api, **overrides)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == code and detail["field"] == field
    _assert_nothing_persisted(api, code)


def test_upload_without_built_assets_is_refused(
    api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    resp = _upload(api)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "dataset_incompatible" and "manifest is missing" in detail["message"]
    _assert_nothing_persisted(api, "dataset_incompatible")


def test_upload_of_a_phase_b_modality_is_not_implemented(api: SimpleNamespace) -> None:
    resp = _upload(api, modality="llm")
    assert resp.status_code == 501, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "not_implemented" and detail["phase"] == "B"
    _assert_nothing_persisted(api, "not_implemented")


def test_valid_upload_registers_with_the_resolved_binding(
    api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    queued: list[str] = []
    monkeypatch.setattr(
        "redsim.workers.tasks.ml_model.ml_model_validate.delay",
        lambda job_id: (queued.append(job_id), SimpleNamespace(id="celery-review22"))[1],
    )

    resp = _upload(api)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    manifest = body["manifest"]
    assert body["status"] == "validating" and body["source"] == "upload"
    assert manifest["dataset_id"] == IMAGE_DS
    assert manifest["dataset_split"] == "test_coarse", "the dataset's only bundled split, not 'test'"
    assert manifest["dataset_revision"] == "rev1"
    assert manifest["license"] == "MIT, see LICENSE"
    assert manifest["modality"] == "image"
    assert manifest["sha256"] == hashlib.sha256(ONNX_BYTES).hexdigest()

    with api.Session() as sess:
        target = sess.get(Target, body["id"])
        run = sess.get(Run, body["ingest_run_id"])
        job = sess.query(Job).filter(Job.run_id == body["ingest_run_id"]).one()
    assert target is not None and run is not None and run.target_id == body["id"]
    assert job.type == "model.validate" and job.celery_task_id == "celery-review22"
    assert queued == [job.id]
    assert len(_blob_files(api)) == 1
    events = [event.action for event in api.writer.events]
    assert events == ["model.register"]
    assert api.writer.events[0].detail["dataset_id"] == IMAGE_DS


# ---------------------------------------------------------------------------
# F3: the worker binding reads datasets[...].splits[...].file
# ---------------------------------------------------------------------------


def test_evaluation_binding_resolves_through_the_datasets_mapping(assets_root: Path) -> None:
    pytest.importorskip("numpy")  # redsim.ml.targets.bundled imports numpy

    path, class_names, revision, split = ml_models._evaluation_binding(
        IMAGE_DS, dataset_split="test_coarse",
    )
    assert path == (assets_root / IMAGE_SPLIT_REL).resolve()
    assert class_names == IMAGE_CLASSES
    assert revision == "rev1" and split == "test_coarse"

    # No declared split: the dataset's only bundled evaluation split is used.
    assert ml_models._evaluation_binding(IMAGE_DS, dataset_split=None)[3] == "test_coarse"

    # The dataset entry's spec 11.3 caveats ride on the binding and reach an upload's manifest (spec 14.5).
    binding = ml_models.resolve_dataset_binding(IMAGE_DS, dataset_split="test_coarse", root=assets_root)
    assert binding.fixture_only is True and binding.caveats == list(IMAGE_CAVEATS)
    assert ml_models.evaluation_caveats(IMAGE_DS, dataset_split="test_coarse") == list(IMAGE_CAVEATS)
    assert ml_models.evaluation_caveats(TABULAR_DS, dataset_split=None) == []
    assert ml_models.evaluation_caveats("hf:nobody/unknown", dataset_split=None) == []
    tabular = ml_models._evaluation_binding(TABULAR_DS, dataset_split="")
    assert tabular[3] == "eval" and tabular[1] == ["benign", "phishing"] and tabular[2] == "rev2"


def test_evaluation_binding_refuses_unknown_dataset_missing_split_and_digest_drift(
    assets_root: Path,
) -> None:
    pytest.importorskip("numpy")
    from redsim.ml.errors import UnsupportedArtifact

    with pytest.raises(UnsupportedArtifact, match="dataset_incompatible: unknown bundled dataset"):
        ml_models._evaluation_binding("hf:nobody/unknown", dataset_split=None)
    with pytest.raises(UnsupportedArtifact, match="dataset_incompatible: .*train_coarse"):
        ml_models._evaluation_binding(IMAGE_DS, dataset_split="train_coarse")
    with pytest.raises(UnsupportedArtifact, match="dataset_incompatible: dataset_id is required"):
        ml_models._evaluation_binding("", dataset_split=None)

    (assets_root / IMAGE_SPLIT_REL).write_bytes(b"tampered slice")
    with pytest.raises(UnsupportedArtifact, match="sha256"):
        ml_models._evaluation_binding(IMAGE_DS, dataset_split="test_coarse")


def test_artifact_target_from_path_accepts_a_valid_upload(assets_root: Path, tmp_path: Path) -> None:
    pytest.importorskip("numpy")
    model_file = tmp_path / "upload.onnx"
    model_file.write_bytes(ONNX_BYTES)
    detail = {
        "source": "upload",
        "manifest": {
            "name": "review22", "modality": "image", "format": "onnx",
            "sha256": hashlib.sha256(ONNX_BYTES).hexdigest(),
            "dataset_id": IMAGE_DS, "license": "MIT",
        },
    }
    # Before F3 this raised dataset_incompatible for every upload. Building the
    # target does not load the model; that happens in the sandbox child.
    target = ml_models.artifact_target_from_path("m-up", model_file, detail)
    assert target.id == "m-up"


def test_resolve_dataset_binding_still_accepts_legacy_flat_entries() -> None:
    document = {
        "models": {
            "legacy_cnn": {
                "dataset_id": "hf:legacy/ds", "dataset_split": "test", "modality": "image",
                "eval_split": "datasets/legacy/test.npz", "eval_split_sha256": "ab" * 32,
                "class_names": ["a", "b"], "dataset_revision": "r9",
            },
        },
    }
    binding = ml_models.resolve_dataset_binding("hf:legacy/ds", document=document)
    assert binding.legacy is True
    assert binding.file_path == "datasets/legacy/test.npz"
    assert binding.file_sha256 == "ab" * 32
    assert binding.class_names == ["a", "b"] and binding.revision == "r9"
    assert binding.modality == "image" and binding.split == "test"
    with pytest.raises(ml_models.DatasetBindingError, match="unknown bundled dataset"):
        ml_models.resolve_dataset_binding("hf:legacy/other", document=document)


def test_check_upload_dataset_enforces_modality(assets_root: Path) -> None:
    with pytest.raises(ml_models.DatasetBindingError, match="tabular dataset"):
        ml_models.check_upload_dataset(TABULAR_DS, modality="image")
    binding = ml_models.check_upload_dataset(TABULAR_DS, modality="tabular")
    assert binding.split == "eval" and binding.modality == "tabular"
    image = ml_models.check_upload_dataset(IMAGE_DS, modality="image")
    assert image.split == "test_coarse" and image.modality == "image" and image.legacy is False
