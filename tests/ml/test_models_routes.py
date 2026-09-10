"""G-API-MODELS, G-ASSET8, G-ASSET11, G-ASSET4, G-API-TARGETS: the models routes.

Offline sqlite harness (``tests/conftest.py``) with foreign keys on, an
in-memory audit writer, a filesystem blob store and an asset tree written with
the real ``redsim.ml.assets.manifest`` models: ``vehicles_cnn`` is a bundled
demo model with verifiable weights and an evaluation split, ``cifar10_smallcnn``
is a fixture-only entry, ``url_trees`` is in the registry but has no built
assets. No ML library is imported: nothing here loads a model.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")  # the target registry imports numpy at module import

from fastapi.testclient import TestClient

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Job, Organization, Project, Run, Target
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    ModelEntry,
    SplitEntry,
    sha256_bytes,
    stamp_manifest_sha256,
    write_manifest,
)
from redsim.ml.schema import CleanAccuracy
from redsim.services import ml_models
from redsim.storage.blobs import FilesystemBlobStore

PROJECT = "proj-1"
OTHER = "proj-2"
IMAGE_DS = "hf:example/vehicles"
CIFAR_DS = "hf:uoft-cs/cifar10"
TABULAR_DS = "kaggle:example/urls"
IMAGE_CLASSES = ["Air Defense", "BMP", "Tank"]
WEIGHTS = b"PK\x03\x04 not a real state_dict, digest-checked only"
ONNX_BYTES = b"\x08\x07\x12\x0eredsim-wave2"
ZIP_BYTES = b"PK\x03\x04" + b"\x00" * 28
PICKLE_BYTES = b"\x80\x04\x95" + b"\x00" * 13


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write(root: Path, rel: str, payload: bytes) -> FileEntry:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return FileEntry(path=rel, sha256=sha256_bytes(payload), size_bytes=len(payload))


def _model(model_id: str, weights: FileEntry, dataset_id: str, split: str, classes: list[str],
           **over: Any) -> ModelEntry:
    base: dict[str, Any] = {
        "id": model_id, "name": f"{model_id} (test build)", "modality": "image", "format": "torch_state_dict",
        "sha256": weights.sha256, "size_bytes": weights.size_bytes, "file": weights,
        "architecture_id": "small_cnn",
        "architecture": {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": len(classes), "image_size": 8},
        "input_shape": [3, 8, 8], "n_classes": len(classes), "class_names": classes,
        "dataset_id": dataset_id, "dataset_revision": "rev1", "dataset_split": split, "train_split": "train",
        "seed": 0, "epochs": 1, "gradients": True, "license": "MIT",
        "clean_accuracy": CleanAccuracy(value=0.5, n=4, split=split), "metrics": {"clean_accuracy": 0.5, "n": 4},
    }
    base.update(over)
    return stamp_manifest_sha256(ModelEntry(**base))


@pytest.fixture
def assets_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A built asset tree in the shape ``redsim ml build-assets`` writes."""
    root = tmp_path / "assets"
    root.mkdir()
    image_split = _write(root, "datasets/hf--example--vehicles/rev1/test_coarse.npz", b"npz placeholder")
    cifar_split = _write(root, "datasets/hf--uoft-cs--cifar10/rev1/test.npz", b"cifar placeholder")
    tabular_split = _write(root, "datasets/kaggle--example--urls/rev2/eval.csv", b"f1,f2,label\n0.1,0.2,benign\n")
    vehicles_weights = _write(root, "bundled/vehicles_cnn/weights.pt", WEIGHTS)
    cifar_weights = _write(root, "bundled/cifar10_smallcnn/weights.pt", WEIGHTS + b"-cifar")

    manifest = AssetManifest.new()
    manifest.datasets[IMAGE_DS] = DatasetEntry(
        id=IMAGE_DS, source="huggingface", revision="rev1", license="MIT", url="https://hf.example/vehicles",
        class_names=IMAGE_CLASSES,
        splits={"test_coarse": SplitEntry(name="test_coarse", n=4, file=image_split),
                "train_coarse": SplitEntry(name="train_coarse", n=9)},
        preprocessing={"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
    )
    manifest.datasets[CIFAR_DS] = DatasetEntry(
        id=CIFAR_DS, source="huggingface", revision="rev1", license="MIT", class_names=[f"c{i}" for i in range(10)],
        splits={"test": SplitEntry(name="test", n=4, file=cifar_split)}, fixture_only=True,
        preprocessing={"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
    )
    manifest.datasets[TABULAR_DS] = DatasetEntry(
        id=TABULAR_DS, source="kaggle", revision="rev2", license="CC0: Public Domain",
        class_names=["benign", "phishing"],
        splits={"eval": SplitEntry(name="eval", n=1, seed=0, file=tabular_split)},
        preprocessing={"features": ["f1", "f2"], "extractor": "redsim.ml.datasets.url_features"},
    )
    manifest.models["vehicles_cnn"] = _model("vehicles_cnn", vehicles_weights, IMAGE_DS, "test_coarse", IMAGE_CLASSES)
    manifest.models["cifar10_smallcnn"] = _model(
        "cifar10_smallcnn", cifar_weights, CIFAR_DS, "test", [f"c{i}" for i in range(10)], fixture_only=True,
        architecture={"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 10, "image_size": 8},
    )
    write_manifest(manifest, root / MANIFEST_NAME)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(root))
    return root


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        assets_root: Path) -> Iterator[SimpleNamespace]:
    """Dev-mode app over the sqlite harness with foreign keys enforced; admin on two projects."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    engine = sqlite_session_factory.engine
    raw = engine.raw_connection()
    try:
        raw.cursor().execute("PRAGMA foreign_keys=ON")
    finally:
        raw.close()
    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    # The targets route binds the resolver at import time (tests/test_api_routes_coverage.py patches it there).
    monkeypatch.setattr("redsim.api.v1.targets.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)
    monkeypatch.delenv("REDSIM_ML_UPLOAD_MAX_MB", raising=False)
    monkeypatch.setattr("redsim.workers.tasks.ml_model.ml_model_validate.delay",
                        lambda job_id: SimpleNamespace(id=f"celery-{job_id}"))

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    user = CurrentUser(sub="dev:admin@test", email="admin@test",
                       project_memberships={PROJECT: "admin", OTHER: "admin"})
    app.dependency_overrides[get_current_user] = lambda: user
    yield SimpleNamespace(
        client=TestClient(app), Session=sqlite_session_factory.Session, engine=engine,
        writer=writer, blobs=blobs, blob_root=blob_root, assets_root=assets_root,
    )
    rl._BUCKETS.clear()


def _upload(api: SimpleNamespace, *, filename: str = "model.onnx", payload: bytes = ONNX_BYTES,
            params: dict[str, str] | None = None, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "source": "upload", "project_id": PROJECT, "name": "wave2", "declared_format": "onnx",
        "modality": "image", "license_statement": "MIT, see LICENSE", "dataset_id": IMAGE_DS,
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return api.client.post("/v1/models", data=fields, params=params or {},
                           files={"file": (filename, payload, "application/octet-stream")})


def _events(api: SimpleNamespace, action: str) -> list[Any]:
    return [event for event in api.writer.events if event.action == action]


def _blob_files(api: SimpleNamespace) -> list[Path]:
    return [p for p in api.blob_root.rglob("*") if p.is_file()]


def _seed_upload(api: SimpleNamespace, model_id: str, payload: bytes = b"model-bytes", project: str = PROJECT) -> None:
    ref = api.blobs.put(f"{project}/models/{model_id}/model.onnx", payload)
    with api.Session() as sess:
        target = Target(id=model_id, project_id=project, kind="ml_model_artifact", value=ref.location, verified=True)
        target.detail = {
            "source": "upload", "status": "available", "sha256": ref.sha256, "name": "uploaded",
            "modality": "image", "format": "onnx",
            "manifest": {"status": "available", "sha256": ref.sha256, "dataset_id": IMAGE_DS},
        }
        sess.add(target)
        sess.flush()
        sess.add(Run(id=f"run-ingest-{model_id}", project_id=project, target_id=model_id, mode="api",
                     status="succeeded", scanner="ml.ingest", stage_table={}))
        sess.commit()


# ---------------------------------------------------------------------------
# Upload refusals: spec 17.3 codes, success=False audit row, nothing persisted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "status", "code", "field"),
    [
        (dict(filename="model.pkl", payload=PICKLE_BYTES), 415, "pickle_refused", "file"),
        (dict(filename="model.onnx", payload=PICKLE_BYTES), 415, "pickle_refused", "file"),
        (dict(filename="model.onnx", payload=b"\x00\x01\x02\x03"), 415, "unsupported_model_format", "file"),
        (dict(filename="model.onnx", payload=b""), 415, "unsupported_model_format", "file"),
        (dict(filename="model.pt", payload=ZIP_BYTES), 415, "unsupported_model_format", "declared_format"),
        (dict(declared_format="pickle"), 415, "unsupported_model_format", "declared_format"),
        (dict(filename="model.pt", payload=ZIP_BYTES, declared_format="torch_state_dict"),
         422, "architecture_required", "architecture_id"),
        (dict(filename="model.pt", payload=ZIP_BYTES, declared_format="torch_state_dict", architecture_id="vgg99"),
         422, "architecture_not_allowlisted", "architecture_id"),
        (dict(dataset_id="hf:nobody/unknown"), 422, "dataset_incompatible", "dataset_id"),
        (dict(dataset_id=TABULAR_DS), 422, "dataset_incompatible", "dataset_id"),
        (dict(dataset_id=None), 422, "dataset_incompatible", "dataset_id"),
        (dict(license_statement=None), 422, "license_required", "license_statement"),
        (dict(modality="llm"), 501, "not_implemented", "modality"),
    ],
    ids=["pkl-suffix", "pickle-opcode", "unknown-magic", "empty-file", "declared-onnx-got-zip",
         "declared-format-off-table", "state-dict-without-architecture", "architecture-not-allowlisted",
         "unknown-dataset", "dataset-modality-mismatch", "no-dataset", "no-license", "phase-b-modality"],
)
def test_upload_refusal_codes_and_audit(
    api: SimpleNamespace, kwargs: dict[str, Any], status: int, code: str, field: str,
) -> None:
    resp = _upload(api, **kwargs)
    assert resp.status_code == status, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == code and detail["field"] == field
    if code == "not_implemented":
        assert detail["phase"] == "B"

    # Spec 9.3 step 2 / 5.11: one model.register success=False row on the project chain, and no bytes kept.
    events = _events(api, "model.register")
    assert len(events) == 1 and api.writer.events == events
    event = events[0]
    assert event.success is False and event.project_id == PROJECT and event.allowlist_check == "n/a"
    assert event.detail["reason"] == code
    assert event.detail["source"] == "upload" and event.detail["kind"] == "ml_model_artifact"
    assert event.detail["field"] == field
    assert "sha256" not in event.detail or event.detail["sha256"] is None
    serialized = json.dumps(event.detail, default=str)
    assert ONNX_BYTES.decode("latin-1") not in serialized and "PK\\u0003" not in serialized
    with api.Session() as sess:
        assert sess.query(Target).count() == 0 and sess.query(Run).count() == 0 and sess.query(Job).count() == 0
    assert _blob_files(api) == []


def test_upload_size_cap_and_content_length(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSIM_ML_UPLOAD_MAX_MB", "1")
    too_big = b"\x08" + b"\x00" * (1024 * 1024)      # 1 MiB + 1 byte, ONNX-looking head
    resp = _upload(api, filename="big.onnx", payload=too_big, params={"project": PROJECT})
    assert resp.status_code == 413, resp.text
    assert resp.json()["detail"]["code"] == "model_too_large"
    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is False and events[0].project_id == PROJECT
    assert events[0].detail["reason"] == "model_too_large"
    assert _blob_files(api) == []

    # Spec 17.3: Content-Length is required. A chunked body carries none.
    boundary = "redsimboundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"source\"\r\n\r\nupload\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"project_id\"\r\n\r\n{PROJECT}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"m.onnx\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + ONNX_BYTES + f"\r\n--{boundary}--\r\n".encode()
    resp = api.client.post(
        "/v1/models", content=iter([body]), params={"project": PROJECT},
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 411, resp.text
    refusals = [event for event in _events(api, "model.register") if event.detail.get("reason") == "length_required"]
    assert len(refusals) == 1 and refusals[0].success is False
    with api.Session() as sess:
        assert sess.query(Target).count() == 0
    assert _blob_files(api) == []


def test_upload_success_writes_blob_key_rows_and_audit(api: SimpleNamespace) -> None:
    resp = _upload(api, filename="my model (v2).onnx")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    model_id = body["id"]
    assert body["status"] == "validating" and body["source"] == "upload" and body["registered"] is True
    assert body["manifest"]["sha256"] == hashlib.sha256(ONNX_BYTES).hexdigest()
    assert body["manifest"]["class_names"] == IMAGE_CLASSES and body["manifest"]["n_classes"] == 3
    assert body["validation"] == {"ingest_job_id": body["ingest_job_id"], "ingest_run_id": body["ingest_run_id"]}
    assert body["enqueued"] is True and body["campaign_history"] == []

    with api.Session() as sess:
        target = sess.get(Target, model_id)
        run = sess.get(Run, body["ingest_run_id"])
        job = sess.get(Job, body["ingest_job_id"])
    assert target is not None and run is not None and job is not None
    assert target.detail["blob"]["key"] == f"{PROJECT}/models/{model_id}/my_model_v2.onnx"
    assert Path(target.value).is_file() and target.value == target.detail["blob"]["location"]
    assert run.scanner == "ml.ingest" and run.target_id == model_id and job.type == "model.validate"
    assert job.celery_task_id == f"celery-{job.id}"

    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is True
    detail = events[0].detail
    assert detail["target_id"] == model_id and detail["source"] == "upload"
    assert detail["blob_key"] == target.detail["blob"]["key"]
    assert detail["sha256"] == body["manifest"]["sha256"] and detail["size_bytes"] == len(ONNX_BYTES)
    assert detail["ingest_run_id"] == body["ingest_run_id"] and detail["declared_format"] == "onnx"
    assert detail["filename"] == "my_model_v2.onnx"


# ---------------------------------------------------------------------------
# Bundled registration: per-project ids, 409, 404, verification
# ---------------------------------------------------------------------------


def _register(api: SimpleNamespace, bundled_id: str, project: str = PROJECT) -> Any:
    return api.client.post("/v1/models", json={"source": "bundled", "project_id": project, "bundled_id": bundled_id})


def test_bundled_register_two_projects_and_409(api: SimpleNamespace) -> None:
    first = _register(api, "vehicles_cnn")
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["id"] != "vehicles_cnn" and body["bundled_id"] == "vehicles_cnn" and body["registered"] is True
    assert body["status"] == "available" and body["source"] == "bundled" and body["format"] == "torch_state_dict"
    assert body["manifest"]["sha256"] == sha256_bytes(WEIGHTS) and body["manifest"]["bundled"] is True
    assert body["validation"]["detected_format"] == "torch_state_dict" and body["validation"]["gradients"] is True
    assert body["campaign_history"] == []
    with api.Session() as sess:
        target = sess.get(Target, body["id"])
    assert target is not None and target.value == "bundled:vehicles_cnn" and target.project_id == PROJECT
    assert target.detail["blob"]["key"] == "ml/assets/bundled/vehicles_cnn/weights.pt"
    assert Path(target.detail["blob"]["location"]).read_bytes() == WEIGHTS, "the weights were copied to the blob store"

    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is True
    detail = events[0].detail
    assert detail["source"] == "bundled" and detail["bundled_id"] == "vehicles_cnn"
    assert detail["target_id"] == body["id"] and detail["sha256"] == sha256_bytes(WEIGHTS)
    assert detail["dataset_id"] == IMAGE_DS and detail["architecture_id"] == "small_cnn"

    dup = _register(api, "vehicles_cnn")
    assert dup.status_code == 409, dup.text
    assert dup.json()["detail"]["code"] == "already_registered"
    assert dup.json()["detail"]["target_id"] == body["id"]
    refused = [event for event in _events(api, "model.register") if not event.success]
    assert len(refused) == 1 and refused[0].detail["reason"] == "already_registered"

    second = _register(api, "vehicles_cnn", project=OTHER)
    assert second.status_code == 201, second.text
    assert second.json()["id"] not in {"vehicles_cnn", body["id"]} and second.json()["project_id"] == OTHER
    with api.Session() as sess:
        rows = sess.query(Target).filter(Target.value == "bundled:vehicles_cnn").all()
    assert {row.project_id for row in rows} == {PROJECT, OTHER}

    listing = api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]
    vehicles = [row for row in listing if row["bundled_id"] == "vehicles_cnn"]
    assert len(vehicles) == 1 and vehicles[0]["id"] == body["id"], "a registered bundled model is listed once"

    unknown = _register(api, "no_such_model")
    assert unknown.status_code == 404, unknown.text
    assert unknown.json()["detail"]["code"] == "not_found"
    assert unknown.json()["detail"]["reason"] == "unknown_bundled_model"

    fixture = _register(api, "cifar10_smallcnn")
    assert fixture.status_code == 404, fixture.text
    assert fixture.json()["detail"]["reason"] == "unknown_bundled_model"

    unbuilt = _register(api, "url_trees")
    assert unbuilt.status_code == 409, unbuilt.text
    assert unbuilt.json()["detail"]["code"] == "model_load_refused"
    assert unbuilt.json()["detail"]["refusal_reason"] == "bundled_assets_missing"

    # Phase B (ENDPOINT-23): source=endpoint is admitted field by field; an empty body is a
    # 422 refusal on its first missing field, audited like the other refusals.
    endpoint = api.client.post("/v1/models", json={"source": "endpoint", "project_id": PROJECT})
    assert endpoint.status_code == 422, endpoint.text
    assert endpoint.json()["detail"]["code"] == "endpoint_url_invalid"
    assert endpoint.json()["detail"]["field"] == "url"
    assert all(not e.success for e in _events(api, "model.register")[-4:]), "every refusal wrote a success=False row"
    with api.Session() as sess:
        assert sess.query(Target).count() == 2


def test_bundled_register_refuses_tampered_assets(api: SimpleNamespace) -> None:
    (api.assets_root / "bundled/vehicles_cnn/weights.pt").write_bytes(b"tampered weights")
    resp = _register(api, "vehicles_cnn")
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "model_load_refused" and detail["refusal_reason"] == "assets_unverified"
    assert any("sha256 mismatch" in reason for reason in detail["reasons"])
    assert _blob_files(api) == []
    with api.Session() as sess:
        assert sess.query(Target).count() == 0
    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is False


def test_register_bundled_model_service_audits_before_rows(api: SimpleNamespace) -> None:
    """The service the wave-3 ``redsim ml seed`` calls: audit row first, then blob, then Target."""
    from redsim.config import RedsimConfig

    seen: dict[str, Any] = {}

    class _Writer(InMemoryAuditWriter):
        def append(self, **event: Any) -> Any:
            with api.Session() as sess:
                seen["targets_at_audit"] = sess.query(Target).count()
            seen["blobs_at_audit"] = len(_blob_files(api))
            return super().append(**event)

    writer = _Writer()
    with api.Session() as sess:
        target = ml_models.register_bundled_model(
            sess, PROJECT, "vehicles_cnn", "cli:seed", audit_writer=writer, config=RedsimConfig(),
            blob_store=api.blobs,
        )
        sess.commit()
        target_id = target.id
    assert seen == {"targets_at_audit": 0, "blobs_at_audit": 0}
    assert [event.action for event in writer.events] == ["model.register"]
    assert writer.events[0].detail["target_id"] == target_id
    with api.Session() as sess:
        row = sess.get(Target, target_id)
    assert row is not None and row.detail["bundled_id"] == "vehicles_cnn" and row.detail["status"] == "available"

    # A legacy build id resolves to the registry id and is a duplicate now.
    from redsim.api.errors import ApiError

    with api.Session() as sess, pytest.raises(ApiError) as excinfo:
        ml_models.register_bundled_model(sess, PROJECT, "vehicles_cnn", "cli:seed", audit_writer=writer,
                                         config=RedsimConfig(), blob_store=api.blobs)
    assert excinfo.value.code == "already_registered"
    assert ml_models.canonical_bundled_id("url_classifier") == "url_trees"


# ---------------------------------------------------------------------------
# Catalog listing: deleted rows hidden, fixtures never shown, LLM row honest
# ---------------------------------------------------------------------------


def test_list_hides_deleted_and_fixture_only(api: SimpleNamespace) -> None:
    _seed_upload(api, "m-up")
    registered = _register(api, "vehicles_cnn").json()

    listing = api.client.get("/v1/models", params={"project": PROJECT})
    assert listing.status_code == 200
    rows = {row["id"]: row for row in listing.json()["models"]}
    assert "m-up" in rows and registered["id"] in rows
    assert "cifar10_smallcnn" not in rows, "fixture-only targets are never listed (G-ASSET8)"
    assert "vehicles_cnn" not in rows, "the registered row replaces the unregistered catalog entry"
    llm = rows["endpoint_stub"]
    assert llm["status"] == "not_implemented" and llm["reason"] and llm["phase"] == "B"
    assert llm["source"] == "endpoint" and llm["modality"] == "llm" and llm["last_run_id"] is None
    assert set(llm["manifest"]) == {"phase", "kind", "gateway", "configured"}, "env var names and flags only"
    trees = rows["url_trees"]
    assert trees["status"] == "not_implemented" and "not found" in trees["reason"] and trees["registered"] is False
    assert all("last_run_id" in row for row in rows.values())

    assert api.client.delete("/v1/models/m-up").status_code == 200
    assert api.client.delete(f"/v1/models/{registered['id']}").status_code == 200
    after = {row["id"]: row for row in api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]}
    assert "m-up" not in after and registered["id"] not in after
    assert after["vehicles_cnn"]["registered"] is False, "a deleted bundled registration shows as unregistered again"
    assert api.client.get("/v1/models/m-up", params={"project": PROJECT}).status_code == 404
    assert api.client.get("/v1/models/cifar10_smallcnn", params={"project": PROJECT}).status_code == 404
    unregistered = api.client.get("/v1/models/vehicles_cnn", params={"project": PROJECT})
    assert unregistered.status_code == 200 and unregistered.json()["registered"] is False

    # Re-registering after a soft delete creates a new row rather than colliding.
    again = _register(api, "vehicles_cnn")
    assert again.status_code == 201 and again.json()["id"] != registered["id"]


def _campaign_table(engine: Any) -> Any:
    from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text

    table = Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True), Column("project_id", String, nullable=False),
        Column("org_id", String), Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False), Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False), Column("settings_hash", String),
        Column("provenance", JSON), Column("score", JSON), Column("limitations", JSON, nullable=False),
        Column("parent_run_id", String), Column("reviewer_notes", Text),
        Column("created_at", DateTime), Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


def test_detail_campaign_history_and_last_run_id(api: SimpleNamespace) -> None:
    _seed_upload(api, "m-hist")
    now = datetime.now(UTC)
    with api.Session() as sess:
        sess.add(Run(id="run-old", project_id=PROJECT, target_id="m-hist", mode="api", status="succeeded",
                     scanner="ml.campaign", stage_table={}, created_at=now - timedelta(hours=2),
                     completed_at=now - timedelta(hours=1)))
        sess.add(Run(id="run-new", project_id=PROJECT, target_id="m-hist", mode="api", status="running",
                     scanner="ml.campaign", stage_table={}, created_at=now - timedelta(minutes=5)))
        sess.commit()

    # Without the migration-owned table the history comes from Run rows and says so.
    detail = api.client.get("/v1/models/m-hist").json()
    assert detail["last_run_id"] == "run-new"
    assert [entry["run_id"] for entry in detail["campaign_history"]] == ["run-new", "run-old"]
    assert [entry["kind"] for entry in detail["campaign_history"]] == ["attack", "attack"]
    assert detail["campaign_history"][0]["score_status"] == "pending"
    assert detail["campaign_history"][1]["score_status"] == "unavailable"
    assert all(entry["campaign_record"] == "unavailable" for entry in detail["campaign_history"])
    assert all(entry["scorecard_url"] is None for entry in detail["campaign_history"])
    listing = {row["id"]: row for row in api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]}
    assert listing["m-hist"]["last_run_id"] == "run-new"

    table = _campaign_table(api.engine)
    with api.Session() as sess:
        sess.execute(table.insert().values(
            run_id="run-old", project_id=PROJECT, target_id="m-hist", kind="attack", modality="image",
            config={"attack_ids": ["fgsm", "pgd"], "reference_eps": 0.03, "eps_grid": [0.01, 0.03, 0.1]},
            settings_hash="a" * 64, score={"mri": 0.42}, limitations=[],
        ))
        sess.execute(table.insert().values(
            run_id="run-new", project_id=PROJECT, target_id="m-hist", kind="attack", modality="image",
            config={"attack_ids": ["fgsm"], "reference_eps": 0.03}, settings_hash="a" * 64, limitations=[],
        ))
        sess.commit()
    history = api.client.get("/v1/models/m-hist").json()["campaign_history"]
    old = next(entry for entry in history if entry["run_id"] == "run-old")
    new = next(entry for entry in history if entry["run_id"] == "run-new")
    assert old["attack_ids"] == ["fgsm", "pgd"] and old["reference_eps"] == 0.03 and old["settings_hash"] == "a" * 64
    assert old["score_status"] == "scored" and old["scorecard_url"] == "/v1/runs/run-old/campaign"
    assert "mri" not in json.dumps(old), "the MRI is a link into the scorecard, never a bare number in a list"
    assert "baseline_run_id" not in new and new["score_status"] == "pending" and new["scorecard_url"] is None
    assert "campaign_record" not in old


# ---------------------------------------------------------------------------
# POST /v1/targets refuses ML kinds (G-API-TARGETS)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["ml_model_artifact", "ml_model_endpoint"])
def test_targets_route_rejects_ml_kinds_with_use_models_route(api: SimpleNamespace, kind: str) -> None:
    resp = api.client.post("/v1/targets", json={"project_id": PROJECT, "kind": kind, "value": "bundled:vehicles_cnn"})
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "use_models_route" and detail["field"] == "kind"
    events = _events(api, "target.manage")
    assert len(events) == 1 and events[0].success is False and events[0].detail["reason"] == "use_models_route"
    with api.Session() as sess:
        assert sess.query(Target).count() == 0

    # Non-ML kinds still go through the allowlist service unchanged.
    ok = api.client.post("/v1/targets", json={"project_id": PROJECT, "kind": "url", "value": "http://localhost:3000"})
    assert ok.status_code == 200 and ok.json()["kind"] == "url"


# ---------------------------------------------------------------------------
# Input contract of an open-weights upload: validated in the API, stored in the manifest, never guessed
# ---------------------------------------------------------------------------


def test_upload_input_contract_lands_in_the_manifest(api: SimpleNamespace) -> None:
    resp = _upload(api, input_scale="255", input_mean="0.485, 0.456, 0.406", input_std="[0.229, 0.224, 0.225]",
                   input_resize="224", input_layout="nhwc")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["manifest"]["input_preprocessing"] == {
        "scale": 255.0, "mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225], "resize": 224, "layout": "NHWC",
    }
    with api.Session() as sess:
        target = sess.get(Target, body["id"])
    assert target is not None
    assert target.detail["manifest"]["input_preprocessing"] == body["manifest"]["input_preprocessing"]
    events = _events(api, "model.register")
    assert events[-1].success is True and events[-1].detail["input_preprocessing"] is True


def test_upload_without_input_contract_records_none(api: SimpleNamespace) -> None:
    resp = _upload(api, input_scale="", input_mean="")
    assert resp.status_code == 201, resp.text
    assert "input_preprocessing" not in resp.json()["manifest"]
    assert _events(api, "model.register")[-1].detail["input_preprocessing"] is False


@pytest.mark.parametrize(
    ("fields", "field"),
    [
        ({"input_scale": "0"}, "input_scale"),
        ({"input_scale": "many"}, "input_scale"),
        ({"input_mean": "0.5,0.5,0.5"}, "input_std"),
        ({"input_mean": "0.5,0.5", "input_std": "0.2,0.2"}, "input_mean"),
        ({"input_mean": "0.5", "input_std": "0"}, "input_std"),
        ({"input_mean": "[1, 2", "input_std": "1"}, "input_mean"),
        ({"input_resize": "4"}, "input_resize"),
        ({"input_resize": "224.5"}, "input_resize"),
        ({"input_layout": "CHWN"}, "input_layout"),
    ],
    ids=["zero-scale", "text-scale", "mean-alone", "two-channels", "zero-std", "bad-json", "resize-small",
         "resize-float", "layout"],
)
def test_upload_input_contract_refusals(api: SimpleNamespace, fields: dict[str, str], field: str) -> None:
    before = len(_blob_files(api))
    resp = _upload(api, **fields)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == field
    assert len(_blob_files(api)) == before
    event = _events(api, "model.register")[-1]
    assert event.success is False and event.detail["reason"] == "params_out_of_range"
