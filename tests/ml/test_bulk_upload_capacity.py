"""Bulk model upload, per-project capacity and the capacity view (BULK-13, -20..25; plan 12 wave B3).

Offline sqlite harness (``tests/conftest.py``) with foreign keys on, an in-memory
audit writer, a filesystem blob store and an asset tree written with the real
``redsim.ml.assets.manifest`` models (the shape ``tests/ml/test_models_routes.py``
uses). Model "files" are a few bytes with the right magic: nothing here loads a
model, and ``redsim.api.v1.models_bulk`` imports no ML library.

Pinned:

* one ``bulk.upload`` row precedes every member row; each file keeps its own
  ``model.register`` row, ``Target``, ``ml.ingest`` Run, ``model.validate`` Job
  and enqueue, with ``bulk_id`` on all of them;
* per-file refusals are rows in a ``207`` body (``422 batch_member_refused``
  when every file is refused) with their own ``success=False`` rows;
* the request caps (``bulk_too_many_files``, ``bulk_too_large``) refuse before
  any member row and are audited;
* ``admit_or_defer`` defers over the concurrency cap (marker, never a refusal)
  and refuses the daily budget with ``429 daily_budget_exceeded`` plus an
  audited row; the dispatcher continues deferred jobs oldest first, restores the
  flag on a broker failure, and the gauges are filled from the same rows;
* ``GET /v1/ml/capacity`` returns per-project numbers behind membership and
  hides the global block from non-system callers.
"""

from __future__ import annotations

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
from redsim.api.errors import ApiError
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Job, MlBatch, Organization, Project, Run, Target
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
from redsim.services import ml_capacity as capacity
from redsim.storage.blobs import FilesystemBlobStore

pytestmark = pytest.mark.integration

PROJECT = "proj-bulk"
OTHER = "proj-other"
IMAGE_DS = "hf:example/vehicles"
IMAGE_CLASSES = ["Air Defense", "BMP", "Tank"]
ONNX_BYTES = b"\x08\x07\x12\x0eredsim-bulk-a"
ONNX_BYTES_B = b"\x08\x07\x12\x0eredsim-bulk-b"
STATE_DICT_BYTES = b"PK\x03\x04" + b"\x00" * 28          # zip magic: a torch state_dict container
PICKLE_BYTES = b"\x80\x04\x95" + b"\x00" * 13

ADMIN = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin", OTHER: "admin"})
VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
STRANGER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={OTHER: "admin"})
SYSTEM = CurrentUser(sub="system:ops", email="ops@test", project_memberships={}, is_system=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write(root: Path, rel: str, payload: bytes) -> FileEntry:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return FileEntry(path=rel, sha256=sha256_bytes(payload), size_bytes=len(payload))


@pytest.fixture
def assets_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A built asset tree with one image dataset (the upload binding target) and one bundled model."""
    root = tmp_path / "assets"
    root.mkdir()
    split = _write(root, "datasets/hf--example--vehicles/rev1/test_coarse.npz", b"npz placeholder")
    weights = _write(root, "bundled/vehicles_cnn/weights.pt", STATE_DICT_BYTES + b"-vehicles")
    manifest = AssetManifest.new()
    manifest.datasets[IMAGE_DS] = DatasetEntry(
        id=IMAGE_DS, source="huggingface", revision="rev1", license="MIT", class_names=IMAGE_CLASSES,
        splits={"test_coarse": SplitEntry(name="test_coarse", n=4, file=split)},
        preprocessing={"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
    )
    manifest.models["vehicles_cnn"] = stamp_manifest_sha256(ModelEntry(
        id="vehicles_cnn", name="vehicles (test build)", modality="image", format="torch_state_dict",
        sha256=weights.sha256, size_bytes=weights.size_bytes, file=weights, architecture_id="small_cnn",
        architecture={"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 3, "image_size": 8},
        input_shape=[3, 8, 8], n_classes=3, class_names=IMAGE_CLASSES, dataset_id=IMAGE_DS, dataset_revision="rev1",
        dataset_split="test_coarse", train_split="train", seed=0, epochs=1, gradients=True, license="MIT",
        clean_accuracy=CleanAccuracy(value=0.5, n=4, split="test_coarse"), metrics={"clean_accuracy": 0.5, "n": 4},
    ))
    write_manifest(manifest, root / MANIFEST_NAME)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(root))
    return root


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        assets_root: Path) -> Iterator[SimpleNamespace]:
    """Dev-mode app over the sqlite harness (foreign keys on); the caller is switchable per request."""
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
        sess.add(Project(id=PROJECT, org_id="org-1", name="Bulk", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setattr("redsim.api.v1.targets.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    for key in ("REDSIM_DB_URL", "REDSIM_TEST_AUDIT", "REDSIM_ML_UPLOAD_MAX_MB", "REDSIM_ML_BULK_UPLOAD_MAX_FILES",
                "REDSIM_ML_BULK_UPLOAD_MAX_MB", capacity.MAX_CONCURRENT_ENV, capacity.DAILY_BUDGET_ENV,
                capacity.DAILY_BUDGET_ENV_ALIAS):
        monkeypatch.delenv(key, raising=False)
    enqueued: list[str] = []

    def _delay(job_id: str) -> SimpleNamespace:
        enqueued.append(job_id)
        return SimpleNamespace(id=f"celery-{job_id}")

    monkeypatch.setattr("redsim.workers.tasks.ml_model.ml_model_validate.delay", _delay)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder = SimpleNamespace(user=ADMIN)
    app.dependency_overrides[get_current_user] = lambda: holder.user
    client = TestClient(app)

    def call(user: CurrentUser, method: str, path: str, **kwargs: Any) -> Any:
        holder.user = user
        try:
            return client.request(method, path, **kwargs)
        finally:
            holder.user = ADMIN

    yield SimpleNamespace(
        client=client, call=call, Session=sqlite_session_factory.Session, session_cm=sqlite_session_factory.session_cm,
        engine=engine, writer=writer, blobs=blobs, blob_root=blob_root, assets_root=assets_root, enqueued=enqueued,
        app=app,
    )
    rl._BUCKETS.clear()


def _item(filename: str, **over: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"filename": filename, "name": filename.rsplit(".", 1)[0], "modality": "image",
                            "dataset_id": IMAGE_DS, "license_statement": "MIT, see LICENSE"}
    if filename.endswith(".pt"):
        item.update(declared_format="torch_state_dict", architecture_id="small_cnn")
    for key, value in over.items():
        if value is None:
            item.pop(key, None)
        else:
            item[key] = value
    return item


def _bulk(api: SimpleNamespace, files: list[tuple[str, bytes]], items: list[dict[str, Any]] | None = None, *,
          user: CurrentUser = ADMIN, project_in_manifest: bool = True, manifest: Any = "auto",
          params: dict[str, str] | None = None) -> Any:
    parts = [("files", (name, payload, "application/octet-stream")) for name, payload in files]
    data: dict[str, str] = {}
    if manifest == "auto":
        doc: dict[str, Any] = {"items": items if items is not None else [_item(name) for name, _ in files]}
        if project_in_manifest:
            doc["project_id"] = PROJECT
        data["manifest"] = json.dumps(doc)
    elif manifest is not None:
        data["manifest"] = manifest
    return api.call(user, "POST", "/v1/models/bulk", data=data, files=parts, params=params or {})


def _events(api: SimpleNamespace, action: str) -> list[Any]:
    return [event for event in api.writer.events if event.action == action]


def _rows(api: SimpleNamespace) -> dict[str, list[Any]]:
    with api.Session() as sess:
        return {
            "targets": list(sess.query(Target).all()), "runs": list(sess.query(Run).all()),
            "jobs": list(sess.query(Job).all()), "batches": list(sess.query(MlBatch).all()),
        }


# ---------------------------------------------------------------------------
# Bulk upload
# ---------------------------------------------------------------------------


def test_bulk_upload_happy_path_keeps_one_admission_per_file(api: SimpleNamespace) -> None:
    resp = _bulk(api, [("a.onnx", ONNX_BYTES), ("b.pt", STATE_DICT_BYTES)])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["bulk_id"].startswith("bulk-") and body["project_id"] == PROJECT and body["kind"] == "upload"
    assert (body["n_files"], body["n_admitted"], body["n_refused"]) == (2, 2, 0)
    results = body["results"]
    assert [r["filename"] for r in results] == ["a.onnx", "b.pt"]
    assert all(r["status"] == "validating" and r["enqueued"] is True for r in results)
    assert results[0]["detected_format"] == "onnx" and results[1]["detected_format"] == "torch_state_dict"
    ids = {key: {r[key] for r in results} for key in ("target_id", "ingest_run_id", "ingest_job_id")}
    assert all(len(v) == 2 for v in ids.values()), "every file keeps its own Target, Run and Job"

    rows = _rows(api)
    assert len(rows["targets"]) == 2 and len(rows["runs"]) == 2 and len(rows["jobs"]) == 2
    for target in rows["targets"]:
        assert target.kind == "ml_model_artifact" and target.detail["bulk_id"] == body["bulk_id"]
        assert target.detail["status"] == "validating" and target.detail["source"] == "upload"
    assert all(run.scanner == "ml.ingest" and run.status == "queued" and run.stage_table["bulk_id"] == body["bulk_id"]
               for run in rows["runs"])
    assert all(job.type == "model.validate" and job.status == "queued" and job.detail["bulk_id"] == body["bulk_id"]
               and job.celery_task_id == f"celery-{job.id}" for job in rows["jobs"])
    assert sorted(api.enqueued) == sorted(ids["ingest_job_id"]), "one model.validate enqueue per file"
    (batch,) = rows["batches"]
    assert batch.id == body["bulk_id"] and batch.kind == "upload" and batch.project_id == PROJECT
    assert batch.config["n_admitted"] == 2 and batch.config["n_refused"] == 0
    assert sorted(batch.config["target_ids"]) == sorted(ids["target_id"])
    assert "license_statement" not in json.dumps(batch.config)
    blobs = [p for p in api.blob_root.rglob("*") if p.is_file()]
    assert len(blobs) == 2

    # Audit: bulk.upload first, then one model.register per file, all success, ids and digests only.
    actions = [e.action for e in api.writer.events]
    assert actions == ["bulk.upload", "model.register", "model.register"]
    head = api.writer.events[0]
    assert head.success is True and head.project_id == PROJECT and head.run_id is None
    assert head.detail["bulk_id"] == body["bulk_id"] and head.detail["n_files"] == 2
    assert head.detail["filenames"] == ["a.onnx", "b.pt"] and head.detail["content_length"] > 0
    for event, result in zip(api.writer.events[1:], results, strict=True):
        assert event.success is True and event.run_id == result["ingest_run_id"]
        assert event.detail["bulk_id"] == body["bulk_id"] and event.detail["target_id"] == result["target_id"]
        assert event.detail["sha256"] == result["sha256"] and event.detail["ingest_job_id"] == result["ingest_job_id"]
    serialized = json.dumps([e.detail for e in api.writer.events])
    assert "PK\\u0003" not in serialized and "\\u0008\\u0007" not in serialized, "no model bytes on the chain"


def test_bulk_upload_mixed_is_207_with_a_refusal_row_per_file(api: SimpleNamespace) -> None:
    resp = _bulk(api, [("a.onnx", ONNX_BYTES), ("bad.pkl", PICKLE_BYTES), ("c.onnx", PICKLE_BYTES)],
                 items=[_item("a.onnx"), _item("bad.pkl", declared_format="onnx"), _item("c.onnx")])
    assert resp.status_code == 207, resp.text
    body = resp.json()
    assert (body["n_admitted"], body["n_refused"]) == (1, 2)
    statuses = [(r["filename"], r["status"], r.get("code")) for r in body["results"]]
    assert statuses == [("a.onnx", "validating", None), ("bad.pkl", "refused", "pickle_refused"),
                        ("c.onnx", "refused", "pickle_refused")]
    assert all(r["field"] == "file" and r["http_status"] == 415 for r in body["results"] if r["status"] == "refused")

    rows = _rows(api)
    assert len(rows["targets"]) == 1 and len(rows["runs"]) == 1 and len(rows["jobs"]) == 1
    assert len(api.enqueued) == 1
    actions = [(e.action, e.success) for e in api.writer.events]
    assert actions == [("bulk.upload", True), ("model.register", True), ("model.register", False),
                       ("model.register", False)]
    refusals = [e for e in api.writer.events if e.success is False]
    assert all(e.detail["reason"] == "pickle_refused" and e.detail["bulk_id"] == body["bulk_id"]
               and e.project_id == PROJECT and e.allowlist_check == "n/a" for e in refusals)
    assert [e.detail["bulk_index"] for e in refusals] == [1, 2]
    (batch,) = rows["batches"]
    assert batch.config["refused"] == [{"index": 1, "filename": "bad.pkl", "code": "pickle_refused"},
                                       {"index": 2, "filename": "c.onnx", "code": "pickle_refused"}]


def test_bulk_upload_every_file_refused_is_422_batch_member_refused(api: SimpleNamespace) -> None:
    resp = _bulk(api, [("only.pkl", PICKLE_BYTES)], items=[_item("only.pkl", declared_format="onnx")])
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "batch_member_refused" and detail["n_refused"] == 1 and detail["n_admitted"] == 0
    assert detail["members"] == [{"index": 0, "filename": "only.pkl", "code": "pickle_refused",
                                  "message": detail["results"][0]["message"]}]
    rows = _rows(api)
    assert not rows["targets"] and not rows["runs"] and not rows["jobs"] and not api.enqueued
    assert len(rows["batches"]) == 1 and rows["batches"][0].config["n_refused"] == 1
    assert [(e.action, e.success) for e in api.writer.events] == [("bulk.upload", True), ("model.register", False)]


@pytest.mark.parametrize(
    ("kwargs", "status", "code", "field"),
    [
        (dict(items=[_item("a.onnx", license_statement=None)]), 207, "license_required", "license_statement"),
        (dict(items=[_item("a.onnx", dataset_id="hf:nobody/unknown")]), 207, "dataset_incompatible", "dataset_id"),
        (dict(items=[_item("a.onnx", modality="llm")]), 207, "not_implemented", "modality"),
        (dict(items=[_item("a.onnx", declared_format="torch_state_dict", architecture_id="small_cnn")]), 207,
         "unsupported_model_format", "declared_format"),
        (dict(items=[_item("a.onnx", declared_format="torch_state_dict")]), 207, "architecture_required",
         "architecture_id"),
    ],
    ids=["no-license", "unknown-dataset", "phase-b-modality", "declared-vs-magic", "state-dict-without-architecture"],
)
def test_bulk_upload_per_file_refusals_use_the_single_route_codes(
    api: SimpleNamespace, kwargs: dict[str, Any], status: int, code: str, field: str,
) -> None:
    """A refused item next to an admitted one: the single route's code, field and row, request still 207."""
    items = [*kwargs["items"], _item("ok.onnx")]
    resp = _bulk(api, [("a.onnx", ONNX_BYTES), ("ok.onnx", ONNX_BYTES_B)], items=items)
    assert resp.status_code == status, resp.text
    refused, admitted = resp.json()["results"]
    assert refused["status"] == "refused" and refused["code"] == code and refused["field"] == field
    if code == "not_implemented":
        assert refused["phase"] == "B"
    assert admitted["status"] == "validating"
    failed = [e for e in api.writer.events if e.success is False]
    assert len(failed) == 1 and failed[0].action == "model.register" and failed[0].detail["reason"] == code


def test_bulk_upload_file_count_cap_refuses_before_any_row(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSIM_ML_BULK_UPLOAD_MAX_FILES", "2")
    resp = _bulk(api, [("a.onnx", ONNX_BYTES), ("b.onnx", ONNX_BYTES_B), ("c.onnx", ONNX_BYTES)])
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "bulk_too_many_files" and detail["field"] == "files"
    assert (detail["n_files"], detail["max_files"]) == (3, 2)
    rows = _rows(api)
    assert not rows["targets"] and not rows["batches"] and not api.enqueued
    (event,) = api.writer.events
    assert event.action == "bulk.upload" and event.success is False and event.project_id == PROJECT
    assert event.detail["reason"] == "bulk_too_many_files" and event.detail["n_files"] == 3


def test_bulk_upload_total_cap_is_413_before_parsing(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSIM_ML_BULK_UPLOAD_MAX_MB", "1")
    big = ONNX_BYTES + b"\x00" * (1024 * 1024 + 64)
    resp = _bulk(api, [("big.onnx", big)], params={"project": PROJECT})
    assert resp.status_code == 413, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "bulk_too_large" and detail["cap_bytes"] == 1024 * 1024
    (event,) = api.writer.events
    assert event.action == "bulk.upload" and event.success is False and event.project_id == PROJECT
    assert event.detail["reason"] == "bulk_too_large"
    assert not _rows(api)["batches"]

    # Per-file cap inside a bulk request: a per-item refusal, not a request failure (spec row).
    monkeypatch.delenv("REDSIM_ML_BULK_UPLOAD_MAX_MB", raising=False)
    monkeypatch.setenv("REDSIM_ML_UPLOAD_MAX_MB", "1")
    api.writer.events.clear()
    resp = _bulk(api, [("big.onnx", big), ("small.onnx", ONNX_BYTES_B)])
    assert resp.status_code == 207, resp.text
    first, second = resp.json()["results"]
    assert first["status"] == "refused" and first["code"] == "model_too_large" and first["http_status"] == 413
    assert second["status"] == "validating"
    assert [e.detail.get("reason") for e in api.writer.events if e.action == "model.register" and not e.success] \
        == ["model_too_large"]


def test_bulk_upload_manifest_shape_and_matching_refusals(api: SimpleNamespace) -> None:
    # No manifest part at all.
    resp = _bulk(api, [("a.onnx", ONNX_BYTES)], manifest=None, params={"project": PROJECT})
    assert resp.status_code == 422 and resp.json()["detail"]["field"] == "manifest"
    # Manifest that is not JSON.
    resp = _bulk(api, [("a.onnx", ONNX_BYTES)], manifest="{not json", params={"project": PROJECT})
    assert resp.status_code == 422 and resp.json()["detail"]["field"] == "manifest"
    # Manifest with an unknown key.
    resp = _bulk(api, [("a.onnx", ONNX_BYTES)],
                 manifest=json.dumps({"project_id": PROJECT, "items": [{**_item("a.onnx"), "bogus": 1}]}))
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == "manifest" and detail["reasons"]
    # Unmatched filename: the item names a part that was not sent, and a part has no item.
    resp = _bulk(api, [("a.onnx", ONNX_BYTES)], items=[_item("zzz.onnx")])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["field"] == "items.filename"
    assert any("zzz.onnx" in r for r in detail["reasons"]) and any("a.onnx" in r for r in detail["reasons"])
    # Every refusal above was audited and wrote no row.
    assert api.writer.events and all(e.action == "bulk.upload" and e.success is False for e in api.writer.events)
    rows = _rows(api)
    assert not rows["targets"] and not rows["batches"] and not api.enqueued


def test_bulk_upload_gates_and_body_shape(api: SimpleNamespace) -> None:
    # JSON without a project is 422 params_out_of_range on project_id (the B0 stub's contract).
    resp = api.call(ADMIN, "POST", "/v1/models/bulk", json={})
    assert resp.status_code == 422 and resp.json()["detail"]["field"] == "project_id"
    assert api.call(ADMIN, "POST", "/v1/models/bulk").status_code == 422
    # JSON with a project passes the gates, then says the route is multipart.
    resp = api.call(ADMIN, "POST", "/v1/models/bulk", json={"project_id": PROJECT})
    assert resp.status_code == 422 and resp.json()["detail"]["field"] == "files"
    # Role and membership gates run before anything is read or written.
    n_events = len(api.writer.events)
    assert _bulk(api, [("a.onnx", ONNX_BYTES)], user=VIEWER).status_code == 403
    assert _bulk(api, [("a.onnx", ONNX_BYTES)], user=STRANGER).status_code == 403
    assert len(api.writer.events) == n_events, "a 403 writes nothing"
    assert not _rows(api)["batches"]


def test_bulk_upload_does_not_import_ml_libraries() -> None:
    """The route module and its lazy imports stay within the API boundary."""
    import importlib
    import sys

    module = importlib.import_module("redsim.api.v1.models_bulk")
    assert module.router is not None
    for name in ("torch", "art", "onnxruntime", "shap"):
        assert not any(m == name or m.startswith(name + ".") for m in sys.modules if sys.modules[m] is not None
                       and getattr(sys.modules[m], "__file__", "") and "redsim" in str(sys.modules[m].__file__)), name


# ---------------------------------------------------------------------------
# Capacity: deferral, budget, dispatcher, gauges
# ---------------------------------------------------------------------------


def _seed_job(sess: Any, job_id: str, *, status: str = "queued", job_type: str = "attack.run",
              created_at: datetime | None = None, project: str = PROJECT, detail: dict[str, Any] | None = None) -> None:
    run_id = f"run-{job_id}"
    sess.add(Run(id=run_id, project_id=project, mode="api", status=status if status != "queued" else "queued",
                 scanner="ml.campaign", stage_table={"stage": None, "stages_done": [], "jobs": {}},
                 created_at=created_at or datetime.now(UTC)))
    sess.flush()
    sess.add(Job(id=job_id, run_id=run_id, project_id=project, type=job_type, status=status,
                 detail=detail or {"campaign_config": {}}, created_at=created_at or datetime.now(UTC)))
    sess.flush()


def test_admit_or_defer_defers_over_the_concurrency_cap_never_refuses(api: SimpleNamespace) -> None:
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        _seed_job(sess, "job-running-1", status="running")
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        decision = capacity.admit_or_defer(sess, project, "attack")
        assert decision.deferred is True and decision.active == 1 and decision.max_concurrent_runs == 1
        marker = decision.marker()
        assert marker["code"] == "capacity_deferred" and marker["active_runs"] == 1
        assert decision.response_fields()["deferred"] is True and decision.response_fields()["capacity"] == marker
        assert decision.used_today == 1 and decision.daily_run_budget is None
        # Raising the marker as a refusal is a programming error; the decision never does.
        with pytest.raises(ValueError, match="marker"):
            ApiError("capacity_deferred")
        # Raising the cap admits at once; a deferred job does not occupy a slot.
        project.ml_max_concurrent_runs = 3
        _seed_job(sess, "job-deferred-x", detail={"campaign_config": {}, "deferred": True})
        again = capacity.admit_or_defer(sess, project, "verify")
        assert again.deferred is False and again.active == 1 and again.job_type == "verify.replay"
        assert again.marker() == {} and again.response_fields() == {"deferred": False}
    # NULL columns fall back to the deployment default (2 unless the env overrides it).
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = None
        caps = capacity.effective_caps(project)
        assert caps.max_concurrent_runs == 2 and caps.concurrency_source == "default"
        assert caps.daily_run_budget is None and caps.budget_source == "default"
    with pytest.raises(ValueError, match="unknown admission kind"):
        with api.session_cm() as sess:
            capacity.admit_or_defer(sess, PROJECT, "sweep")


def test_daily_budget_refuses_429_with_an_audited_row(api: SimpleNamespace) -> None:
    writer = InMemoryAuditWriter()
    now = datetime(2026, 9, 9, 15, 30, tzinfo=UTC)
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_daily_run_budget = 2
        _seed_job(sess, "job-today-1", status="succeeded", created_at=now - timedelta(hours=3))
        _seed_job(sess, "job-yesterday", status="succeeded", created_at=now - timedelta(days=1, hours=1))
        _seed_job(sess, "job-explain", status="succeeded", job_type="explain.run", created_at=now - timedelta(hours=1))
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        assert capacity.used_today(sess, PROJECT, now=now) == 1, "yesterday and follow-on jobs do not count"
        # One more fits.
        decision = capacity.admit_or_defer(sess, project, "attack", now=now)
        assert decision.deferred is False and decision.used_today == 1 and decision.daily_run_budget == 2
        # Two more (a batch) do not: the whole batch is refused (validate-all).
        with pytest.raises(ApiError) as info:
            capacity.admit_or_defer(sess, project, "attack", requested=2, now=now, actor="user:alice",
                                    audit_writer=writer, action="batch.run", target_ids=["t1", "t2"])
        exc = info.value
        assert exc.status == 429 and exc.code == "daily_budget_exceeded"
        assert exc.detail["budget"] == 2 and exc.detail["used"] == 1 and exc.detail["requested"] == 2
        assert exc.detail["resets_at"] == "2026-09-10T00:00:00Z" and exc.detail["retry_after"] == 8 * 3600 + 30 * 60
        (event,) = writer.events
        assert event.action == "batch.run" and event.success is False and event.project_id == PROJECT
        assert event.detail["code"] == "daily_budget_exceeded" and event.detail["budget"] == 2
        assert event.detail["used_today"] == 1 and event.detail["target_ids"] == ["t1", "t2"]
        assert event.detail["actor"] == "user:alice" and event.run_id is None
        # Spent budget: one more is refused as well, without a writer nothing is written here (the caller's row).
        project.ml_daily_run_budget = 1
        with pytest.raises(ApiError) as info:
            capacity.admit_or_defer(sess, project, "verify", now=now)
        assert info.value.code == "daily_budget_exceeded" and len(writer.events) == 1
        # A follow-on kind is not budgeted (it re-uses an admitted run's samples).
        assert capacity.admit_or_defer(sess, project, "explain", now=now).deferred is False


def test_mark_deferred_and_dispatch_continuation(api: SimpleNamespace) -> None:
    sent: list[str] = []

    def enqueue(job_id: str) -> str:
        sent.append(job_id)
        return f"celery-{job_id}"

    writer = InMemoryAuditWriter()
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        _seed_job(sess, "job-running", status="running")
        # The admission order: decide (over cap -> defer), write the queued row, then mark it deferred.
        # A job already marked deferred does not occupy a slot, so the next admission still sees active == 1.
        for offset, job_id in ((2, "job-d1"), (1, "job-d2")):
            decision = capacity.admit_or_defer(sess, project, "attack")
            assert decision.deferred is True and decision.active == 1
            _seed_job(sess, job_id, created_at=datetime.now(UTC) - timedelta(minutes=offset))
            capacity.mark_deferred(sess, run_id=f"run-{job_id}", job_id=job_id, decision=decision)
    with api.session_cm() as sess:
        job = sess.get(Job, "job-d1")
        run = sess.get(Run, "run-job-d1")
        assert job.detail["deferred"] is True and job.detail["capacity"]["active_runs"] == 1
        assert run.stage_table["deferred"] is True and run.stage_table["capacity"]["max_concurrent_runs"] == 1
        assert capacity.is_deferred(job)
        counts = capacity.count_active(sess, PROJECT)
        assert (counts.running, counts.dispatched, counts.deferred) == (1, 0, 2)
        assert counts.deferred_job_ids == ["job-d1", "job-d2"]
        assert capacity.projects_with_deferred_jobs(sess) == [PROJECT]

        # The slot is taken: nothing moves.
        report = capacity.dispatch_deferred(sess, enqueue=enqueue)
        assert report.n_dispatched == 0 and report.still_deferred == {PROJECT: 2} and sent == []

        # The running job is finishing (continuation hook excludes it): the oldest deferred job goes first.
        report = capacity.dispatch_deferred(sess, project_id=PROJECT, enqueue=enqueue,
                                            exclude_job_ids=["job-running"], audit_writer=writer)
        assert report.dispatched == {PROJECT: ["job-d1"]} and report.still_deferred == {PROJECT: 1}
        assert sent == ["job-d1"]
        job = sess.get(Job, "job-d1", populate_existing=True)
        run = sess.get(Run, "run-job-d1", populate_existing=True)
        assert job.detail["deferred"] is False and job.detail["capacity"]["dispatched_at"]
        assert job.celery_task_id == "celery-job-d1" and job.status == "queued"
        assert run.stage_table["deferred"] is False
        assert sess.get(Job, "job-d2", populate_existing=True).detail["deferred"] is True
        (event,) = writer.events
        assert event.action == "batch.dispatch" and event.run_id == "run-job-d1" and event.success is True
        assert event.detail["job_id"] == "job-d1" and event.detail["max_concurrent_runs"] == 1

        # A broker failure restores the flag; the backstop retries later.
        def broken(job_id: str) -> str:
            raise ConnectionError("broker down")

        sess.get(Job, "job-d1").status = "succeeded"
        sess.commit()
        report = capacity.dispatch_deferred(sess, project_id=PROJECT, enqueue=broken, exclude_job_ids=["job-running"])
        assert report.failed == {PROJECT: ["job-d2"]} and report.n_dispatched == 0
        job2 = sess.get(Job, "job-d2", populate_existing=True)
        assert job2.detail["deferred"] is True and "ConnectionError" in job2.detail["capacity"]["last_dispatch_error"]
        assert job2.celery_task_id is None
        # And the next pass picks it up.
        report = capacity.dispatch_deferred(sess, project_id=PROJECT, enqueue=enqueue, exclude_job_ids=["job-running"])
        assert report.dispatched == {PROJECT: ["job-d2"]} and sent == ["job-d1", "job-d2"]


def test_continuation_hook_and_backstop_task_body(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    from redsim.workers.celery_app import app as celery_app
    from redsim.workers.tasks import capacity as task_module

    sent: list[str] = []
    monkeypatch.setattr(capacity, "default_enqueue", lambda job_id: (sent.append(job_id), f"celery-{job_id}")[1])
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        _seed_job(sess, "job-finishing", status="running")
        _seed_job(sess, "job-waiting")
        decision = capacity.admit_or_defer(sess, project, "attack")
        capacity.mark_deferred(sess, run_id="run-job-waiting", job_id="job-waiting", decision=decision)
    # The hook the finishing campaign task calls: its own job is excluded from the slot count.
    result = task_module.continue_deferred(PROJECT, finishing_job_id="job-finishing")
    assert result["dispatched"] == {PROJECT: ["job-waiting"]} and sent == ["job-waiting"]
    # Nothing left: the backstop body reports zero and samples the gauges.
    result = task_module.dispatch_deferred_once()
    assert result["n_dispatched"] == 0 and result["gauges"]["deferred"] == {PROJECT: 0}
    assert result["gauges"]["jobs_active"] == 1
    # A project id nobody knows is a no-op, and the hook never raises.
    assert task_module.continue_deferred(None) == {"dispatched": {}, "n_dispatched": 0}
    monkeypatch.setattr(capacity, "dispatch_deferred", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert task_module.continue_deferred(PROJECT)["error"].startswith("continuation failed")
    # Wiring: the Celery task, its queue and the 60 s beat backstop.
    assert task_module.ml_dispatch_deferred.name == "redsim.ml_dispatch_deferred"
    assert task_module.ml_dispatch_deferred._get_exec_options()["queue"] == "default"
    assert "redsim.workers.tasks.capacity" in celery_app.conf.include
    entry = celery_app.conf.beat_schedule["ml-dispatch-deferred"]
    assert entry["task"] == "redsim.ml_dispatch_deferred" and entry["schedule"] == 60.0
    assert entry["options"]["queue"] == "default"


def test_deferred_continuation_wraps_every_exit_path(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    """The two-line hook for ``ml_campaign_run``: dispatch on return and on raise, project read from the job row."""
    from redsim.workers.tasks import capacity as task_module

    sent: list[str] = []
    monkeypatch.setattr(capacity, "default_enqueue", lambda job_id: (sent.append(job_id), f"celery-{job_id}")[1])
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        _seed_job(sess, "job-finishing", status="running")
        for job_id in ("job-w1", "job-w2"):
            decision = capacity.admit_or_defer(sess, project, "attack")
            _seed_job(sess, job_id)
            capacity.mark_deferred(sess, run_id=f"run-{job_id}", job_id=job_id, decision=decision)
    # A body that returns: the finishing job (still ``running`` in the row, as inside task_context) is excluded
    # from the slot count, so the oldest deferred member goes out when the block exits, not before.
    with task_module.deferred_continuation("job-finishing"):
        assert sent == []
    assert sent == ["job-w1"]
    # A body that raises: the hook still runs and the exception propagates unchanged.
    with api.session_cm() as sess:
        sess.get(Job, "job-w1").status = "succeeded"
    with pytest.raises(RuntimeError, match="sandbox died"), task_module.deferred_continuation("job-finishing"):
        raise RuntimeError("sandbox died")
    assert sent == ["job-w1", "job-w2"]
    # The project may be given; a job nobody knows is a no-op; a broken lookup never raises out of the hook.
    with task_module.deferred_continuation("job-finishing", project_id=PROJECT):
        pass
    with task_module.deferred_continuation("no-such-job"):
        pass
    assert task_module._job_project_id("no-such-job") is None
    monkeypatch.setattr("redsim.db.session.get_session", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    with task_module.deferred_continuation("job-finishing"):
        pass
    assert sent == ["job-w1", "job-w2"]
    assert "deferred_continuation" in task_module.__all__


def test_gauges_are_filled_from_the_jobs_table(api: SimpleNamespace) -> None:
    prometheus = pytest.importorskip("prometheus_client")
    from redsim.observability import METRIC_NAMES, get_metrics

    assert "redsim_ml_deferred_runs" in METRIC_NAMES and "redsim_ml_daily_budget_used" in METRIC_NAMES
    get_metrics()
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        _seed_job(sess, "job-g-running", status="running")
        _seed_job(sess, "job-g-deferred", detail={"campaign_config": {}, "deferred": True})
        _seed_job(sess, "job-g-other", status="running", project=OTHER)
        sample = capacity.sample_gauges(sess)
    assert sample["jobs_active"] == 2
    assert sample["deferred"] == {OTHER: 0, PROJECT: 1} and sample["budget_used"] == {OTHER: 1, PROJECT: 2}
    registry = prometheus.REGISTRY
    assert registry.get_sample_value("redsim_jobs_active", {}) == 2.0
    assert registry.get_sample_value("redsim_ml_deferred_runs", {"project": PROJECT}) == 1.0
    assert registry.get_sample_value("redsim_ml_deferred_runs", {"project": OTHER}) == 0.0
    assert registry.get_sample_value("redsim_ml_daily_budget_used", {"project": PROJECT}) == 2.0
    text = api.client.get("/metrics").text
    assert "redsim_ml_deferred_runs" in text and "redsim_ml_daily_budget_used" in text and "redsim_jobs_active" in text


# ---------------------------------------------------------------------------
# GET /v1/ml/capacity
# ---------------------------------------------------------------------------


def test_capacity_view_reports_per_project_numbers_behind_membership(api: SimpleNamespace) -> None:
    with api.session_cm() as sess:
        project = sess.get(Project, PROJECT)
        project.ml_max_concurrent_runs = 1
        project.ml_daily_run_budget = 5
        _seed_job(sess, "job-c-running", status="running")
        _seed_job(sess, "job-c-deferred", detail={"campaign_config": {}, "deferred": True})
        _seed_job(sess, "job-c-queued")
        _seed_job(sess, "job-c-other", status="running", project=OTHER)
    resp = api.call(ADMIN, "GET", f"/v1/ml/capacity?project={PROJECT}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    block = body["project"]
    assert block["project_id"] == PROJECT and block["max_concurrent_runs"] == 1 and block["daily_run_budget"] == 5
    assert block["sources"] == {"max_concurrent_runs": "project", "daily_run_budget": "project"}
    assert (block["running_jobs"], block["queued_jobs"], block["deferred_runs"], block["active_runs"]) == (1, 2, 1, 2)
    assert block["slots_free"] == 0 and block["used_today"] == 3 and block["budget_remaining"] == 2
    assert block["resets_at"].endswith("T00:00:00Z")
    assert body["limits"]["bulk_upload"] == {"max_files": 10, "max_total_mb": 1024, "per_file_max_mb": 512}
    assert body["limits"]["max_concurrent_runs_default"] == 2 and body["limits"]["daily_run_budget_default"] is None
    assert "global" not in body, "a member never sees other tenants' counts"
    assert [p["project_id"] for p in body["projects"]] == [PROJECT]

    # Every readable project without ?project=, still no global block.
    body = api.call(ADMIN, "GET", "/v1/ml/capacity").json()
    assert sorted(p["project_id"] for p in body["projects"]) == sorted([OTHER, PROJECT]) and "project" not in body
    assert "global" not in body
    # Membership gate on the named project; a stranger's own projects otherwise.
    assert api.call(STRANGER, "GET", f"/v1/ml/capacity?project={PROJECT}").status_code == 403
    body = api.call(STRANGER, "GET", "/v1/ml/capacity").json()
    assert [p["project_id"] for p in body["projects"]] == [OTHER]
    assert api.call(VIEWER, "GET", f"/v1/ml/capacity?project={PROJECT}").status_code == 200
    # A system principal gets the deployment-wide counts too.
    body = api.call(SYSTEM, "GET", "/v1/ml/capacity").json()
    assert body["global"]["running_jobs"] == 2 and body["global"]["ml_deferred_runs"] == 1
    assert body["global"]["ml_queued_jobs"] == 2 and len(body["projects"]) == 2
    # A refusal-free read writes nothing.
    assert api.writer.events == []
