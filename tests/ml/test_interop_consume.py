"""Consume side of spec 27 (INTEROP-13, -15, -16): ``POST /v1/datasets``, the parse child, the binding hook.

Offline file-backed sqlite harness (one connection per session, as the worker's
nested sessions need), an in-memory audit writer shared by the API and the
eager worker task, a filesystem blob store and the REAL sandbox child:
``redsim.ml_dataset_validate`` spawns ``python -m redsim.ml.interop.consume``
under the ML sandbox's rlimits and credential-free environment and parses the
Parquet there. The test process builds the fixtures with ``pyarrow``; a spy on
``pyarrow.parquet.ParquetFile`` in this process proves the worker parent never
opened one, and a subprocess probe proves the API, service and worker modules
import with ``pyarrow`` blocked.

Pinned here:

* the static refusal matrix of INTEROP-13 (each a ``success=False``
  ``dataset.register`` row first, no row, no blob, nothing enqueued);
* the happy path order: audit row, blobs, ``ml_datasets`` / Run / Job rows,
  then the enqueue; the worker moves the row to ``available`` with row and
  per-class counts, writes the ``dataset.validate`` and ``job.complete`` rows
  and the report artifact;
* the child's refusals (manifest digest disagreement, an unknown class label,
  a missing feature column, image values outside the declared range);
* a blob substituted after admission is refused in the parent before any child;
* the child environment carries no credential, proxy or ``REDSIM_*`` setting;
* the catalog lists consumed rows per membership; the record route and the
  binding hook (``resolve_consumed_slice`` / ``consumed_dataset_binding``);
* the export and manifest routes: the gates, the contribute service's typed refusal for a
  run without slices, ``404`` until an export exists (the ld+json round trip with a real
  export lives in ``tests/ml/test_interop_export.py``);
* the campaign-admission binding hook (INTEROP-16): an available consumed slice of the
  project can be named as ``dataset_id`` and its manifest digest becomes the revision; a
  validating slice, another project's, another modality's, or a model bound to a bundled
  dataset are refused ``dataset_incompatible``.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("pyarrow")
pytest.importorskip("numpy")

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session, sessionmaker

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Artifact, Base, Job, MlDataset, Organization, Project, Run
from redsim.storage.blobs import FilesystemBlobStore
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

PROJECT = "proj-1"
OTHER = "proj-2"
RUN = "run-campaign-1"
CLASSES = ["benign", "phishing"]
FEATURES = ["f_len", "f_dots", "f_entropy"]
IMAGE_CLASSES = ["circle", "square", "triangle"]
IMAGE_SHAPE = (3, 4, 4)
LICENSE = "CC0-1.0 derived evaluation slice (test double)"
# Values a worker parent realistically holds; none may reach the child (low-entropy fakes).
PARENT_SECRETS = {
    "PYTHIA_API_KEY": "pk_fake_never_forward", "AWS_SECRET_ACCESS_KEY": "aws-fake-secret",
    "REDSIM_AUTH_PROFILES_KEY": "fake-fernet-key", "REDSIM_DB_URL_SHADOW": "postgresql://u:p@db.invalid/x",
    "HTTPS_PROXY": "http://proxy.example:3128", "KAGGLE_API_TOKEN": "fake-kaggle",
}


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def tabular_parquet(*, n: int = 12, features: list[str] | None = None, labels: list[Any] | None = None,
                    label_column: str = "label") -> bytes:
    features = FEATURES if features is None else features
    rng = np.random.default_rng(7)
    columns: dict[str, Any] = {name: pa.array(rng.random(n).astype(np.float64)) for name in features}
    if labels is None:
        labels = [CLASSES[i % 2] for i in range(n)]
    columns[label_column] = pa.array(labels)
    buffer = io.BytesIO()
    pq.write_table(pa.table(columns), buffer)
    return buffer.getvalue()


def image_parquet(*, n: int = 6, shape: tuple[int, ...] = IMAGE_SHAPE, dtype: str = "uint8",
                  labels: list[Any] | None = None, high: int = 255) -> bytes:
    rng = np.random.default_rng(3)
    count = int(np.prod(shape))
    rows = [rng.integers(0, high + 1, size=count).astype(dtype).tobytes() for _ in range(n)]
    if labels is None:
        labels = [i % len(IMAGE_CLASSES) for i in range(n)]
    table = pa.table({"image": pa.array(rows, type=pa.binary()), "label": pa.array(labels)})
    buffer = io.BytesIO()
    pq.write_table(table, buffer)
    return buffer.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def croissant(files: dict[str, str | None], *, license_: str | None = LICENSE, dataset_type: Any = "sc:Dataset",
              record_fields: list[str] | None = None, extra: dict[str, Any] | None = None) -> bytes:
    document: dict[str, Any] = {
        "@context": {"@vocab": "https://schema.org/", "cr": "http://mlcommons.org/croissant/",
                     "sc": "https://schema.org/"},
        "@type": dataset_type,
        "name": "other-team-slice",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "distribution": [
            {"@type": "cr:FileObject", "@id": name, "name": name, "contentUrl": name,
             "encodingFormat": "application/vnd.apache.parquet",
             **({"sha256": digest} if digest is not None else {})}
            for name, digest in files.items()
        ],
    }
    if license_ is not None:
        document["license"] = license_
    if record_fields is not None:
        document["recordSet"] = [{"@type": "cr:RecordSet", "@id": "rows", "name": "rows",
                                  "field": [{"@type": "cr:Field", "@id": f"rows/{f}", "name": f} for f in record_fields]}]
    if extra:
        document.update(extra)
    return json.dumps(document).encode("utf-8")


def tabular_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "project_id": PROJECT, "name": "url slice from team B", "license_statement": LICENSE,
        "modality": "tabular", "class_names": json.dumps(CLASSES), "features": json.dumps(FEATURES),
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return fields


def image_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "project_id": PROJECT, "name": "tiny image slice", "license_statement": LICENSE,
        "modality": "image", "class_names": json.dumps(IMAGE_CLASSES), "input_shape": json.dumps(list(IMAGE_SHAPE)),
        "dtype": "uint8", "value_range": "0,255",
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return fields


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _UserHolder:
    def __init__(self) -> None:
        self.current = CurrentUser(sub="dev:remediator@test", email="remediator@test",
                                   project_memberships={PROJECT: "remediator", OTHER: "remediator"})

    def as_role(self, role: str, *projects: str) -> None:
        memberships = {p: role for p in (projects or (PROJECT, OTHER))}
        self.current = CurrentUser(sub=f"dev:{role}@test", email=f"{role}@test", project_memberships=memberships)

    def as_stranger(self) -> None:
        self.current = CurrentUser(sub="dev:stranger@test", email="stranger@test",
                                   project_memberships={OTHER: "admin"})


@pytest.fixture
def sqlite_file_factory(tmp_path: Path) -> SimpleNamespace:
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'consume.db'}", connect_args={"check_same_thread": False})

    @sa_event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    maker = sessionmaker(engine, expire_on_commit=False)

    @contextlib.contextmanager
    def session_cm() -> Iterator[Session]:
        sess = maker()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    return SimpleNamespace(engine=engine, Session=maker, session_cm=session_cm)


@pytest.fixture
def api(sqlite_file_factory: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SimpleNamespace]:
    """Dev-mode app over the sqlite harness with the worker's collaborators wired to the same stores."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings
    from redsim.config import RedsimConfig

    factory = sqlite_file_factory
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)
    monkeypatch.delenv("REDSIM_ML_DATASET_UPLOAD_MAX_MB", raising=False)
    monkeypatch.delenv("REDSIM_ML_KEEP_WORK_DIR", raising=False)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("REDSIM_ML_SANDBOX_TIMEOUT_S", "240")

    with factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        sess.add(Run(id=RUN, project_id=PROJECT, mode="api", scanner="ml.campaign", status="succeeded",
                     stage_table={}))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: blobs)
    config = RedsimConfig(output_dir=str(tmp_path / "out"))
    monkeypatch.setattr("redsim.config.load_config", lambda *_a, **_k: config)
    monkeypatch.setattr("redsim.workers.events._redis_client", lambda: None)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", lambda *_a, **_k: writer)

    queued: list[str] = []
    seen_at_enqueue: list[dict[str, Any]] = []

    def fake_delay(job_id: str) -> SimpleNamespace:
        with factory.Session() as sess:
            seen_at_enqueue.append({
                "job_id": job_id,
                "register_rows": [e for e in writer.events if e.action == "dataset.register" and e.success],
                "datasets": sess.query(MlDataset).count(), "runs": sess.query(Run).count(),
                "jobs": sess.query(Job).count(),
            })
        queued.append(job_id)
        return SimpleNamespace(id=f"celery-{job_id}")

    monkeypatch.setattr("redsim.workers.tasks.dataset_validate.ml_dataset_validate.delay", fake_delay)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder = _UserHolder()
    app.dependency_overrides[get_current_user] = lambda: holder.current
    yield SimpleNamespace(
        client=TestClient(app), Session=factory.Session, writer=writer, blobs=blobs, blob_root=blob_root,
        queued=queued, seen_at_enqueue=seen_at_enqueue, user=holder, tmp_path=tmp_path,
    )
    rl._BUCKETS.clear()


def _post(api: SimpleNamespace, fields: dict[str, Any], *, parquet: bytes | None, manifest: bytes | None = None,
          parquet_name: str = "slice.parquet", params: dict[str, Any] | None = None) -> Any:
    files: list[tuple[str, tuple[str, bytes, str]]] = []
    if parquet is not None:
        files.append(("file", (parquet_name, parquet, "application/vnd.apache.parquet")))
    if manifest is not None:
        files.append(("manifest", ("manifest.json", manifest, "application/ld+json")))
    if not files:
        # A multipart body with no file part: a dummy zero-length form field keeps the encoding multipart.
        return api.client.post("/v1/datasets", data=fields, files=[("nothing", ("", b"", "text/plain"))],
                               params=params)
    return api.client.post("/v1/datasets", data=fields, files=files, params=params)


def _events(api: SimpleNamespace, action: str) -> list[Any]:
    return [event for event in api.writer.events if event.action == action]


def _counts(api: SimpleNamespace) -> tuple[int, int, int]:
    with api.Session() as sess:
        return sess.query(MlDataset).count(), sess.query(Run).count() - 1, sess.query(Job).count()


def _blob_files(api: SimpleNamespace) -> list[Path]:
    return sorted(p for p in api.blob_root.rglob("*") if p.is_file())


def _run_worker(job_id: str) -> dict[str, Any]:
    from redsim.workers.tasks.dataset_validate import ml_dataset_validate

    result = ml_dataset_validate.apply(args=[job_id]).get()
    assert isinstance(result, dict)
    return result


def _walk(value: Any) -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key), inner
            yield from _walk(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _walk(inner)


def assert_no_url_or_bytes(document: Any, payloads: list[bytes]) -> None:
    text = json.dumps(document, default=str)
    assert "://" not in text, "audit detail never carries a URL string"
    for payload in payloads:
        assert payload[:64].decode("latin-1") not in text


# ---------------------------------------------------------------------------
# Happy path: tabular slice, audit -> blobs -> rows -> enqueue, then the child parses it
# ---------------------------------------------------------------------------


def test_tabular_slice_is_admitted_then_parsed_in_the_child(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = tabular_parquet(n=12)
    resp = _post(api, tabular_fields(), parquet=payload)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    dataset_id = row["id"]
    assert row["status"] == "validating" and row["role"] == "consumed" and row["modality"] == "tabular"
    assert row["class_names"] == CLASSES and row["revision"] == sha(payload) and row["has_manifest"] is False
    assert row["files"] == [{"name": "slice.parquet", "role": "parquet", "sha256": sha(payload),
                             "size_bytes": len(payload), "content_type": "application/vnd.apache.parquet"}]
    assert row["enqueued"] is True and row["n_rows"] is None
    assert row["schema"]["features"] == FEATURES and row["schema"]["label_column"] == "label"

    # Rows: the dataset (validating), the ingest Run, the dataset.validate Job with the file list.
    with api.Session() as sess:
        stored = sess.get(MlDataset, dataset_id)
        assert stored is not None and stored.status == "validating" and stored.project_id == PROJECT
        assert stored.manifest_sha256 == sha(payload) and stored.license == LICENSE
        assert stored.blob_location == f"{PROJECT}/datasets/{dataset_id}"
        run = sess.get(Run, row["ingest_run_id"])
        assert run is not None and run.scanner == "ml.dataset_ingest" and run.status == "queued" and run.target_id is None
        job = sess.get(Job, row["ingest_job_id"])
        assert job is not None and job.type == "dataset.validate" and job.status == "queued"
        assert job.detail["dataset_id"] == dataset_id and job.detail["declared_sha256"] == sha(payload)
        assert job.detail["declared_format"] == "parquet" and job.detail["files"][0]["sha256"] == sha(payload)
        assert job.celery_task_id == f"celery-{job.id}"
    assert len(_blob_files(api)) == 1 and _blob_files(api)[0].read_bytes() == payload

    # Audit: one successful dataset.register row, ids/digests/counts only, preceding the rows and the enqueue.
    events = _events(api, "dataset.register")
    assert len(events) == 1 and events[0].success is True and events[0].project_id == PROJECT
    detail = events[0].detail
    assert detail["dataset_id"] == dataset_id and detail["sha256s"] == {"slice.parquet": sha(payload)}
    assert detail["n_files"] == 1 and detail["modality"] == "tabular" and detail["n_classes"] == 2
    assert detail["ingest_run_id"] == row["ingest_run_id"] and detail["ingest_job_id"] == row["ingest_job_id"]
    assert_no_url_or_bytes(detail, [payload])
    assert api.queued == [row["ingest_job_id"]]
    seen = api.seen_at_enqueue[0]
    assert len(seen["register_rows"]) == 1 and (seen["datasets"], seen["runs"], seen["jobs"]) == (1, 2, 1)

    # The worker: the parent never opens a Parquet file (spy), the child does and the row becomes available.
    def never(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("pyarrow.parquet.ParquetFile was called in the worker parent")

    monkeypatch.setattr(pq, "ParquetFile", never)
    for key, value in PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    result = _run_worker(row["ingest_job_id"])
    assert result["status"] == "available" and result["refusal_reason"] is None
    with api.Session() as sess:
        stored = sess.get(MlDataset, dataset_id)
        assert stored is not None and stored.status == "available" and stored.refusal_reason is None
        parse = stored.detail["validation"]["parse"]
        assert parse["n_rows"] == 12 and parse["per_class"] == {"benign": 6, "phishing": 6}
        assert parse["schema_version"] == "consumed-slice-1" and parse["x_shape"] == [12, 3]
        assert parse["revision"] == sha(payload) and parse["library_versions"]["pyarrow"]
        assert {c["name"] for c in parse["columns"]} == set(FEATURES) | {"label"}
        job = sess.get(Job, row["ingest_job_id"])
        assert job is not None and job.status == "succeeded"
        run = sess.get(Run, row["ingest_run_id"])
        assert run is not None and run.status == "succeeded"
        kinds = {a.kind for a in sess.query(Artifact).filter(Artifact.run_id == row["ingest_run_id"]).all()}
        assert kinds == {"ml.dataset_validation_report"}
    validate_rows = _events(api, "dataset.validate")
    assert len(validate_rows) == 1 and validate_rows[0].success is True and validate_rows[0].run_id == row["ingest_run_id"]
    assert validate_rows[0].detail["n_rows"] == 12 and validate_rows[0].detail["status"] == "available"
    assert validate_rows[0].detail["per_class"] == {"benign": 6, "phishing": 6}
    assert_no_url_or_bytes(validate_rows[0].detail, [payload])
    complete = [e for e in _events(api, "job.complete") if e.run_id == row["ingest_run_id"]]
    assert len(complete) == 1 and complete[0].detail["validation_status"] == "available"
    assert complete[0].detail["counts"]["rows"] == 12
    # Work directories are removed after the job.
    assert not any((api.tmp_path / "work").glob("job-*")) or not any((api.tmp_path / "work").iterdir())

    # Read side: the catalog lists it beside the bundled rows (none built here) and the record route serves it.
    listed = api.client.get("/v1/datasets").json()
    assert listed["assets"]["status"] == "missing" and listed["count"] == 1 and listed["consumed_count"] == 1
    mine = listed["datasets"][0]
    assert mine["id"] == dataset_id and mine["role"] == "consumed" and mine["status"] == "available"
    assert mine["size"] == 12 and mine["compatible_modalities"] == ["tabular"] and mine["classes"] == CLASSES
    one = api.client.get(f"/v1/datasets/{dataset_id}")
    assert one.status_code == 200 and one.json()["n_rows"] == 12 and one.json()["per_class"]["benign"] == 6
    api.user.as_stranger()
    assert api.client.get(f"/v1/datasets/{dataset_id}").status_code == 403
    assert api.client.get("/v1/datasets").json()["datasets"] == []
    assert api.client.get("/v1/datasets", params={"project": PROJECT}).status_code == 403

    # Binding hook (INTEROP-16): available slice resolves; the DatasetBinding carries the blob and the revision.
    from redsim.services.ml_datasets import consumed_dataset_binding, resolve_consumed_slice
    from redsim.services.ml_models import DatasetBindingError

    with api.Session() as sess:
        slice_ = resolve_consumed_slice(sess, dataset_id, project_id=PROJECT)
        assert slice_ is not None and slice_.n_rows == 12 and slice_.class_names == CLASSES
        assert slice_.revision == sha(payload) and slice_.parquet_files[0]["sha256"] == sha(payload)
        assert resolve_consumed_slice(sess, dataset_id, project_id=OTHER) is None
        binding = consumed_dataset_binding(sess, dataset_id, project_id=PROJECT, modality="tabular")
        assert binding.dataset_id == dataset_id and binding.split == "eval" and binding.revision == sha(payload)
        assert binding.class_names == CLASSES and Path(binding.file_path).read_bytes() == payload
        with pytest.raises(DatasetBindingError):
            consumed_dataset_binding(sess, dataset_id, project_id=PROJECT, modality="image")
        with pytest.raises(DatasetBindingError):
            consumed_dataset_binding(sess, dataset_id, project_id=OTHER)
        with pytest.raises(DatasetBindingError):
            consumed_dataset_binding(sess, "ds-nope", project_id=PROJECT)


def test_image_slice_with_croissant_manifest_becomes_available(api: SimpleNamespace) -> None:
    payload = image_parquet(n=6)
    manifest = croissant({"images.parquet": sha(payload)}, license_="MIT (test double)")
    resp = _post(api, image_fields(license_statement=None), parquet=payload, manifest=manifest,
                 parquet_name="images.parquet")
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["license"] == "MIT (test double)", "the manifest's licence stands in for the form field"
    assert row["has_manifest"] is True and row["revision"] == sha(manifest) and len(row["files"]) == 2
    assert row["schema"]["input_shape"] == list(IMAGE_SHAPE) and row["schema"]["dtype"] == "uint8"
    assert len(_blob_files(api)) == 2
    result = _run_worker(row["ingest_job_id"])
    assert result["status"] == "available", result
    with api.Session() as sess:
        stored = sess.get(MlDataset, row["id"])
        assert stored is not None and stored.status == "available"
        parse = stored.detail["validation"]["parse"]
        assert parse["n_rows"] == 6 and parse["x_shape"] == [6, 3, 4, 4] and parse["manifest_sha256"] == sha(manifest)
        assert parse["manifest_declared_sha256s"] == {"images.parquet": sha(payload)}
        assert parse["per_class"] == {"circle": 2, "square": 2, "triangle": 2}
        assert 0 <= parse["value_range_observed"][0] <= parse["value_range_observed"][1] <= 255


# ---------------------------------------------------------------------------
# Static refusals (INTEROP-13): audited success=False first, nothing persisted, nothing enqueued
# ---------------------------------------------------------------------------


def _case(fields: dict[str, Any], parquet: bytes | None, manifest: bytes | None, status: int, code: str,
          field: str, parquet_name: str = "slice.parquet") -> tuple[Any, ...]:
    return (fields, parquet, manifest, status, code, field, parquet_name)


_GOOD = tabular_parquet(n=4)
_GOOD_SHA = sha(_GOOD)

REFUSALS = [
    pytest.param(*_case(tabular_fields(license_statement=None), _GOOD, None, 422, "license_required",
                        "license_statement"), id="no-license"),
    pytest.param(*_case(tabular_fields(license_statement=None), _GOOD, croissant({"slice.parquet": None}, license_=None),
                        422, "license_required", "license_statement"), id="no-license-manifest-either"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"https://example.invalid/slice.parquet": None}), 422,
                        "remote_reference_refused", "manifest"), id="remote-https"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"s3://bucket/slice.parquet": None}), 422,
                        "remote_reference_refused", "manifest"), id="remote-s3"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"../slice.parquet": None}), 422,
                        "remote_reference_refused", "manifest"), id="parent-segment"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"/etc/slice.parquet": None}), 422,
                        "remote_reference_refused", "manifest"), id="absolute-path"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"other.parquet": None}), 422,
                        "remote_reference_refused", "manifest"), id="names-a-file-not-uploaded"),
    pytest.param(*_case(tabular_fields(), b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, None, 415,
                        "unsupported_dataset_format", "file"), id="not-parquet-magic"),
    pytest.param(*_case(tabular_fields(), _GOOD[:-4] + b"XXXX", None, 415, "unsupported_dataset_format", "file"),
                 id="footer-magic-missing"),
    pytest.param(*_case(tabular_fields(), b"\x80\x04\x95" + b"\x00" * 32, None, 415, "unsupported_dataset_format",
                        "file", "slice.pkl"), id="pickle"),
    pytest.param(*_case(tabular_fields(), b"", None, 415, "unsupported_dataset_format", "file"), id="empty"),
    pytest.param(*_case(tabular_fields(), None, None, 415, "unsupported_dataset_format", "file"), id="no-file-part"),
    pytest.param(*_case(tabular_fields(), _GOOD, b"{not json", 415, "unsupported_dataset_format", "manifest"),
                 id="manifest-not-json"),
    pytest.param(*_case(tabular_fields(), _GOOD, croissant({"slice.parquet": None}, dataset_type="sc:Person"), 415,
                        "unsupported_dataset_format", "manifest"), id="manifest-not-a-dataset"),
    pytest.param(*_case(tabular_fields(), _GOOD, json.dumps({"@context": {}, "@type": "sc:Dataset"}).encode(), 415,
                        "unsupported_dataset_format", "manifest"), id="manifest-without-distribution"),
    pytest.param(*_case(tabular_fields(class_names=None), _GOOD, None, 422, "schema_undeclared", "class_names"),
                 id="no-class-names"),
    pytest.param(*_case(tabular_fields(class_names=json.dumps(["a", "a"])), _GOOD, None, 422, "schema_undeclared",
                        "class_names"), id="duplicate-class-names"),
    pytest.param(*_case(tabular_fields(features=None), _GOOD, None, 422, "schema_undeclared", "features"),
                 id="tabular-without-features"),
    pytest.param(*_case(tabular_fields(features=json.dumps(FEATURES + ["label"])), _GOOD, None, 422,
                        "schema_undeclared", "features"), id="label-listed-as-feature"),
    pytest.param(*_case(image_fields(input_shape=None), image_parquet(n=2), None, 422, "schema_undeclared",
                        "input_shape"), id="image-without-shape"),
    pytest.param(*_case(image_fields(dtype="object"), image_parquet(n=2), None, 422, "schema_undeclared", "dtype"),
                 id="image-bad-dtype"),
    pytest.param(*_case(image_fields(value_range=None), image_parquet(n=2), None, 422, "schema_undeclared",
                        "value_range"), id="image-without-range"),
    pytest.param(*_case(tabular_fields(modality=None), _GOOD, None, 422, "schema_undeclared", "modality"),
                 id="no-modality"),
    pytest.param(*_case(tabular_fields(modality="text"), _GOOD, None, 501, "not_implemented", "modality"),
                 id="text-modality"),
    pytest.param(*_case(tabular_fields(modality="detection"), _GOOD, None, 501, "not_implemented", "modality"),
                 id="detection-modality"),
]


@pytest.mark.parametrize(("fields", "parquet", "manifest", "status", "code", "field", "parquet_name"), REFUSALS)
def test_static_refusals_are_audited_and_persist_nothing(
    api: SimpleNamespace, fields: dict[str, Any], parquet: bytes | None, manifest: bytes | None, status: int,
    code: str, field: str, parquet_name: str,
) -> None:
    resp = _post(api, fields, parquet=parquet, manifest=manifest, parquet_name=parquet_name)
    assert resp.status_code == status, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == code and detail["field"] == field, detail
    if code == "not_implemented":
        assert detail["phase"] == "B" and detail["reason"]
    events = _events(api, "dataset.register")
    assert len(events) == 1 and events[0].success is False and events[0].project_id == PROJECT
    assert events[0].detail["reason"] == code and events[0].detail["field"] == field
    assert_no_url_or_bytes(events[0].detail, [p for p in (parquet, manifest) if p])
    assert _counts(api) == (0, 0, 0) and _blob_files(api) == [] and api.queued == []


def test_size_cap_and_content_length(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSIM_ML_DATASET_UPLOAD_MAX_MB", "1")
    too_big = b"PAR1" + b"\x00" * (1024 * 1024) + b"PAR1"
    resp = _post(api, tabular_fields(), parquet=too_big, params={"project": PROJECT})
    assert resp.status_code == 413, resp.text
    assert resp.json()["detail"]["code"] == "dataset_too_large"
    events = _events(api, "dataset.register")
    assert len(events) == 1 and events[0].success is False and events[0].project_id == PROJECT
    assert events[0].detail["reason"] == "dataset_too_large" and events[0].detail["cap"] == 1024 * 1024
    assert _counts(api) == (0, 0, 0) and _blob_files(api) == []

    # Spec 17.3: Content-Length is required. A chunked body carries none.
    boundary = "redsimboundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"project_id\"\r\n\r\n{PROJECT}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"s.parquet\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + _GOOD + f"\r\n--{boundary}--\r\n".encode()
    resp = api.client.post("/v1/datasets", content=iter([body]), params={"project": PROJECT},
                           headers={"content-type": f"multipart/form-data; boundary={boundary}"})
    assert resp.status_code == 411, resp.text
    refusals = [e for e in _events(api, "dataset.register") if e.detail.get("reason") == "length_required"]
    assert len(refusals) == 1 and refusals[0].success is False
    assert _counts(api) == (0, 0, 0)


def test_json_body_is_refused_as_unsupported_format(api: SimpleNamespace) -> None:
    resp = api.client.post("/v1/datasets", json={"project_id": PROJECT, "license_statement": LICENSE})
    assert resp.status_code == 415, resp.text
    assert resp.json()["detail"]["code"] == "unsupported_dataset_format"
    events = _events(api, "dataset.register")
    assert len(events) == 1 and events[0].success is False and events[0].detail["reason"] == "unsupported_dataset_format"
    assert _counts(api) == (0, 0, 0)


def test_missing_project_id_is_422_and_gates_run_before_any_check(api: SimpleNamespace) -> None:
    resp = api.client.post("/v1/datasets", json={})
    assert resp.status_code == 422 and resp.json()["detail"]["code"] == "params_out_of_range"
    assert resp.json()["detail"]["field"] == "project_id"
    # Viewer and scanner are below the remediator tier: the policy layer's plain 403, no audit row.
    for role in ("viewer", "scanner"):
        api.user.as_role(role)
        resp = _post(api, tabular_fields(), parquet=_GOOD)
        assert resp.status_code == 403 and isinstance(resp.json()["detail"], str), resp.text
    api.user.as_stranger()
    assert _post(api, tabular_fields(), parquet=_GOOD).status_code == 403
    assert api.writer.events == [] and _counts(api) == (0, 0, 0) and _blob_files(api) == []
    # Approver and admin pass the gate.
    api.user.as_role("admin")
    assert _post(api, tabular_fields(), parquet=_GOOD).status_code == 201


# ---------------------------------------------------------------------------
# The child's refusals (INTEROP-15): typed reason on the row, success=False dataset.validate row
# ---------------------------------------------------------------------------


def _register_and_run(api: SimpleNamespace, fields: dict[str, Any], *, parquet: bytes, manifest: bytes | None = None,
                      parquet_name: str = "slice.parquet") -> tuple[dict[str, Any], dict[str, Any]]:
    resp = _post(api, fields, parquet=parquet, manifest=manifest, parquet_name=parquet_name)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    return row, _run_worker(row["ingest_job_id"])


def _assert_refused(api: SimpleNamespace, row: dict[str, Any], result: dict[str, Any], reason: str) -> None:
    from redsim.services.ml_datasets import consumed_dataset_binding, resolve_consumed_slice
    from redsim.services.ml_models import DatasetBindingError

    assert result["status"] == "refused" and result["refusal_reason"] == reason, result
    with api.Session() as sess:
        stored = sess.get(MlDataset, row["id"])
        assert stored is not None and stored.status == "refused" and stored.refusal_reason == reason
        parse = stored.detail["validation"]["parse"]
        assert parse["refusal_reason"] == reason and parse["reason"]
        job = sess.get(Job, row["ingest_job_id"])
        assert job is not None and job.status == "succeeded", "a refusal is a completed job"
        assert resolve_consumed_slice(sess, row["id"], project_id=PROJECT) is None
        with pytest.raises(DatasetBindingError):
            consumed_dataset_binding(sess, row["id"], project_id=PROJECT)
    validate_rows = [e for e in _events(api, "dataset.validate") if e.detail.get("dataset_id") == row["id"]]
    assert len(validate_rows) == 1 and validate_rows[0].success is False
    assert validate_rows[0].detail["refusal_reason"] == reason and validate_rows[0].detail["status"] == "refused"
    record = api.client.get(f"/v1/datasets/{row['id']}").json()
    assert record["status"] == "refused" and record["refusal_reason"] == reason


def test_manifest_digest_disagreement_is_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = tabular_parquet(n=6)
    manifest = croissant({"slice.parquet": "ab" * 32})
    row, result = _register_and_run(api, tabular_fields(), parquet=payload, manifest=manifest)
    _assert_refused(api, row, result, "manifest_digest_mismatch")


def test_unknown_class_label_is_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = tabular_parquet(n=6, labels=["benign", "phishing", "benign", "malware", "benign", "phishing"])
    row, result = _register_and_run(api, tabular_fields(), parquet=payload)
    _assert_refused(api, row, result, "class_names_mismatch")


def test_label_index_out_of_range_is_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = tabular_parquet(n=4, labels=[0, 1, 2, 0])
    row, result = _register_and_run(api, tabular_fields(), parquet=payload)
    _assert_refused(api, row, result, "class_names_mismatch")


def test_missing_feature_column_is_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = tabular_parquet(n=6, features=FEATURES[:2])
    row, result = _register_and_run(api, tabular_fields(), parquet=payload)
    _assert_refused(api, row, result, "schema_mismatch")


def test_image_values_outside_declared_range_are_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = image_parquet(n=4, high=255)
    row, result = _register_and_run(api, image_fields(value_range="0,1"), parquet=payload)
    _assert_refused(api, row, result, "schema_mismatch")


def test_image_row_of_the_wrong_size_is_refused_by_the_child(api: SimpleNamespace) -> None:
    payload = image_parquet(n=4, shape=(3, 2, 2))
    row, result = _register_and_run(api, image_fields(), parquet=payload)
    _assert_refused(api, row, result, "schema_mismatch")


def test_row_cap_is_enforced_in_the_child(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSIM_ML_DATASET_MAX_ROWS", "5")
    row, result = _register_and_run(api, tabular_fields(), parquet=tabular_parquet(n=8))
    _assert_refused(api, row, result, "dataset_too_large")


def test_substituted_blob_is_refused_in_the_parent_before_any_child(api: SimpleNamespace,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    payload = tabular_parquet(n=4)
    resp = _post(api, tabular_fields(), parquet=payload)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    blob = _blob_files(api)[0]
    blob.write_bytes(tabular_parquet(n=5))     # the bytes changed under the recorded digest
    spawned: list[Any] = []

    class _NoChild:
        def __init__(self, *a: Any, **k: Any) -> None:
            spawned.append(a)
            raise AssertionError("no child may be spawned for a blob that fails the parent-side digest check")

    monkeypatch.setattr("redsim.workers.tasks.dataset_validate.subprocess.Popen", _NoChild)
    result = _run_worker(row["ingest_job_id"])
    _assert_refused(api, row, result, "artifact_digest_mismatch")
    assert spawned == []


# ---------------------------------------------------------------------------
# Boundary: the child env, the API-process import guard
# ---------------------------------------------------------------------------


def test_child_is_spawned_credential_free_under_the_ml_sandbox(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    import redsim.workers.tasks.dataset_validate as task_module

    for key, value in PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    captured: list[dict[str, Any]] = []
    real_popen = task_module.subprocess.Popen

    def spy(argv: Any, **kwargs: Any) -> Any:
        captured.append({"argv": list(argv), **kwargs})
        return real_popen(argv, **kwargs)

    monkeypatch.setattr("redsim.workers.tasks.dataset_validate.subprocess.Popen", spy)
    row, result = _register_and_run(api, tabular_fields(), parquet=tabular_parquet(n=4))
    assert result["status"] == "available", result
    assert len(captured) == 1
    call = captured[0]
    assert call["argv"][:3] == [sys.executable, "-m", "redsim.ml.interop.consume"]
    assert call["start_new_session"] is True and call["stdout"] is subprocess.DEVNULL
    if os.name == "posix":
        assert call["preexec_fn"] is not None, "rlimits apply to the parse child"
    env = call["env"]
    leaked = sorted(k for k in env if k.startswith(("PYTHIA_", "AWS_", "KAGGLE", "REDSIM_AUTH", "REDSIM_DB")))
    assert leaked == [], leaked
    assert not any(k.lower().endswith("_proxy") for k in env), sorted(env)
    assert set(env.values()).isdisjoint(PARENT_SECRETS.values())
    assert env["REDSIM_DISABLE_LLM"] == "1" and env["REDSIM_PLUGINS"] == "0"
    assert sorted(k for k in env if k.startswith("REDSIM_")) == sorted(
        ["REDSIM_DISABLE_LLM", "REDSIM_ENV_FILE", "REDSIM_ML_ASSETS_DIR", "REDSIM_PLUGINS"])
    # The request the child read names files, digests, the declaration and the cap: no location, no bytes.
    assert "location" not in json.dumps(call["argv"]) and Path(call["argv"][4]).name == "request.json"


def test_api_service_and_worker_modules_import_with_pyarrow_blocked() -> None:
    probe = r"""
import json, sys
for name in ("pyarrow", "mlcroissant", "torch", "onnxruntime", "sklearn", "shap", "reportlab", "garak"):
    sys.modules[name] = None
import redsim.api.v1.datasets, redsim.services.ml_datasets, redsim.workers.tasks.dataset_validate
from redsim.services.ml_datasets import prepare_dataset_admission
loaded = sorted(m for m in sys.modules if m.split(".")[0] in {"pyarrow", "mlcroissant"} and sys.modules[m] is not None)
print(json.dumps({"loaded": loaded}))
"""
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1])["loaded"] == []


# ---------------------------------------------------------------------------
# Export route and manifest reads (interop-contribute service)
# ---------------------------------------------------------------------------


def test_export_route_gates_then_refuses_a_run_without_slices(api: SimpleNamespace) -> None:
    api.user.as_role("viewer")
    resp = api.client.post(f"/v1/runs/{RUN}/dataset")
    assert resp.status_code == 403 and isinstance(resp.json()["detail"], str)
    api.user.as_stranger()
    assert api.client.post(f"/v1/runs/{RUN}/dataset").status_code == 403
    api.user.as_role("remediator")
    assert api.client.post("/v1/runs/no-such-run/dataset").status_code == 404
    assert _events(api, "dataset.export") == [], "the gates refuse before the service is reached"
    resp = api.client.post(f"/v1/runs/{RUN}/dataset")
    # The seeded run retained no slices: the service's typed refusal, audited success=False, nothing created.
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "export_unavailable" and detail["message"]
    refusals = _events(api, "dataset.export")
    assert len(refusals) == 1 and refusals[0].success is False
    assert refusals[0].detail["code"] == "export_unavailable" and refusals[0].detail["source_run_id"] == RUN
    assert_no_url_or_bytes(refusals[0].detail, [])
    assert _counts(api) == (0, 0, 0) and api.queued == []


def test_manifest_route_404s_until_an_export_exists(api: SimpleNamespace) -> None:
    assert api.client.get("/v1/datasets/no-such-id").status_code == 404
    api.user.as_stranger()
    assert api.client.get(f"/v1/datasets/{RUN}").status_code == 403, "membership through the run"
    api.user.as_role("viewer")
    resp = api.client.get(f"/v1/datasets/{RUN}")
    assert resp.status_code == 404, "no export exists for this run yet"
    assert "no dataset export exists" in resp.text


# ---------------------------------------------------------------------------
# Campaign admission binding hook (INTEROP-16)
# ---------------------------------------------------------------------------


def test_campaign_admission_binds_an_available_consumed_slice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``POST /v1/models/{id}/attacks`` with ``dataset_id`` = a consumed slice (routes harness of test_campaign_routes)."""
    from redsim.services.ml_datasets import DeclaredSchema, is_dataset_id, new_dataset_id
    from tests.ml.test_campaign_routes import DATASET, ORG, assert_refused, build_harness, launch, seed_model
    from tests.ml.test_campaign_routes import PROJECT as ROUTES_PROJECT

    harness = build_harness(tmp_path, monkeypatch)
    seed_model(harness, dataset_id=None)                                  # manifest binds no dataset
    seed_model(harness, "model-bound", dataset_id=DATASET)                # manifest binds a bundled dataset
    with harness.Session.begin() as session:
        session.add(Project(id="project-other", org_id=ORG, name="Other", slug="other-project"))

    def add_slice(*, status: str, modality: str, project: str = ROUTES_PROJECT) -> tuple[str, str]:
        dataset_id = new_dataset_id()
        assert is_dataset_id(dataset_id)
        revision = hashlib.sha256(dataset_id.encode()).hexdigest()
        schema = DeclaredSchema(
            modality=modality, class_names=("a", "b", "c"),
            features=("f0", "f1") if modality == "tabular" else None,
            input_shape=(3, 8, 8) if modality == "image" else None,
            dtype="float32" if modality == "image" else None,
            value_range=(0.0, 1.0) if modality == "image" else None,
        )
        with harness.Session.begin() as session:
            session.add(MlDataset(
                id=dataset_id, project_id=project, status=status, license="CC0-1.0 (test double)",
                modality=modality, class_names=list(schema.class_names), manifest_sha256=revision,
                blob_location=f"{project}/datasets/{dataset_id}",
                detail={"schema": schema.to_mapping(),
                        "files": [{"name": "slice.parquet", "role": "parquet", "sha256": "cd" * 32,
                                   "location": f"/blobs/{dataset_id}", "size_bytes": 10}],
                        "validation": {"parse": {"n_rows": 6}}},
            ))
        return dataset_id, revision

    validating, _ = add_slice(status="validating", modality="image")
    tabular, _ = add_slice(status="available", modality="tabular")
    foreign, _ = add_slice(status="available", modality="image", project="project-other")
    available, revision = add_slice(status="available", modality="image")

    # refusals: not yet available, another project's, another modality's, unknown id, bound model
    detail = assert_refused(harness, launch(harness, {"attack_ids": ["fgsm"], "dataset_id": validating}),
                            "dataset_incompatible", audit_rows=1)
    assert detail["field"] == "dataset_id" and detail["dataset_role"] == "consumed"
    assert "not an available consumed slice" in detail["message"]
    assert_refused(harness, launch(harness, {"attack_ids": ["fgsm"], "dataset_id": foreign}),
                   "dataset_incompatible", audit_rows=2)
    detail = assert_refused(harness, launch(harness, {"attack_ids": ["fgsm"], "dataset_id": tabular}),
                            "dataset_incompatible", audit_rows=3)
    assert "tabular slice" in detail["message"]
    assert_refused(harness, launch(harness, {"attack_ids": ["fgsm"], "dataset_id": "ds-000000000000"}),
                   "dataset_incompatible", audit_rows=4)
    detail = assert_refused(harness, launch(harness, {"attack_ids": ["fgsm"], "dataset_id": available}, "model-bound"),
                            "dataset_incompatible", audit_rows=5)
    assert DATASET in detail["message"] and "bind the consumed slice at model upload" in detail["message"]
    assert all(row.detail.get("dataset_id") in {validating, foreign, tabular, "ds-000000000000", available}
               for row in harness.events("attack.run")), "refusal rows carry the dataset id, never its bytes"

    # the available slice of this project binds: 202, revision = the slice's manifest digest, audited as consumed
    resp = launch(harness, {"attack_ids": ["fgsm"], "dataset_id": available})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["run_id"]
    row = harness.campaign_row(run_id)
    assert row is not None
    assert row["config"]["dataset_id"] == available and row["config"]["dataset_revision"] == revision
    admitted = [e for e in harness.events("attack.run") if e.success]
    assert len(admitted) == 1 and admitted[0].run_id == run_id
    assert admitted[0].detail["dataset_id"] == available and admitted[0].detail["dataset_role"] == "consumed"
    assert admitted[0].detail["dataset_revision"] == revision
    assert harness.delay_calls == [resp.json()["job_ids"][0]]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_static_helpers() -> None:
    from redsim.services.ml_datasets import (
        DatasetAdmissionError,
        check_parquet_bytes,
        is_local_reference,
        safe_part_name,
    )

    assert is_local_reference("slice.parquet") and is_local_reference("my slice (v2).parquet")
    for bad in ("https://example.invalid/x.parquet", "s3://b/x", "../x", "/x", "dir/x.parquet", "..", "", "a\\b",
                "file:///tmp/x", "//host/x"):
        assert not is_local_reference(bad), bad
    assert safe_part_name("../../evil name.parquet", "p") == "evil_name.parquet"
    assert safe_part_name("", "slice.parquet") == "slice.parquet"
    check_parquet_bytes("ok.parquet", b"PAR1" + b"\x00" * 8 + b"PAR1")
    with pytest.raises(DatasetAdmissionError) as excinfo:
        check_parquet_bytes("x.parquet", b"PAR1" + b"\x00" * 8)
    assert excinfo.value.code == "unsupported_dataset_format"
    with pytest.raises(DatasetAdmissionError):
        check_parquet_bytes("x.npz", b"PK\x03\x04" + b"\x00" * 8 + b"PAR1")


def test_declared_schema_round_trips_and_reads_manifest_fallbacks() -> None:
    from redsim.services.ml_datasets import DeclaredSchema, declared_schema_from_fields

    schema = declared_schema_from_fields(tabular_fields(features=json.dumps([
        {"name": "f_len", "min": 0, "max": 1}, {"name": "f_dots"}])))
    assert schema.features == ("f_len", "f_dots") and schema.feature_ranges == {"f_len": (0.0, 1.0)}
    assert DeclaredSchema.from_mapping(schema.to_mapping()) == schema
    # Feature names fall back to the manifest's record set when the form does not declare them.
    manifest = json.loads(croissant({"slice.parquet": None}, record_fields=FEATURES + ["label"]))
    schema = declared_schema_from_fields(tabular_fields(features=None), manifest=manifest)
    assert schema.features == tuple(FEATURES)
    image = declared_schema_from_fields(image_fields())
    assert image.input_shape == IMAGE_SHAPE and image.value_range == (0.0, 255.0) and image.dtype == "uint8"
    assert DeclaredSchema.from_mapping(image.to_mapping()) == image
