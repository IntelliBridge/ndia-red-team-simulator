"""Black-box endpoint registration, validation, projection and deletion (ENDPOINT-01, -09, -17..20, -29, -30).

Offline file-backed sqlite harness (every session on its own connection, as the
worker's nested sessions need), foreign keys on, an in-memory audit writer shared
by the API and the eager worker task, a filesystem blob store and a hand-written
asset manifest binding ``synthetic/tiny`` to a three-class evaluation split. The
route and task tests are pure Python (the sandbox probe is replaced by a stub);
the one test marked ``ml`` registers the tiny endpoint server through the API and
runs the validate task through the REAL sandbox child, asserting what the child
saw: no credential, no proxy, no ``REDSIM_*`` secret, only the broker socket path.

The credential is the tiny server's low-entropy fake ``tok-123``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("cryptography")

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session, sessionmaker

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Artifact, AuthProfile, Base, Job, Organization, Project, Run, Target
from redsim.security_utils.secrets import encrypt_secret
from redsim.storage.blobs import FilesystemBlobStore
from tests.conftest import patch_jsonb_for_sqlite

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration

PROJECT = "proj-1"
OTHER = "proj-2"
DATASET = "synthetic/tiny"
TABULAR_DS = "kaggle:example/urls"
FIXTURE_DS = "hf:uoft-cs/cifar10"
CLASS_NAMES = ["circle", "square", "triangle"]      # tests.ml.fakes.CLASS_NAMES, spelled here so no torch is needed
TOKEN = "tok-123"                                   # tests.ml.tiny_endpoint_server.DEFAULT_TOKEN (low-entropy fake)
BEARER = "authprof-bearer01"
HEADER = "authprof-header01"
HEADER_NO_NAME = "authprof-header00"
FORM = "authprof-form0001"
FOREIGN = "authprof-other001"
URL = "http://127.0.0.1:9/predict"
# Values a worker parent realistically holds; none may reach the sandbox child. (``REDSIM_DB_URL`` is
# left unset: the eager task would open that engine for real; ``REDSIM_AUTH_PROFILES_KEY`` is set by
# the ``api`` fixture and is the REDSIM_* secret the child must not see.)
PARENT_SECRETS = {
    "PYTHIA_API_KEY": "pk_test_never_forward", "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "HTTPS_PROXY": "http://proxy.example:3128", "https_proxy": "http://proxy.example:3128",
    "HTTP_PROXY": "http://proxy.example:3128", "NO_PROXY": "localhost",
}
SECRET_KEYS = {"secret", "secret_ciphertext", "authorization", "token", "password", "api_key"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def write_assets(root: Path, split_bytes: bytes) -> None:
    """A minimal bundled asset tree: ``synthetic/tiny`` (image, 3 classes, split ``test``), a tabular
    dataset and a fixture-only dataset, in the plain JSON shape ``services.ml_models`` reads."""
    root.mkdir(parents=True, exist_ok=True)
    split = root / "datasets" / "tiny" / "test.npz"
    split.parent.mkdir(parents=True, exist_ok=True)
    split.write_bytes(split_bytes)
    tabular = root / "datasets" / "urls" / "eval.csv"
    tabular.parent.mkdir(parents=True, exist_ok=True)
    tabular.write_bytes(b"f1,f2,label\n0.1,0.2,benign\n")
    cifar = root / "datasets" / "cifar" / "test.npz"
    cifar.parent.mkdir(parents=True, exist_ok=True)
    cifar.write_bytes(b"cifar placeholder")

    def file_entry(path: Path) -> dict[str, Any]:
        return {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size}

    (root / "MANIFEST.json").write_text(json.dumps({
        "schema_version": 1,
        "datasets": {
            DATASET: {"id": DATASET, "revision": "deadbeef", "class_names": CLASS_NAMES, "license": "test double",
                      "preprocessing": {"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
                      "splits": {"test": {"name": "test", "n": 24, "file": file_entry(split)}}},
            TABULAR_DS: {"id": TABULAR_DS, "revision": "rev2", "class_names": ["benign", "phishing"],
                         "license": "CC0", "preprocessing": {"features": ["f1", "f2"]},
                         "splits": {"eval": {"name": "eval", "n": 1, "file": file_entry(tabular)}}},
            FIXTURE_DS: {"id": FIXTURE_DS, "revision": "rev1", "class_names": [f"c{i}" for i in range(10)],
                         "license": "MIT", "fixture_only": True,
                         "preprocessing": {"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
                         "splits": {"test": {"name": "test", "n": 4, "file": file_entry(cifar)}}},
        },
        "models": {},
    }))


@pytest.fixture
def assets_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "assets"
    write_assets(root, b"npz placeholder (the API never opens it)")
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(root))
    return root


class _UserHolder:
    """The dependency override reads ``current`` so a test can switch roles mid-way."""

    def __init__(self) -> None:
        self.current = CurrentUser(sub="dev:admin@test", email="admin@test",
                                   project_memberships={PROJECT: "admin", OTHER: "admin"})

    def as_role(self, role: str) -> None:
        self.current = CurrentUser(sub=f"dev:{role}@test", email=f"{role}@test",
                                   project_memberships={PROJECT: role, OTHER: role})


@pytest.fixture
def sqlite_file_factory(tmp_path: Path) -> SimpleNamespace:
    """A file-backed sqlite engine: one connection per session, foreign keys on, JSONB patched for sqlite."""
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'endpoint.db'}", connect_args={"check_same_thread": False})

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
def api(sqlite_file_factory: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        assets_root: Path) -> Iterator[SimpleNamespace]:
    """Dev-mode app over the sqlite harness: two projects, five auth profiles, a recording enqueue."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    sqlite_session_factory = sqlite_file_factory
    monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("REDSIM_AUTH_PROFILES_KEY_PREVIOUS", raising=False)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        ciphertext = encrypt_secret(TOKEN)
        sess.add(AuthProfile(id=BEARER, project_id=PROJECT, name="bearer", kind="bearer", config={},
                             secret_ciphertext=ciphertext))
        sess.add(AuthProfile(id=HEADER, project_id=PROJECT, name="header", kind="header",
                             config={"header_name": "X-Api-Key"}, secret_ciphertext=ciphertext))
        sess.add(AuthProfile(id=HEADER_NO_NAME, project_id=PROJECT, name="header-no-name", kind="header", config={},
                             secret_ciphertext=ciphertext))
        sess.add(AuthProfile(id=FORM, project_id=PROJECT, name="form", kind="form",
                             config={"login_url": "http://127.0.0.1:9/login"}, secret_ciphertext=ciphertext))
        sess.add(AuthProfile(id=FOREIGN, project_id=OTHER, name="bearer", kind="bearer", config={},
                             secret_ciphertext=ciphertext))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: blobs)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setattr("redsim.api.v1.targets.resolve_writer", lambda _config: writer)

    queued: list[str] = []
    seen_at_enqueue: list[dict[str, Any]] = []

    def fake_delay(job_id: str) -> SimpleNamespace:
        # Spec 9.3 step 4: by the time Celery is touched the chained row and the committed rows exist
        # (read on a fresh connection, so only committed state counts).
        with sqlite_session_factory.Session() as sess:
            seen_at_enqueue.append({
                "job_id": job_id,
                "register_rows": [e for e in writer.events if e.action == "model.register" and e.success],
                "targets": sess.query(Target).count(), "runs": sess.query(Run).count(),
                "jobs": sess.query(Job).count(),
            })
        queued.append(job_id)
        return SimpleNamespace(id=f"celery-{job_id}")

    monkeypatch.setattr("redsim.workers.tasks.ml_model.ml_model_validate.delay", fake_delay)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder = _UserHolder()
    app.dependency_overrides[get_current_user] = lambda: holder.current
    yield SimpleNamespace(
        client=TestClient(app), Session=sqlite_session_factory.Session, session_cm=sqlite_session_factory.session_cm,
        writer=writer, blobs=blobs, blob_root=blob_root, assets_root=assets_root, queued=queued,
        seen_at_enqueue=seen_at_enqueue, user=holder, tmp_path=tmp_path,
    )
    rl._BUCKETS.clear()


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "source": "endpoint", "project_id": PROJECT, "url": URL, "auth_profile_id": BEARER, "modality": "image",
        "dataset_id": DATASET, "dataset_split": "test", "name": "tiny endpoint",
        "license_statement": "non-operational evaluation instance of a test double; MIT",
        "evaluation_instance_attestation": True, "input_shape": [3, 8, 8], "class_names": list(CLASS_NAMES),
        "batch_rows": 16, "timeout_s": 5,
    }
    for key, value in overrides.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return body


def _events(api: SimpleNamespace, action: str) -> list[Any]:
    return [event for event in api.writer.events if event.action == action]


def _counts(api: SimpleNamespace) -> tuple[int, int, int]:
    with api.Session() as sess:
        return sess.query(Target).count(), sess.query(Run).count(), sess.query(Job).count()


def _walk(value: Any) -> Iterator[tuple[str, Any]]:
    """Every ``(key, leaf)`` pair of a JSON document, for the secret-freeness scans."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key), inner
            yield from _walk(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _walk(inner)


def assert_secret_free(document: Any, *, forbid_url: bool = True) -> None:
    keys = {key.lower() for key, _ in _walk(document)}
    assert not (keys & SECRET_KEYS), f"secret-shaped key in {sorted(keys & SECRET_KEYS)}"
    text = json.dumps(document, default=str)
    assert TOKEN not in text and "Bearer " not in text and "user:pw" not in text
    if forbid_url:
        assert "/predict" not in text, "the URL never leaves the row; projections and audit carry the host only"


def _register(api: SimpleNamespace, **overrides: Any) -> Any:
    return api.client.post("/v1/models", json=_body(**overrides))


# ---------------------------------------------------------------------------
# Registration: happy path, order, RBAC
# ---------------------------------------------------------------------------


def test_endpoint_registration_writes_audit_then_rows_then_enqueues(api: SimpleNamespace) -> None:
    resp = _register(api)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["source"] == "endpoint" and row["format"] == "endpoint" and row["status"] == "validating"
    assert row["modality"] == "image" and row["gradients"] is False and row["registered"] is True
    assert len(row["sha256"]) == 64, "sha256 is the descriptor digest, not a file digest"
    assert row["manifest"]["size_bytes"] == 0 and row["manifest"]["endpoint"]["url_host"] == "127.0.0.1:9"
    assert row["endpoint"]["host"] == "127.0.0.1:9" and row["endpoint"]["scheme"] == "http"
    assert row["endpoint"]["plaintext"] is True and row["endpoint"]["auth_profile_id"] == BEARER
    assert row["endpoint"]["auth_kind"] == "bearer" and row["endpoint"]["contract_version"] == "endpoint-v1"
    assert row["endpoint"]["attestation"]["evaluation_instance"] is True and row["endpoint"]["verified"] is False
    assert row["endpoint"]["fingerprint_sha256"] is None and row["endpoint"]["probe"] is None
    assert row["enqueued"] is True and row["campaign_history"] == []
    assert_secret_free(row)

    # Rows: Target (kind endpoint, value URL, verified False), the ml.ingest Run, the model.validate Job.
    with api.Session() as sess:
        target = sess.get(Target, row["id"])
        assert target is not None and target.kind == "ml_model_endpoint" and target.value == URL
        assert target.verified is False and target.detail["status"] == "validating"
        assert target.detail["manifest"]["format"] == "endpoint" and target.detail["manifest"]["gradients"] is False
        assert target.detail["attestation"]["evaluation_instance"] is True
        assert_secret_free(target.detail)
        run = sess.get(Run, row["ingest_run_id"])
        assert run is not None and run.scanner == "ml.ingest" and run.status == "queued" and run.target_id == target.id
        job = sess.get(Job, row["ingest_job_id"])
        assert job is not None and job.type == "model.validate" and job.status == "queued"
        assert job.detail == {"target_id": target.id, "declared_format": "endpoint", "auth_profile_id": BEARER}
        assert job.celery_task_id == f"celery-{job.id}"

    # Audit: one successful model.register row, URL as target, allowlist pass, host and ids in detail.
    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is True and events[0].allowlist_check == "pass"
    assert events[0].target == URL and events[0].project_id == PROJECT and events[0].run_id == row["ingest_run_id"]
    detail = events[0].detail
    assert detail["kind"] == "ml_model_endpoint" and detail["source"] == "endpoint" and detail["host"] == "127.0.0.1:9"
    assert detail["auth_profile_id"] == BEARER and detail["auth_kind"] == "bearer"
    assert detail["descriptor_sha256"] == row["sha256"] and detail["attestation"] == {"evaluation_instance": True}
    assert detail["target_id"] == row["id"] and detail["dataset_id"] == DATASET and detail["n_classes"] == 3
    assert_secret_free(detail)

    # Order: the chained row and the rows exist when Celery is touched (spec 9.3 step 4).
    assert api.queued == [row["ingest_job_id"]]
    seen = api.seen_at_enqueue[0]
    assert len(seen["register_rows"]) == 1 and (seen["targets"], seen["runs"], seen["jobs"]) == (1, 1, 1)

    # The catalog shows it with the host only; the LLM registry row is still its own not_implemented entry.
    listed = api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]
    mine = next(item for item in listed if item["id"] == row["id"])
    assert mine["source"] == "endpoint" and mine["status"] == "validating" and mine["endpoint"]["host"] == "127.0.0.1:9"
    assert_secret_free(mine)
    llm = [item for item in listed if item["id"] == "endpoint_stub"]
    assert len(llm) == 1 and llm[0]["status"] == "not_implemented" and llm[0]["modality"] == "llm"
    one = api.client.get(f"/v1/models/{row['id']}").json()
    assert one["endpoint"]["host"] == "127.0.0.1:9" and one["campaign_history"] == []


def test_header_kind_profile_is_accepted(api: SimpleNamespace) -> None:
    resp = _register(api, auth_profile_id=HEADER)
    assert resp.status_code == 201, resp.text
    assert resp.json()["endpoint"]["auth_kind"] == "header"
    assert _events(api, "model.register")[0].detail["auth_kind"] == "header"


@pytest.mark.parametrize("role", ["remediator", "approver", "scanner"])
def test_non_admin_roles_are_refused_before_anything_is_written(api: SimpleNamespace, role: str) -> None:
    api.user.as_role(role)
    resp = _register(api)
    assert resp.status_code == 403, resp.text
    assert _counts(api) == (0, 0, 0) and api.queued == []
    assert _events(api, "model.register") == [], "the policy layer denied; no success row exists"


# ---------------------------------------------------------------------------
# Registration: every refusal code, audited success=False first, nothing persisted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "status", "code", "field"),
    [
        (dict(url="http://user:pw@127.0.0.1:9/predict"), 422, "endpoint_url_invalid", "url"),
        (dict(url="http://127.0.0.1:9/predict?token=abc"), 422, "endpoint_url_invalid", "url"),
        (dict(url="http://127.0.0.1:9/predict#frag"), 422, "endpoint_url_invalid", "url"),
        (dict(url="ftp://127.0.0.1/predict"), 422, "endpoint_url_invalid", "url"),
        (dict(url="not a url"), 422, "endpoint_url_invalid", "url"),
        (dict(url="https://models.example.mil/predict"), 403, "endpoint_not_allowlisted", "url"),
        (dict(auth_profile_id=FOREIGN), 404, "not_found", "auth_profile_id"),
        (dict(auth_profile_id="authprof-nope"), 404, "not_found", "auth_profile_id"),
        (dict(auth_profile_id=FORM), 422, "auth_profile_kind_unsupported", "auth_profile_id"),
        (dict(auth_profile_id=HEADER_NO_NAME), 422, "auth_profile_kind_unsupported", "auth_profile_id"),
        (dict(auth_profile_id=None), 422, "auth_profile_required", "auth_profile_id"),
        (dict(dataset_id="hf:nobody/unknown"), 422, "dataset_incompatible", "dataset_id"),
        (dict(dataset_id=TABULAR_DS, dataset_split="eval"), 422, "dataset_incompatible", "dataset_id"),
        (dict(dataset_id=FIXTURE_DS), 422, "dataset_incompatible", "dataset_id"),
        (dict(dataset_split="train"), 422, "dataset_incompatible", "dataset_split"),
        (dict(class_names=None, n_classes=5), 422, "dataset_incompatible", "n_classes"),
        (dict(class_names=["triangle", "square", "circle"]), 422, "dataset_incompatible", "class_names"),
        (dict(class_names=None, n_classes=None), 422, "schema_undeclared", "class_names"),
        (dict(input_shape=[8, 8]), 422, "schema_undeclared", "input_shape"),
        (dict(license_statement=None), 422, "license_required", "license_statement"),
        (dict(evaluation_instance_attestation=False), 422, "attestation", "evaluation_instance_attestation"),
        (dict(evaluation_instance_attestation=None), 422, "attestation", "evaluation_instance_attestation"),
        (dict(modality="llm"), 501, "not_implemented", "modality"),
        (dict(batch_rows=5000), 422, "params_out_of_range", "batch_rows"),
        (dict(timeout_s=600), 422, "params_out_of_range", "timeout_s"),
        (dict(surprise="field"), 422, "params_out_of_range", "surprise"),
    ],
    ids=["userinfo", "query", "fragment", "ftp", "not-a-url", "not-allowlisted", "foreign-profile",
         "unknown-profile", "form-kind", "header-without-name", "no-profile", "unknown-dataset",
         "dataset-modality-mismatch", "fixture-dataset", "unknown-split", "n-classes-mismatch",
         "class-order-mismatch", "no-classes", "input-shape-rank", "no-license", "attestation-false",
         "attestation-missing", "llm-modality", "batch-rows-cap", "timeout-cap", "unknown-field"],
)
def test_registration_refusal_codes_and_audit(
    api: SimpleNamespace, overrides: dict[str, Any], status: int, code: str, field: str,
) -> None:
    from redsim.api.v1 import models as models_route

    if code == "auth_profile_required":
        code = models_route.AUTH_PROFILE_REQUIRED
    if code == "attestation":
        code = models_route.ATTESTATION_REQUIRED
    resp = _register(api, **overrides)
    assert resp.status_code == status, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == code and detail["field"] == field, detail
    if code == "not_implemented":
        assert detail["phase"] == "B"
    assert_secret_free(detail)

    events = _events(api, "model.register")
    assert len(events) == 1 and api.writer.events == events, "exactly one row: the refusal"
    event = events[0]
    assert event.success is False and event.project_id == PROJECT
    assert event.detail["reason"] == code and event.detail["field"] == field
    assert event.detail["kind"] == "ml_model_endpoint" and event.detail["source"] == "endpoint"
    if code == "endpoint_not_allowlisted":
        # The URL is the refused target and the verdict is on the row, like every allowlist refusal.
        assert event.target == overrides["url"] and event.allowlist_check == "fail"
        assert event.detail["host"] == "models.example.mil" and event.detail["rule"] == "not_allowlisted"
    else:
        assert event.target is None and event.allowlist_check == "n/a"
        assert_secret_free(event.detail)
    assert "pw" not in json.dumps(event.detail) or "user:pw" not in json.dumps(event.detail)
    assert _counts(api) == (0, 0, 0) and api.queued == []


def test_llm_endpoint_kind_is_delegated_or_501(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    from redsim.api.v1 import models as models_route

    monkeypatch.setattr(models_route, "_llm_registrar", lambda: None)
    resp = api.client.post("/v1/models", json={"source": "endpoint", "project_id": PROJECT, "endpoint_kind": "llm",
                                               "model_id": "anthropic/claude", "auth_profile_id": BEARER})
    assert resp.status_code == 501, resp.text
    assert resp.json()["detail"]["code"] == "not_implemented" and resp.json()["detail"]["phase"] == "B"
    assert resp.json()["detail"]["field"] == "endpoint_kind"
    events = _events(api, "model.register")
    assert len(events) == 1 and events[0].success is False and events[0].detail["endpoint_kind"] == "llm"
    assert _counts(api) == (0, 0, 0)

    calls: list[dict[str, Any]] = []

    def registrar(session: Any, *, project_id: str, fields: dict[str, Any], actor: str, audit_writer: Any,
                  config: Any) -> dict[str, Any]:
        calls.append({"project_id": project_id, "fields": dict(fields), "actor": actor})
        return {"id": "llm-1", "source": "endpoint", "modality": "llm", "status": "validating"}

    monkeypatch.setattr(models_route, "_llm_registrar", lambda: registrar)
    resp = api.client.post("/v1/models", json={"source": "endpoint", "project_id": PROJECT, "endpoint_kind": "llm",
                                               "model_id": "anthropic/claude", "auth_profile_id": BEARER})
    assert resp.status_code == 201, resp.text
    assert resp.json()["id"] == "llm-1" and resp.json()["campaign_history"] == []
    assert calls[0]["project_id"] == PROJECT and calls[0]["fields"]["endpoint_kind"] == "llm"
    assert calls[0]["actor"] == "user:dev:admin@test"


def test_queue_outage_rolls_the_registration_back(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(job_id: str) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr("redsim.workers.tasks.ml_model.ml_model_validate.delay", broken)
    resp = _register(api)
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["code"] == "queue_unavailable"
    assert _counts(api) == (0, 0, 0), "Target, Run and Job were withdrawn with the failed enqueue"
    events = _events(api, "model.register")
    assert [e.success for e in events] == [True, False]
    assert events[1].detail["reason"] == "queue_unavailable" and events[1].detail["rolled_back"] is True
    assert events[1].detail["target_id"] == events[0].detail["target_id"]
    assert events[1].detail["error_class"] == "ConnectionError"
    assert_secret_free(events[1].detail)
    # The id is gone from the catalog and the detail route alike.
    assert api.client.get(f"/v1/models/{events[0].detail['target_id']}", params={"project": PROJECT}).status_code == 404


# ---------------------------------------------------------------------------
# Projection and deletion of registered endpoint targets
# ---------------------------------------------------------------------------


def _seed_endpoint(api: SimpleNamespace, target_id: str = "ep-1", *, status: str = "available",
                   project: str = PROJECT) -> None:
    fingerprint = "f" * 64
    manifest = {
        "name": "tiny endpoint", "modality": "image", "format": "endpoint", "sha256": "d" * 64, "size_bytes": 0,
        "input_shape": [3, 8, 8], "n_classes": 3, "class_names": CLASS_NAMES, "dataset_id": DATASET,
        "dataset_split": "test", "dataset_revision": "deadbeef", "status": status, "gradients": False,
        "bundled": False, "license": "MIT",
        "endpoint": {"url_host": "127.0.0.1:9", "auth_profile_id": BEARER, "contract_version": "endpoint-v1",
                     "input_shape": [3, 8, 8], "batch_rows": 16, "timeout_s": 5.0},
    }
    with api.Session() as sess:
        target = Target(id=target_id, project_id=project, kind="ml_model_endpoint", value=URL, verified=False)
        target.detail = {
            **manifest, "source": "endpoint", "auth_profile_id": BEARER, "auth_kind": "bearer",
            "input_format": "float32_nchw", "scheme": "http", "plaintext": True,
            "attestation": {"evaluation_instance": True}, "manifest": manifest,
            "endpoint_probe": {"http_status": 200, "latency_ms": 3.2, "n_rows": 8, "output_kind": "probabilities",
                               "tls_mode": "plaintext", "checked_at": "2026-09-09T00:00:00+00:00"},
            "endpoint_fingerprint": {"sha256": fingerprint, "label": "remote model identity", "output_kind":
                                     "probabilities"},
            "validation": {"detected_format": "endpoint", "gradients": False, "onnx_torch_argmax_agreement": None,
                           "refusal_reason": None, "ingest_job_id": "job-x",
                           "probe": {"http_status": 200, "fingerprint_sha256": fingerprint}},
        }
        sess.add(target)
        sess.flush()
        sess.add(Run(id=f"run-ingest-{target_id}", project_id=project, target_id=target_id, mode="api",
                     status="succeeded", scanner="ml.ingest", stage_table={}))
        sess.commit()


def test_projection_shows_host_fingerprint_and_black_box_attacks_only(api: SimpleNamespace) -> None:
    pytest.importorskip("numpy")   # the attack registry imports numpy at module import
    _seed_endpoint(api)
    listed = api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]
    row = next(item for item in listed if item["id"] == "ep-1")
    assert row["source"] == "endpoint" and row["status"] == "available" and row["format"] == "endpoint"
    assert row["gradients"] is False and row["sha256"] == "d" * 64
    endpoint = row["endpoint"]
    assert endpoint["host"] == "127.0.0.1:9" and endpoint["auth_profile_id"] == BEARER
    assert endpoint["fingerprint_sha256"] == "f" * 64 and endpoint["output_kind"] == "probabilities"
    assert endpoint["probe"]["http_status"] == 200 and endpoint["probe"]["n_rows"] == 8
    assert row["available_attacks"] == ["hopskipjump"], "image endpoints launch the black-box adapters only"
    assert_secret_free(row)
    one = api.client.get("/v1/models/ep-1").json()
    assert one["validation"]["probe"]["fingerprint_sha256"] == "f" * 64
    assert_secret_free(one)
    # The registry's LLM row is separate and still says not_implemented.
    llm = next(item for item in listed if item["id"] == "endpoint_stub")
    assert llm["status"] == "not_implemented" and llm["phase"] == "B"


def test_tabular_endpoint_lists_zoo_and_hopskipjump(api: SimpleNamespace) -> None:
    pytest.importorskip("numpy")
    _seed_endpoint(api, "ep-tab")
    with api.Session() as sess:
        target = sess.get(Target, "ep-tab")
        assert target is not None
        target.detail = {**target.detail, "modality": "tabular"}
        sess.commit()
    row = api.client.get("/v1/models/ep-tab").json()
    assert row["available_attacks"] == ["hopskipjump", "zoo"]


def test_delete_keeps_the_row_refuses_in_flight_and_names_the_host(api: SimpleNamespace) -> None:
    _seed_endpoint(api)
    with api.Session() as sess:
        sess.add(Run(id="run-c1", project_id=PROJECT, target_id="ep-1", mode="api", status="running",
                     scanner="ml.campaign", stage_table={}))
        sess.commit()
    resp = api.client.delete("/v1/models/ep-1")
    assert resp.status_code == 409 and resp.json()["detail"]["code"] == "campaign_in_flight"
    assert _events(api, "target.manage") == []

    with api.Session() as sess:
        run = sess.get(Run, "run-c1")
        assert run is not None
        run.status = "succeeded"
        sess.commit()
    resp = api.client.delete("/v1/models/ep-1")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": "ep-1", "status": "deleted", "blob_deleted": None}
    events = _events(api, "target.manage")
    assert len(events) == 1 and events[0].success is True and events[0].allowlist_check == "n/a"
    detail = events[0].detail
    assert detail["op"] == "delete" and detail["kind"] == "ml_model_endpoint" and detail["target_id"] == "ep-1"
    assert detail["host"] == "127.0.0.1:9" and detail["value"] == "127.0.0.1:9" and detail["source"] == "endpoint"
    assert detail["auth_profile_id"] == BEARER and detail["previous_status"] == "available"
    assert_secret_free(detail)
    # Soft delete: the row stays for history, the catalog hides it, the id answers 404.
    with api.Session() as sess:
        target = sess.get(Target, "ep-1")
        assert target is not None and target.detail["status"] == "deleted" and target.value == URL
        assert sess.get(Run, "run-c1") is not None
    assert api.client.get("/v1/models/ep-1", params={"project": PROJECT}).status_code == 404
    ids = [item["id"] for item in api.client.get("/v1/models", params={"project": PROJECT}).json()["models"]]
    assert "ep-1" not in ids
    assert api.client.delete("/v1/models/ep-1").status_code == 404


def test_delete_needs_target_manage(api: SimpleNamespace) -> None:
    _seed_endpoint(api)
    api.user.as_role("remediator")
    assert api.client.delete("/v1/models/ep-1").status_code == 403
    with api.Session() as sess:
        target = sess.get(Target, "ep-1")
        assert target is not None and target.detail["status"] == "available"


# ---------------------------------------------------------------------------
# The validate task, endpoint variant (probe stubbed; the real child runs in the ml test below)
# ---------------------------------------------------------------------------


def _child_manifest(url_host: str = "127.0.0.1:9", *, output_kind: str = "probabilities") -> dict[str, Any]:
    """What ``probe_endpoint_sandboxed`` returns for a healthy endpoint (``EndpointTarget.manifest()`` shape)."""
    fingerprint = hashlib.sha256(b"first response").hexdigest()
    return {
        "name": "tiny endpoint", "modality": "image", "format": "endpoint", "sha256": "c" * 64, "size_bytes": 0,
        "input_shape": [3, 8, 8], "n_classes": 3, "class_names": CLASS_NAMES, "dataset_id": DATASET,
        "dataset_split": "test", "dataset_revision": "deadbeef", "status": "available", "gradients": False,
        "bundled": False, "license": "MIT", "source": "endpoint", "access": "black-box-endpoint",
        "torch_model": None, "surrogate": None, "scheme": "http",
        "endpoint": {"url_host": url_host, "auth_profile_id": BEARER, "contract_version": "endpoint-v1",
                     "input_shape": [3, 8, 8], "batch_rows": 16, "timeout_s": 5.0},
        "endpoint_probe": {"http_status": 200, "latency_ms": 4.5, "n_rows": 8, "output_kind": output_kind,
                           "tls_mode": "plaintext", "checked_at": "2026-09-09T00:00:00+00:00"},
        "endpoint_fingerprint": {"sha256": fingerprint, "label": "remote model identity (first response "
                                 "fingerprint), not a weights digest", "output_kind": output_kind},
        "endpoint_queries": {"by_purpose": {"probe": {"requests": 1, "rows": 8}}, "rows": 8, "requests": 1,
                             "batch_rows": 16},
        "endpoint_broker": {"url_host": url_host, "scheme": "http", "contract": "endpoint-v1",
                            "tls_mode": "plaintext", "plaintext_loopback": True, "resolved_addresses": ["127.0.0.1"],
                            "limits": {"rps": 10.0, "batch_rows": 16, "timeout_s": 5.0, "max_rows": 500000,
                                       "max_requests": 20000},
                            "requests": 1, "rows": 8, "request_bytes": 6200, "response_bytes": 300, "retries": 0,
                            "failures": 0, "fingerprint_sha256": fingerprint, "output_kind": output_kind,
                            "by_purpose": {"probe": {"requests": 1, "rows": 8}}},
        "endpoint_limits": {"rps": 10.0, "batch_rows": 16, "timeout_s": 5.0, "max_rows": 500000,
                            "max_requests": 20000},
        "explainer": "PartitionExplainer over predict_proba (no differentiable module)",
        "eval_n": 24, "eval_per_class": {"circle": 8, "square": 8, "triangle": 8},
        "caveats": ["remote endpoint"], "nondeterminism": ["remote endpoint predictions"],
    }


@pytest.fixture
def worker(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """The eager Celery task over the same harness: worker audit rows land in ``api.writer``."""
    pytest.importorskip("celery")
    monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", lambda **_k: api.writer)
    monkeypatch.setattr("redsim.workers.events.publish_job_event", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "redsim.config.load_config",
        lambda *a, **k: SimpleNamespace(
            output_dir=str(api.tmp_path / "out"),
            target_allowlist=["127.0.0.1", "localhost", "host.docker.internal"],
            auth_profiles_key=os.environ.get("REDSIM_AUTH_PROFILES_KEY"), auth_profiles_key_previous=None,
        ),
    )
    probes: list[dict[str, Any]] = []
    return SimpleNamespace(probes=probes)


def _stub_probe(monkeypatch: pytest.MonkeyPatch, worker: SimpleNamespace, *, result: Any = None,
                error: Exception | None = None) -> None:
    def probe(target_id: str, target_endpoint: dict[str, Any], endpoint_auth: Any, **kwargs: Any) -> dict[str, Any]:
        worker.probes.append({"target_id": target_id, "target_endpoint": json.loads(json.dumps(target_endpoint)),
                              "endpoint_auth": endpoint_auth, "kwargs": kwargs})
        if error is not None:
            raise error
        return result if result is not None else _child_manifest()

    monkeypatch.setattr("redsim.ml.sandbox.probe_endpoint_sandboxed", probe)


def _run_validate(api: SimpleNamespace, job_id: str) -> Any:
    from redsim.workers.tasks.ml_model import ml_model_validate

    return ml_model_validate.apply(args=(job_id,), throw=True)


def _read(api: SimpleNamespace, row: dict[str, Any]) -> tuple[Job, Run, Target, list[Artifact]]:
    with api.Session() as sess:
        job = sess.get(Job, row["ingest_job_id"])
        run = sess.get(Run, row["ingest_run_id"])
        target = sess.get(Target, row["id"])
        artifacts = list(sess.query(Artifact).filter(Artifact.run_id == row["ingest_run_id"]).all())
    assert job is not None and run is not None and target is not None
    return job, run, target, artifacts


def test_validate_task_probes_through_the_broker_and_marks_available(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_probe(monkeypatch, worker)
    row = _register(api).json()
    result = _run_validate(api, row["ingest_job_id"])
    assert result.result["status"] == "available" and result.result["refusal_reason"] is None

    # The worker decrypted the credential at pickup and handed it to the sandbox parent in memory only.
    assert len(worker.probes) == 1
    probe = worker.probes[0]
    assert probe["endpoint_auth"] == {"kind": "bearer", "config": {}, "secret": TOKEN}
    block = probe["target_endpoint"]
    assert block["url"] == URL and block["auth_profile_id"] == BEARER
    assert block["manifest"]["dataset_id"] == DATASET and block["manifest"]["dataset_split"] == "test"
    assert block["manifest"]["n_classes"] == 3 and block["manifest"]["modality"] == "image"
    assert block["batch_rows"] == 16 and block["timeout_s"] == 5.0
    assert probe["kwargs"]["endpoint_allowlist"] == ["127.0.0.1", "localhost", "host.docker.internal"]
    assert probe["kwargs"]["job_id"] == row["ingest_job_id"]
    assert_secret_free(block, forbid_url=False)

    job, run, target, artifacts = _read(api, row)
    assert job.status == "succeeded" and run.status == "succeeded"
    assert job.detail == {"target_id": row["id"], "declared_format": "endpoint", "auth_profile_id": BEARER}
    detail = target.detail
    assert detail["status"] == "available" and detail["refusal_reason"] is None and detail["gradients"] is False
    assert detail["sha256"] == "c" * 64 and detail["validation"]["registration_descriptor_sha256"] == row["sha256"]
    assert detail["attestation"]["evaluation_instance"] is True and detail["auth_kind"] == "bearer"
    validation = detail["validation"]
    assert validation["detected_format"] == "endpoint" and validation["gradients"] is False
    assert validation["onnx_torch_argmax_agreement"] is None and validation["onnx_conversion"] is None
    assert validation["class_count"] == 3 and validation["ingest_job_id"] == job.id
    assert validation["probe"]["http_status"] == 200 and validation["probe"]["latency_ms"] == 4.5
    assert validation["probe"]["n_rows"] == 8 and validation["probe"]["rows"] == 8
    assert len(validation["probe"]["fingerprint_sha256"]) == 64
    assert validation["probe"]["host"] == "127.0.0.1:9" and validation["probe"]["auth_profile_id"] == BEARER
    assert_secret_free(detail)

    # Audit chain: model.register, model.validate (URL as target, allowlist pass), job.complete.
    actions = [e.action for e in api.writer.events]
    assert actions == ["model.register", "model.validate", "job.complete"]
    validate = api.writer.events[1]
    assert validate.success is True and validate.target == URL and validate.allowlist_check == "pass"
    assert validate.run_id == row["ingest_run_id"] and validate.project_id == PROJECT
    assert validate.detail["status"] == "available" and validate.detail["gradients"] is False
    assert validate.detail["detected_format"] == "endpoint" and validate.detail["onnx_torch_argmax_agreement"] is None
    assert validate.detail["fingerprint_sha256"] == validation["probe"]["fingerprint_sha256"]
    assert validate.detail["http_status"] == 200 and validate.detail["latency_ms"] == 4.5
    assert validate.detail["host"] == "127.0.0.1:9" and validate.detail["rows"] == 8
    complete = api.writer.events[2]
    assert complete.success is True and complete.detail["validation_status"] == "available"
    assert complete.detail["counts"]["endpoint_rows"] == 8 and complete.detail["counts"]["endpoint_requests"] == 1
    assert complete.detail["counts"]["endpoint_bytes"] == 6500
    for event in api.writer.events:
        assert_secret_free(event.detail)

    # The validation report artifact carries the probe and no credential.
    assert len(artifacts) == 1
    report = json.loads(api.blobs.get(artifacts[0].location))
    assert report["status"] == "available" and report["validation"]["probe"]["http_status"] == 200
    assert_secret_free(report)

    # The catalog now shows it available with the fingerprint.
    shown = api.client.get(f"/v1/models/{row['id']}").json()
    assert shown["status"] == "available" and shown["endpoint"]["fingerprint_sha256"] == validate.detail[
        "fingerprint_sha256"]
    assert shown["available_attacks"] in (None, ["hopskipjump"])


def _typed(name: str, message: str) -> Exception:
    """The typed failure the sandbox rebuilds from the child's envelope, by its ``redsim.ml.errors`` name.

    Every endpoint class resolves through ``redsim.ml.errors`` (the broker's and the egress module's
    classes are re-exported there by name, PEP 562), with the constructors the B1 library gave them:
    ``EndpointSchemaMismatch(message, field=)`` and ``EgressRefused(rule, message, host=)``.
    """
    from redsim.ml import errors as ml_errors

    cls = getattr(ml_errors, name)
    if name == "EndpointSchemaMismatch":
        return cls(message, field="probabilities")
    if name in {"EgressRefused", "EndpointNotAllowlisted", "EndpointUrlInvalid"}:
        rule = {"EgressRefused": "private_address", "EndpointNotAllowlisted": "not_allowlisted",
                "EndpointUrlInvalid": "url_shape"}[name]
        return cls(rule, message, host="127.0.0.1")
    return cls(message)


@pytest.mark.parametrize(
    ("error", "message", "reason", "code"),
    [
        ("EndpointSchemaMismatch", "response has 2 columns; the target declares 3 classes", "shape_mismatch",
         "endpoint_schema_mismatch"),
        ("EndpointAuthFailed", "endpoint 127.0.0.1:9 answered 401 to the credential", "load_failed",
         "endpoint_auth_failed"),
        ("EndpointUnreachable", "endpoint 127.0.0.1:9 unreachable after 3 attempts: ConnectError", "load_failed",
         "endpoint_unreachable"),
        ("EgressRefused", "egress_refused: 127.0.0.1 resolves to 10.0.0.5", "load_failed", "egress_refused"),
        ("EndpointNotAllowlisted", "host is not in target_allowlist", "load_failed", "endpoint_not_allowlisted"),
        ("UnsupportedArtifact", "shape_mismatch: declared input_shape (3, 8, 8) vs evaluation data (1, 8, 8)",
         "shape_mismatch", "unsupported_artifact"),
        ("UnsupportedArtifact", "dataset_incompatible: bundled split file is missing", "load_failed",
         "unsupported_artifact"),
    ],
    ids=["schema-mismatch", "auth-failed", "unreachable", "egress-refused", "not-allowlisted", "binding-shape",
         "binding-missing"],
)
def test_validate_task_maps_transport_failures_onto_typed_refusals(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
    error: str, message: str, reason: str, code: str,
) -> None:
    _stub_probe(monkeypatch, worker, error=_typed(error, message))
    row = _register(api).json()
    result = _run_validate(api, row["ingest_job_id"])
    assert result.result["status"] == "refused" and result.result["refusal_reason"] == reason

    job, run, target, artifacts = _read(api, row)
    assert job.status == "succeeded" and run.status == "succeeded", "a refusal is a completed job"
    detail = target.detail
    assert detail["status"] == "refused" and detail["refusal_reason"] == reason
    assert detail["sha256"] == row["sha256"], "the registration digest stays when nothing was validated"
    probe = detail["validation"]["probe"]
    assert probe["error_class"] == error and probe["host"] == "127.0.0.1:9"
    if code != "unsupported_artifact":
        assert probe["code"] == code
    assert message.split(":")[0] in probe["reason"]
    assert detail["validation"]["onnx_torch_argmax_agreement"] is None and detail["validation"]["gradients"] is False
    assert_secret_free(detail)

    actions = [e.action for e in api.writer.events]
    assert actions == ["model.register", "model.validate", "job.complete"]
    validate = api.writer.events[1]
    assert validate.success is False and validate.target == URL and validate.allowlist_check == "pass"
    assert validate.detail["status"] == "refused" and validate.detail["refusal_reason"] == reason
    assert validate.detail["error_class"] == error
    complete = api.writer.events[2]
    assert complete.success is True and complete.detail["validation_status"] == "refused"
    for event in api.writer.events:
        assert_secret_free(event.detail)
    assert len(artifacts) == 1
    # Campaign admission sees a refused model (409 model_load_refused), and the catalog says so.
    shown = api.client.get(f"/v1/models/{row['id']}").json()
    assert shown["status"] == "refused" and shown["refusal_reason"] == reason
    assert shown["endpoint"]["probe"]["error_class"] == error


def test_validate_task_without_worker_key_fails_the_job_and_never_probes(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.security_utils.secrets import AuthProfilesKeyError

    _stub_probe(monkeypatch, worker)
    row = _register(api).json()
    monkeypatch.delenv("REDSIM_AUTH_PROFILES_KEY", raising=False)
    with pytest.raises(AuthProfilesKeyError):
        _run_validate(api, row["ingest_job_id"])
    assert worker.probes == [], "no anonymous probe stands in for a credential the worker cannot decrypt"
    job, run, target, artifacts = _read(api, row)
    assert job.status == "failed" and run.status == "failed"
    assert job.error is not None and job.error.startswith("AuthProfilesKeyError:")
    assert target.detail["status"] == "validating", "an infrastructure failure is not a model refusal"
    assert artifacts == []
    actions = [e.action for e in api.writer.events]
    assert actions == ["model.register", "model.validate"]
    failed = api.writer.events[1]
    assert failed.success is False and failed.target == URL and failed.detail["status"] == "failed"
    assert failed.detail["error_class"] == "AuthProfilesKeyError"
    assert_secret_free(failed.detail)


def test_validate_task_sandbox_timeout_propagates_as_job_failure(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.ml.errors import SandboxTimeout

    _stub_probe(monkeypatch, worker, error=SandboxTimeout("ML sandbox timed out after 1200s"))
    row = _register(api).json()
    with pytest.raises(SandboxTimeout):
        _run_validate(api, row["ingest_job_id"])
    job, run, target, _artifacts = _read(api, row)
    assert job.status == "failed" and run.status == "failed"
    assert target.detail["status"] == "validating"
    assert [e.action for e in api.writer.events] == ["model.register"]


def test_validate_task_with_a_deleted_profile_refuses_without_probing(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_probe(monkeypatch, worker)
    row = _register(api).json()
    with api.Session() as sess:
        profile = sess.get(AuthProfile, BEARER)
        assert profile is not None
        sess.delete(profile)
        sess.commit()
    result = _run_validate(api, row["ingest_job_id"])
    assert result.result["status"] == "refused" and result.result["refusal_reason"] == "load_failed"
    assert worker.probes == []
    _job, _run, target, _artifacts = _read(api, row)
    assert target.detail["validation"]["probe"]["code"] == "auth_profile_not_found"
    assert api.writer.events[1].action == "model.validate" and api.writer.events[1].success is False


# ---------------------------------------------------------------------------
# Catalog seams closed with the B1 assemble: text / detection rows, the LLM domain row
# ---------------------------------------------------------------------------


def test_catalog_lists_text_and_detection_targets(api: SimpleNamespace) -> None:
    """``import redsim.ml.targets`` registers ``sms_tfidf_lr`` and ``assets_frcnn_mnv3`` (MODALITIES-14, -29), so
    ``GET /v1/models`` lists them as unregistered bundled rows with their honest status (no assets built in this
    harness: ``not_implemented`` with the build-assets reason); the LLM domain row names the route that is live
    (``endpoint_kind: llm`` + ``/probes``) instead of a Phase B placeholder."""
    from redsim.ml.targets import list_targets

    registry = {info.id: info for info in list_targets()}
    assert {"sms_tfidf_lr", "assets_frcnn_mnv3"} <= set(registry)
    assert registry["sms_tfidf_lr"].domain == "text" and registry["assets_frcnn_mnv3"].domain == "detection"

    listing = api.client.get("/v1/models", params={"project": PROJECT})
    assert listing.status_code == 200, listing.text
    rows = {row["id"]: row for row in listing.json()["models"]}
    for target_id, modality in (("sms_tfidf_lr", "text"), ("assets_frcnn_mnv3", "detection")):
        row = rows[target_id]
        assert row["source"] == "bundled" and row["registered"] is False and row["modality"] == modality
        assert row["status"] in {"available", "not_implemented"}
        assert row["status"] == "available" or row["reason"], "an unbuilt bundled model says why"
    assert "cifar10_smallcnn" not in rows, "fixture-only targets are never listed"
    llm = rows["endpoint_stub"]
    assert llm["status"] == "not_implemented" and llm["phase"] == "B" and llm["modality"] == "llm"
    assert "endpoint_kind: llm" in llm["reason"] and "/probes" in llm["reason"]
    assert "not implemented" not in llm["reason"].lower(), "LLM registration and probes are live (LLM-03)"


# ---------------------------------------------------------------------------
# Real child, real broker, tiny endpoint server (ml tier)
# ---------------------------------------------------------------------------


@pytest.mark.ml
def test_registration_to_available_through_the_real_child(
    api: SimpleNamespace, worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("torch")
    pytest.importorskip("art")
    import subprocess

    import numpy as np

    from redsim.ml import endpoint_broker, sandbox
    from redsim.ml.targets import endpoint_contract
    from tests.ml.fakes import TinyTarget
    from tests.ml.tiny_endpoint_server import TinyEndpointServer

    # The B1 broker speaks the B0 ``endpoint-v1`` request body: it encodes through
    # ``redsim.ml.targets.endpoint_contract.encode_request`` (``input_format`` from the registered modality,
    # the registered ``input_shape`` enforced) and validates the reply through ``validate_response_bytes``.
    body = endpoint_contract.encode_request([[[[0.0] * 8] * 8] * 3], input_format="float32_nchw",
                                            input_shape=[3, 8, 8])
    assert body["contract"] == endpoint_broker.CONTRACT_VERSION == "endpoint-v1" and body["input_format"] == "float32_nchw"
    assert endpoint_broker.encode_request is endpoint_contract.encode_request

    # A real evaluation split the child can bind, replacing the placeholder and its digest.
    sample = TinyTarget(seed=0).sample(24, 1)
    split = api.assets_root / "datasets" / "tiny" / "test.npz"
    np.savez(split, x=sample.x, y=sample.y, indices=np.arange(24))
    manifest = json.loads((api.assets_root / "MANIFEST.json").read_text())
    manifest["datasets"][DATASET]["splits"]["test"]["file"] = {
        "path": "datasets/tiny/test.npz", "sha256": hashlib.sha256(split.read_bytes()).hexdigest(),
        "size_bytes": split.stat().st_size,
    }
    (api.assets_root / "MANIFEST.json").write_text(json.dumps(manifest))

    # A short 0700 work-dir root (pytest's tmp_path exceeds ``sun_path`` on macOS) and the parent's secrets.
    work_root = Path(tempfile.mkdtemp(prefix="rs-"))
    os.chmod(work_root, 0o700)
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, str(work_root))
    for name in (sandbox.ENV_TIMEOUT_S, sandbox.ENV_CPU_SECONDS, sandbox.ENV_MEMORY_MB, sandbox.ENV_FILESIZE_MB,
                 sandbox.ENV_THREADS, sandbox.KEEP_WORK_DIR_ENV):
        monkeypatch.delenv(name, raising=False)
    for key, value in PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    real_popen = subprocess.Popen
    captured: dict[str, Any] = {}

    def spawn(argv: list[str], **kwargs: Any) -> Any:
        request_path = Path(argv[argv.index("--request") + 1])
        captured["request_text"] = request_path.read_text(encoding="utf-8")
        captured["env"] = dict(kwargs["env"])
        return real_popen(argv, **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", spawn)

    try:
        with TinyEndpointServer(token=TOKEN) as server:
            row = _register(api, url=server.url).json()
            assert row["status"] == "validating" and row["endpoint"]["host"] == server.url.split("//")[1].split("/")[0]
            result = _run_validate(api, row["ingest_job_id"])
            if result.result["status"] != "available":
                _job, _run, refused_target, _artifacts = _read(api, row)
                pytest.fail(f"probe refused: {refused_target.detail.get('validation', {}).get('probe')}")
            # The endpoint saw exactly the 8-row seeded probe, authenticated with the profile's credential.
            assert server.n_requests == 1 and server.requests[0]["rows"] == 8 and server.requests[0]["auth_ok"]
    finally:
        shutil.rmtree(work_root, ignore_errors=True)

    # The child never held the credential, a proxy setting or a parent secret; the request file names the
    # broker socket and the host, never the URL, the token or the profile secret.
    env = captured["env"]
    env_text = json.dumps(env)
    assert TOKEN not in env_text and "pk_test_never_forward" not in env_text and "aws-secret" not in env_text
    assert not any(key.upper().endswith("_PROXY") for key in env)
    assert "REDSIM_AUTH_PROFILES_KEY" not in env and "REDSIM_DB_URL" not in env
    request = json.loads(captured["request_text"])
    spec = request["target_endpoint"]
    assert TOKEN not in captured["request_text"] and "secret" not in spec and "url" not in spec
    assert spec["auth_profile_id"] == BEARER and spec["socket"].endswith(".sock") and spec["scheme"] == "http"

    _job, _run, target, artifacts = _read(api, row)
    detail = target.detail
    assert detail["status"] == "available" and detail["gradients"] is False and detail["format"] == "endpoint"
    assert detail["endpoint_broker"]["rows"] == 8 and detail["endpoint_broker"]["requests"] == 1
    assert len(detail["validation"]["probe"]["fingerprint_sha256"]) == 64
    assert detail["validation"]["probe"]["http_status"] == 200 and detail["validation"]["probe"]["tls_mode"] == "plaintext"
    assert detail["endpoint_fingerprint"]["sha256"] == detail["endpoint_broker"]["fingerprint_sha256"]
    assert_secret_free(detail)
    validate = next(e for e in api.writer.events if e.action == "model.validate")
    assert validate.success is True and validate.target == server.url and validate.allowlist_check == "pass"
    assert validate.detail["fingerprint_sha256"] == detail["validation"]["probe"]["fingerprint_sha256"]
    for event in api.writer.events:
        assert_secret_free(event.detail)
    assert len(artifacts) == 1 and TOKEN not in api.blobs.get(artifacts[0].location).decode()
    shown = api.client.get(f"/v1/models/{row['id']}").json()
    assert shown["status"] == "available" and shown["available_attacks"] == ["hopskipjump"]
    assert_secret_free(shown)
