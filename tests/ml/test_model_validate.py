"""G-ASSET9 / G-ASSET12: the ``model.validate`` worker task.

Drives the real Celery task eagerly (``.apply``) on a file-backed sqlite
harness, with the sandbox child swapped for a stub ``validate_model_sandboxed``
so no model is loaded. Covers the four outcomes the spec separates:

* a state_dict validates -> target ``available`` with ``gradients`` true and the
  spec 5.11 ``model.validate`` + ``job.complete`` audit rows (G-ASSET9);
* a pickle refusal -> target ``refused``, blob deleted, ``model.validate``
  ``success=False`` (G-ASSET9);
* the fetched blob's sha256 disagreeing with the registered manifest -> refused
  *before* the child is ever spawned (G-ASSET12);
* a sandbox wall-clock timeout -> job failed, target status left untouched
  (an infrastructure failure is not a model refusal).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from redsim.db.models import Artifact, Base, Job, Organization, Project, Run, Target
from tests.conftest import patch_jsonb_for_sqlite

TARGET_ID = "model-v1"
RUN_ID = "run-v1"
JOB_ID = "job-v1"
BLOB_LOCATION = "memory://project-v1/models/model-v1/upload.onnx"
MODEL_BYTES = b"opaque uploaded model bytes; never deserialized in this test"
GOOD_SHA = hashlib.sha256(MODEL_BYTES).hexdigest()


class _AuditRecorder:
    def __init__(self, **_kwargs: Any) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **event: Any) -> Any:
        self.events.append(event)
        return SimpleNamespace(**event)


class _BlobStore:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def get(self, _key: str) -> bytes:
        return MODEL_BYTES

    def put(self, key: str, _data: bytes, content_type: str = "") -> Any:
        return SimpleNamespace(location=f"memory://{key}", content_type=content_type)

    def delete(self, location: str) -> None:
        self.deleted.append(location)


def _seed(sessions: sessionmaker[Session], *, manifest_sha256: str) -> None:
    with sessions.begin() as session:
        session.add(Organization(id="org-v1", name="V1 org", slug="v1-org"))
        session.flush()
        session.add(Project(id="project-v1", org_id="org-v1", name="V1", slug="v1"))
        session.flush()
        manifest = {
            "name": "upload.onnx", "format": "onnx", "sha256": manifest_sha256,
            "dataset_id": "vehicles", "status": "validating",
        }
        session.add(Target(
            id=TARGET_ID, project_id="project-v1", kind="ml_model_artifact",
            value=BLOB_LOCATION, verified=True,
            detail={**manifest, "source": "upload", "manifest": manifest,
                    "validation": {"ingest_job_id": JOB_ID}},
        ))
        session.add(Run(
            id=RUN_ID, project_id="project-v1", target_id=TARGET_ID, mode="api",
            status="queued", scanner="ml.ingest", created_by="user:alice",
            stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        session.flush()
        session.add(Job(
            id=JOB_ID, run_id=RUN_ID, project_id="project-v1",
            type="model.validate", status="queued", created_by="user:alice",
            detail={"target_id": TARGET_ID},
        ))


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    patch_jsonb_for_sqlite()
    engine = create_engine(
        f"sqlite:///{tmp_path / 'validate.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def get_session() -> Iterator[Session]:
        sess = sessions()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    events: list[str] = []
    audit = _AuditRecorder()
    store = _BlobStore()
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda: store)
    monkeypatch.setattr(
        "redsim.config.load_config",
        lambda *a, **k: SimpleNamespace(output_dir=str(tmp_path / "out")),
    )
    monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", lambda **_k: audit)
    monkeypatch.setattr(
        "redsim.workers.events.publish_job_event",
        lambda _run, _job, status, **_extra: events.append(status),
    )
    return {"sessions": sessions, "events": events, "audit": audit, "store": store}


def _read(sessions: sessionmaker[Session]) -> tuple[Job, Run, Target, list[Artifact]]:
    with sessions() as session:
        job = session.get(Job, JOB_ID)
        run = session.get(Run, RUN_ID)
        target = session.get(Target, TARGET_ID)
        artifacts = list(session.execute(
            select(Artifact).where(Artifact.run_id == RUN_ID)
        ).scalars())
    assert job is not None and run is not None and target is not None
    return job, run, target, artifacts


def _actions(audit: _AuditRecorder) -> list[str]:
    return [event["action"] for event in audit.events]


def _row(audit: _AuditRecorder, action: str) -> dict[str, Any]:
    return next(event for event in audit.events if event["action"] == action)


def test_state_dict_available_gradients_true(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    _seed(sessions, manifest_sha256=GOOD_SHA)
    manifest = {
        "format": "torch_state_dict", "input_shape": [1, 3, 32, 32], "n_classes": 10,
        "gradients": True, "onnx_torch_argmax_agreement": None,
        "library_versions": {"torch": "2.3.0", "adversarial-robustness-toolbox": "1.17.0"},
    }
    monkeypatch.setattr(
        "redsim.ml.sandbox.validate_model_sandboxed", lambda *_a, **_k: dict(manifest),
    )

    result = ml_model_validate.apply(args=(JOB_ID,), throw=True)

    assert result.result["status"] == "available"
    assert result.result["refusal_reason"] is None
    job, run, target, artifacts = _read(sessions)
    assert job.status == "succeeded" and run.status == "succeeded"
    assert target.detail["status"] == "available"
    assert target.detail["refusal_reason"] is None
    validation = target.detail["validation"]
    assert validation["gradients"] is True
    assert validation["class_count"] == 10
    assert validation["detected_format"] == "torch_state_dict"
    assert validation["library_versions"]["torch"] == "2.3.0"
    # spec 5.11 detail on the model.validate row.
    row = _row(harness["audit"], "model.validate")
    assert row["success"] is True and row["allowlist_check"] == "n/a"
    assert row["detail"]["detected_format"] == "torch_state_dict"
    assert row["detail"]["gradients"] is True
    assert row["detail"]["status"] == "available"
    assert row["detail"]["library_versions"]["torch"] == "2.3.0"
    assert row["detail"]["refusal_reason"] is None
    # job.complete follows model.validate, and the blob is retained.
    complete = _row(harness["audit"], "job.complete")
    assert complete["success"] is True
    assert complete["detail"]["job_type"] == "model.validate"
    assert complete["detail"]["validation_status"] == "available"
    assert _actions(harness["audit"]) == ["model.validate", "job.complete"]
    assert harness["store"].deleted == []
    assert [a.kind for a in artifacts] == ["ml.validation_report"]
    assert harness["events"] == ["running", "succeeded"]


def test_pickle_refused_and_blob_deleted(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.ml.errors import UnsupportedArtifact
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    _seed(sessions, manifest_sha256=GOOD_SHA)

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise UnsupportedArtifact("pickle_refused: upload.onnx starts with a pickle PROTO opcode")

    monkeypatch.setattr("redsim.ml.sandbox.validate_model_sandboxed", refuse)

    result = ml_model_validate.apply(args=(JOB_ID,), throw=True)

    assert result.result["status"] == "refused"
    assert result.result["refusal_reason"] == "pickle_refused"
    job, run, target, artifacts = _read(sessions)
    # A refusal is a completed validation job, not a failed one.
    assert job.status == "succeeded" and run.status == "succeeded"
    assert target.detail["status"] == "refused"
    assert target.detail["refusal_reason"] == "pickle_refused"
    assert target.detail["validation"]["refusal_reason"] == "pickle_refused"
    # spec 6.6: a refused target's blob is deleted.
    assert harness["store"].deleted == [BLOB_LOCATION]
    row = _row(harness["audit"], "model.validate")
    assert row["success"] is False
    assert row["detail"]["status"] == "refused"
    assert row["detail"]["refusal_reason"] == "pickle_refused"
    complete = _row(harness["audit"], "job.complete")
    assert complete["detail"]["validation_status"] == "refused"
    assert _actions(harness["audit"]) == ["model.validate", "job.complete"]
    assert [a.kind for a in artifacts] == ["ml.validation_report"]
    assert harness["events"] == ["running", "succeeded"]


def test_digest_mismatch_refused(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    # The registered manifest digest disagrees with the bytes the blob store
    # returns, so the parent must refuse before spawning the child.
    _seed(sessions, manifest_sha256="11" * 32)

    def never(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("validate_model_sandboxed must not be spawned on a digest mismatch")

    monkeypatch.setattr("redsim.ml.sandbox.validate_model_sandboxed", never)

    result = ml_model_validate.apply(args=(JOB_ID,), throw=True)

    assert result.result["status"] == "refused"
    assert result.result["refusal_reason"] == "load_failed"
    job, run, target, artifacts = _read(sessions)
    assert job.status == "succeeded" and run.status == "succeeded"
    assert target.detail["status"] == "refused"
    assert target.detail["refusal_reason"] == "load_failed"
    assert "hash_mismatch" in target.detail["reason"]
    assert harness["store"].deleted == [BLOB_LOCATION]
    row = _row(harness["audit"], "model.validate")
    assert row["success"] is False and row["detail"]["status"] == "refused"
    assert _actions(harness["audit"]) == ["model.validate", "job.complete"]
    assert [a.kind for a in artifacts] == ["ml.validation_report"]


def test_timeout_leaves_status(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.ml.errors import SandboxTimeout
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    _seed(sessions, manifest_sha256=GOOD_SHA)

    def timeout(*_a: Any, **_k: Any) -> Any:
        raise SandboxTimeout("ML sandbox timed out after 1200s")

    monkeypatch.setattr("redsim.ml.sandbox.validate_model_sandboxed", timeout)

    # An infrastructure timeout is a job failure, not a model refusal: it
    # propagates and task_context records it.
    with pytest.raises(SandboxTimeout):
        ml_model_validate.apply(args=(JOB_ID,), throw=True)

    job, run, target, artifacts = _read(sessions)
    assert job.status == "failed"
    assert job.error is not None and "SandboxTimeout" in job.error
    assert run.status == "failed"
    # Neither available nor refused: the target keeps the status it had.
    assert target.detail["status"] == "validating"
    assert target.detail.get("refusal_reason") is None
    assert harness["store"].deleted == []       # the blob is not deleted
    assert artifacts == []                       # no validation_report
    assert harness["audit"].events == []         # no model.validate / job.complete
    assert harness["events"] == ["running", "failed"]
