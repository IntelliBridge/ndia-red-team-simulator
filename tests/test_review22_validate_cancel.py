"""Review #22 F5: a long ``model.validate`` sandbox run must observe a
cancellation written by a second session while it is running.

``task_context`` used to only *flush* the queued->running transition and hold
the Job/Run row locks for the whole body, so a concurrent ``cancel_run`` UPDATE
blocked on those locks and the worker's fresh-session ``is_cancelled`` probe
kept reading the committed ``'queued'``. The validate task now asks
``task_context`` for ``commit_running=True``, which commits the transition
before the sandbox child starts.

Runs on a file-backed sqlite harness (one connection per session, as in
tests/test_ml_orchestration_p4.py) and drives the real Celery task eagerly via
``.apply()``. The sandbox child is swapped for a sleeping interpreter so the
real ``_run_child`` poll loop, kill path and ``task_context`` bookkeeping run
without loading a model.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from redsim.db.models import Artifact, Base, Job, Organization, Project, Run, Target
from redsim.workers.job_state import set_job_status
from tests.conftest import patch_jsonb_for_sqlite

TARGET_ID = "model-f5"
RUN_ID = "run-f5"
JOB_ID = "job-f5"
CANCEL_MARKER = "cancelled while sandbox child"


class _AuditRecorder:
    def __init__(self, **_kwargs: Any) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **event: Any) -> Any:
        self.events.append(event)
        return SimpleNamespace(**event)


class _BlobStore:
    def get(self, _key: str) -> bytes:
        return b"opaque uploaded bytes; never deserialized in this test"

    def put(self, key: str, _data: bytes, content_type: str = "") -> Any:
        return SimpleNamespace(location=f"memory://{key}", content_type=content_type)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    patch_jsonb_for_sqlite()
    # File-backed so a second thread gets its own connection and real sqlite
    # locking applies; check_same_thread off because the pool may hand a
    # connection created on one thread to another (each session still owns
    # exactly one connection at a time).
    engine = create_engine(
        f"sqlite:///{tmp_path / 'f5.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    with sessions.begin() as session:
        session.add(Organization(id="org-f5", name="F5 org", slug="f5-org"))
        session.flush()
        session.add(Project(id="project-f5", org_id="org-f5", name="F5", slug="f5"))
        session.flush()
        manifest = {"name": "upload.onnx", "format": "onnx", "status": "validating"}
        session.add(Target(
            id=TARGET_ID, project_id="project-f5", kind="ml_model_artifact",
            value="uploads/upload.onnx", verified=True,
            detail={**manifest, "manifest": manifest,
                    "validation": {"ingest_job_id": JOB_ID}},
        ))
        session.add(Run(
            id=RUN_ID, project_id="project-f5", target_id=TARGET_ID, mode="api",
            status="queued", scanner="ml.ingest", created_by="user:alice",
            stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        session.flush()
        session.add(Job(
            id=JOB_ID, run_id=RUN_ID, project_id="project-f5",
            type="model.validate", status="queued", created_by="user:alice",
            detail={"target_id": TARGET_ID},
        ))

    @contextmanager
    def get_session() -> Iterator[Session]:
        # Same shape as redsim.db.session.get_session: explicit commit on clean
        # exit, so a mid-body commit followed by more work still lands.
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
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setenv("REDSIM_ML_SANDBOX_TIMEOUT_S", "20")  # bound a failing run
    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda: _BlobStore())
    monkeypatch.setattr(
        "redsim.config.load_config",
        lambda *a, **k: SimpleNamespace(output_dir=str(tmp_path / "out")),
    )
    monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", lambda **_k: audit)
    monkeypatch.setattr(
        "redsim.workers.events.publish_job_event",
        lambda _run, _job, status, **_extra: events.append(status),
    )
    return {"sessions": sessions, "events": events, "audit": audit}


def _cancel_from_second_session(sessions: sessionmaker[Session]) -> None:
    """What ``services.runs.cancel_run`` writes, minus authz and Celery revoke."""
    now = datetime.now(UTC)
    with sessions.begin() as session:
        run = session.get(Run, RUN_ID)
        assert run is not None
        run.status = "cancelled"
        run.completed_at = now
        for job in session.execute(
            select(Job).where(Job.run_id == RUN_ID, Job.status.in_(["queued", "running"]))
        ).scalars():
            set_job_status(job, "cancelled")
            job.completed_at = now


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


def _sleeping_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen

    def sleeping_child(_argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        return real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", sleeping_child)


def test_second_session_cancellation_is_observed_during_validation(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.ml import sandbox
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    _sleeping_popen(monkeypatch)

    # Wrap the real sandbox entry point only to record what the is_cancelled
    # probe returns; the real _run_child poll loop still drives the child.
    probe_results: list[bool] = []
    real_validate = sandbox.validate_model_sandboxed

    def recording_validate(*args: Any, is_cancelled: Callable[[], bool], **kwargs: Any) -> Any:
        def probe() -> bool:
            value = is_cancelled()
            probe_results.append(value)
            return value
        return real_validate(*args, is_cancelled=probe, **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.validate_model_sandboxed", recording_validate)

    # A second session (another thread, its own connection) waits until the
    # worker's 'running' transition is *visible* to it, then cancels — exactly
    # the write that used to block behind the worker's open transaction.
    seen: dict[str, Any] = {}

    def canceller() -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with sessions() as session:
                job = session.get(Job, JOB_ID)
                status = job.status if job is not None else None
            if status == "running":
                seen["status_before_cancel"] = status
                _cancel_from_second_session(sessions)
                seen["cancelled_at"] = time.monotonic()
                return
            time.sleep(0.05)
        seen["status_before_cancel"] = status

    thread = threading.Thread(target=canceller, daemon=True)
    started = time.monotonic()
    thread.start()
    result = ml_model_validate.apply(args=(JOB_ID,), throw=True)
    thread.join(timeout=15)
    elapsed = time.monotonic() - started

    assert seen.get("status_before_cancel") == "running", (
        "second session never saw the durable 'running' row; the worker still "
        "holds its queued->running transition open"
    )
    assert probe_results and probe_results[-1] is True, probe_results
    assert result.result["status"] == "cancelled"
    assert result.result["refusal_reason"] is None
    assert elapsed < 15, "validation did not stop promptly after the cancel"

    job, run, target, artifacts = _read(sessions)
    assert job.status == "cancelled"
    assert job.started_at is not None
    assert run.status == "cancelled"
    assert target.detail["status"] == "validating"  # neither available nor refused
    assert artifacts == []  # no validation_report for a cancelled run
    assert harness["audit"].events == []
    assert harness["events"] == ["running"]  # no stale 'succeeded'


def test_successful_validation_still_succeeds_with_durable_running(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]
    manifest = {"format": "onnx", "input_shape": [1, 3, 32, 32], "n_classes": 10,
                "gradients": True}
    monkeypatch.setattr(
        "redsim.ml.sandbox.validate_model_sandboxed",
        lambda *_a, **_k: dict(manifest),
    )

    result = ml_model_validate.apply(args=(JOB_ID,), throw=True)

    assert result.result["status"] == "available"
    job, run, target, artifacts = _read(sessions)
    assert job.status == "succeeded"
    assert job.completed_at is not None
    assert run.status == "succeeded"
    assert target.detail["status"] == "available"
    assert target.detail["validation"]["class_count"] == 10
    assert [a.kind for a in artifacts] and len(artifacts) == 1
    assert [e["action"] for e in harness["audit"].events] == ["model.validate", "job.complete"]
    assert harness["events"] == ["running", "succeeded"]


def test_body_failure_after_durable_running_ends_failed(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.workers.tasks.ml_model import ml_model_validate

    sessions = harness["sessions"]

    def malformed(*_a: Any, **_k: Any) -> Any:
        # The real sandbox raises TypeError for a malformed manifest; the task
        # only maps UnsupportedArtifact/RuntimeError to refusals, so this is a
        # genuine body failure that task_context must record.
        raise TypeError("ML sandbox validation did not return a manifest")

    monkeypatch.setattr("redsim.ml.sandbox.validate_model_sandboxed", malformed)

    with pytest.raises(TypeError, match="did not return a manifest"):
        ml_model_validate.apply(args=(JOB_ID,), throw=True)

    job, run, target, artifacts = _read(sessions)
    assert job.status == "failed"  # running -> failed on the durable row
    assert job.completed_at is not None
    assert job.error is not None and "TypeError" in job.error
    assert run.status == "failed"
    assert run.stage_table["jobs"][JOB_ID]["status"] == "failed"
    assert target.detail["status"] == "validating"
    assert artifacts == []
    assert harness["events"] == ["running", "failed"]


# --- task_context(commit_running=True) driven directly on the harness --------


def _bound_task(retries: int, max_retries: int = 2) -> MagicMock:
    from celery.exceptions import Retry

    task = MagicMock()
    task.request.retries = retries
    task.max_retries = max_retries
    task.retry.side_effect = Retry()
    return task


def _operational_error() -> Exception:
    from sqlalchemy.exc import OperationalError

    return OperationalError("SELECT 1", {}, Exception("db gone"))


@pytest.mark.parametrize("commit_running", [False, True])
def test_running_is_visible_to_other_sessions_only_when_committed(
    harness: dict[str, Any], commit_running: bool,
) -> None:
    from redsim.workers.bootstrap import task_context

    sessions = harness["sessions"]
    with task_context(JOB_ID, commit_running=commit_running) as ctx:
        assert not ctx.skip
        with sessions() as other:
            job = other.get(Job, JOB_ID)
            run = other.get(Run, RUN_ID)
            assert job is not None and run is not None
            observed = (job.status, run.status)
    # Default off: other sessions still see the pre-body 'queued' rows, exactly
    # as before this change. Opt-in: the transition is durable during the body.
    assert observed == (("running", "running") if commit_running else ("queued", "queued"))
    job, run, _target, _artifacts = _read(sessions)
    assert (job.status, run.status) == ("succeeded", "succeeded")


def test_transient_error_requeues_durable_running_row(harness: dict[str, Any]) -> None:
    from celery.exceptions import Retry

    from redsim.workers.bootstrap import task_context

    sessions = harness["sessions"]
    task = _bound_task(retries=0)
    with pytest.raises(Retry), task_context(JOB_ID, task=task, commit_running=True):
        with sessions() as other:
            assert other.get(Job, JOB_ID).status == "running"  # durable
        raise _operational_error()

    task.retry.assert_called_once()
    job, run, _target, _artifacts = _read(sessions)
    assert job.status == "queued"  # running -> queued: the retry edge
    assert job.started_at is None
    assert "failed" not in harness["events"]


@pytest.mark.parametrize("transient", [True, False])
def test_cancelled_while_running_is_neither_requeued_nor_failed(
    harness: dict[str, Any], transient: bool,
) -> None:
    from sqlalchemy.exc import OperationalError

    from redsim.workers.bootstrap import task_context

    sessions = harness["sessions"]
    task = _bound_task(retries=0)
    expected = OperationalError if transient else ValueError
    with pytest.raises(expected), task_context(JOB_ID, task=task, commit_running=True):
        _cancel_from_second_session(sessions)  # commits: running -> cancelled
        raise _operational_error() if transient else ValueError("boom")

    # No retry (cancelled -> queued is illegal and the redelivery guard would
    # skip it), no 'failed' overwrite of the terminal row, no 'failed' event.
    task.retry.assert_not_called()
    job, run, _target, _artifacts = _read(sessions)
    assert job.status == "cancelled"
    assert run.status == "cancelled"
    assert job.error is None
    assert harness["events"] == ["running"]
