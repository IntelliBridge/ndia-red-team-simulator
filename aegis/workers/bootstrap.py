"""Per-task setup/teardown that updates the authoritative ``jobs`` row.

Each task function takes ``job_id``; this module wraps that into a context
manager that:

1. Loads the ``Job`` row, sets ``status='running'``, ``started_at=now``.
2. Yields a context bundle (session, run state, audit writer, blob store,
   actor) to the task body.
3. On success: marks ``status='succeeded'``, ``completed_at=now``.
4. On exception: marks ``status='failed'`` with the error captured.

If the worker dies mid-task, the reaper (a periodic Celery beat job)
marks long-running rows past a TTL as ``failed``.
"""

from __future__ import annotations

import os
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from aegis.audit.chain import AuditWriter
    from aegis.state import RunStateAPI
    from aegis.storage import BlobStore


@dataclass
class TaskContext:
    job_id: str
    run_id: str
    project_id: str
    run_state: RunStateAPI
    session: Session
    audit_writer: AuditWriter
    blob_store: BlobStore
    actor: str = "system:worker"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def task_context(job_id: str) -> Iterator[TaskContext]:
    from aegis.audit.chain import PostgresAuditWriter
    from aegis.config import load_config
    from aegis.db.models import Job
    from aegis.db.session import get_session, init_engine
    from aegis.state import PostgresRunState
    from aegis.storage import open_blob_store

    db_url = os.environ.get("AEGIS_DB_URL")
    if db_url:
        init_engine(db_url)
    config = load_config()
    blob_store = open_blob_store()

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} not found")
        job.status = "running"
        job.started_at = _now()
        sess.flush()
        run_id = job.run_id
        project_id = job.project_id

        audit_writer = PostgresAuditWriter(session_factory=get_session)
        run_state = PostgresRunState(
            sess, run_id=run_id, project_id=project_id,
            output_dir=config.output_dir, blob_store=blob_store,
        )
        ctx = TaskContext(
            job_id=job_id, run_id=run_id, project_id=project_id,
            run_state=run_state, session=sess, audit_writer=audit_writer,
            blob_store=blob_store, actor=job.created_by or "system:worker",
        )
        try:
            yield ctx
            job.status = "succeeded"
            job.completed_at = _now()
        except Exception as exc:
            job.status = "failed"
            job.completed_at = _now()
            job.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            raise
