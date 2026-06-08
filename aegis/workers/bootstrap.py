"""Per-task setup/teardown that updates the authoritative ``jobs`` row.

Each task function takes ``job_id``; this module wraps that into a context
manager that:

1. Loads the ``Job`` row. If it is not ``status='queued'`` (e.g. it was
   cancelled, already ran, or is a redelivery of a job that died mid-run),
   yields a context with ``skip=True`` and does nothing else — the task body
   must early-return on ``ctx.skip``. This is the cancellation / at-least-once
   redelivery guard (``task_acks_late=True``); without it a revoked or crashed
   task would re-execute and re-fire offensive work.
2. Otherwise sets ``status='running'``, ``started_at=now``.
3. Yields a context bundle (session, run state, audit writer, blob store,
   actor) to the task body.
4. On success: marks ``status='succeeded'``, ``completed_at=now``.
5. On exception: marks ``status='failed'`` with the error captured.

NOTE: a job that crashes mid-run is left ``running`` and is NOT retried (the
guard skips its redelivery, fail-closed). A periodic reaper to mark stale
``running`` rows ``failed`` past a TTL is not yet implemented.
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)


@dataclass
class TaskContext:
    job_id: str
    run_id: str
    project_id: str
    session: Session
    blob_store: BlobStore
    run_state: RunStateAPI | None = None
    audit_writer: AuditWriter | None = None
    actor: str = "system:worker"
    # Set when the job was not in a runnable ('queued') state — the task body
    # must early-return without doing any work. See ``task_context``.
    skip: bool = False


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

        # Redelivery / cancellation guard. ``task_acks_late=True`` means a task
        # whose worker was revoked (``cancel_run``) or died mid-run can be
        # redelivered by the broker. Only a freshly-``queued`` job is runnable;
        # re-running a ``cancelled``/terminal/already-``running`` job would
        # re-fire offensive work and clobber its status. Skip without touching
        # the row (the task body checks ``ctx.skip`` and returns early).
        if job.status != "queued":
            logger.info(
                "task_context: job %s is %r (not 'queued'); skipping execution",
                job_id, job.status,
            )
            yield TaskContext(
                job_id=job_id, run_id=job.run_id, project_id=job.project_id,
                session=sess, blob_store=blob_store,
                actor=job.created_by or "system:worker", skip=True,
            )
            return

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
