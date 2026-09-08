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
5. On a *transient* error (DB/broker blip) when a bound ``task`` was supplied
   and retries remain: rolls the body back, resets the job to ``'queued'`` so
   the redelivery guard lets it run again, and re-raises via ``task.retry``.
6. On any other exception: marks ``status='failed'`` with the error captured.

Two subtleties worth knowing:

- ``get_session()`` rolls back on exception. A naive ``job.status='failed'``
  set on the body session immediately before re-raising would therefore be
  *discarded*, stranding the job ``'running'`` until the reaper. The failure
  path here rolls the body session back itself (releasing the job-row lock),
  then writes ``'failed'`` and commits on the same session so it survives.
- The redelivery guard means a retried task must not be left ``'failed'`` —
  it would be skipped on redelivery. Transient retries reset the row to
  ``'queued'`` (step 5) rather than failing it.

A periodic reaper (``redsim.workers.tasks.reaper``, on the Celery beat schedule)
is the backstop for jobs that crash so hard they never reach step 6 — it flips
``'running'`` rows past their TTL to ``'failed'``.
"""

from __future__ import annotations

import logging
import os
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.state import RunStateAPI
    from redsim.storage import BlobStore

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
    return datetime.now(UTC)


def _transient_errors() -> tuple[type[BaseException], ...]:
    """Exception types treated as transient (retryable) when a task body fails.

    sqlalchemy is imported lazily so importing this module doesn't drag in the
    DB stack (the unit CI job runs without it)."""
    errs: list[type[BaseException]] = [ConnectionError, TimeoutError]
    try:
        from sqlalchemy.exc import InterfaceError, OperationalError
        errs += [OperationalError, InterfaceError]
    except Exception:  # noqa: BLE001, S110 — sqlalchemy optional in minimal envs
        pass
    return tuple(errs)


def _publish(run_id: str, job_id: str, status: str) -> None:
    """Best-effort lifecycle event to the run's WS channel (never raises)."""
    try:
        from redsim.workers.events import publish_job_event
        publish_job_event(run_id, job_id, status)
    except Exception:
        logger.debug("event publish hook failed", exc_info=True)


@contextmanager
def task_context(job_id: str, task: Any = None) -> Iterator[TaskContext]:
    """Wrap a job-scoped task body. See module docstring.

    ``task`` is the bound Celery task instance (``bind=True``); when supplied it
    enables transient-error retries. Pass ``task=self`` from the task body.
    """
    from redsim.audit.chain import PostgresAuditWriter
    from redsim.config import load_config
    from redsim.db.models import Job
    from redsim.db.session import get_session, init_engine
    from redsim.state import PostgresRunState
    from redsim.storage import open_blob_store
    from redsim.workers.job_state import set_job_status

    db_url = os.environ.get("REDSIM_DB_URL")
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

        set_job_status(job, "running")
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
        _publish(run_id, job_id, "running")
        try:
            yield ctx
            set_job_status(job, "succeeded")
            job.completed_at = _now()
        except Exception as exc:
            from celery.exceptions import Retry
            if isinstance(exc, Retry):
                # task.retry() (below, or called by the body) already raised
                # Retry; the row was reset to 'queued'. Nothing more to do.
                raise

            # Transient blip + retries remain: requeue instead of failing, so
            # the redelivery guard lets the retry run (a 'failed' row would be
            # skipped). Reset on the body session after rolling its partial
            # writes back.
            if (task is not None and isinstance(exc, _transient_errors())
                    and task.request.retries < (task.max_retries or 0)):
                sess.rollback()
                requeued = sess.get(Job, job_id)
                if requeued is not None:
                    set_job_status(requeued, "queued")
                    requeued.started_at = None
                    sess.commit()
                logger.warning(
                    "task_context: transient error on job %s, retrying "
                    "(%d/%s): %s",
                    job_id, task.request.retries + 1, task.max_retries, exc,
                )
                raise task.retry(exc=exc)

            # Terminal failure. get_session() rolls back on exception, which
            # would discard a status write made here; roll back ourselves first
            # (releasing the job-row lock), then persist 'failed' and commit so
            # it survives the re-raise.
            sess.rollback()
            failed = sess.get(Job, job_id)
            if failed is not None:
                set_job_status(failed, "failed")
                failed.completed_at = _now()
                failed.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
                sess.commit()
            _publish(run_id, job_id, "failed")
            raise
    # Reached only when the body succeeded and ``get_session`` committed the
    # 'succeeded' status — publish after the commit so a consumer that reacts to
    # the event sees a durable row.
    _publish(run_id, job_id, "succeeded")
