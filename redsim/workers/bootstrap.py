"""Per-task setup/teardown that updates the authoritative ``jobs`` row.

Each task function takes ``job_id``; this module wraps that into a context
manager that:

1. Loads the ``Job`` row. If it is not ``status='queued'`` (e.g. it was
   cancelled, already ran, or is a redelivery of a job that died mid-run),
   yields a context with ``skip=True`` and does nothing else — the task body
   must early-return on ``ctx.skip``. This is the cancellation / at-least-once
   redelivery guard (``task_acks_late=True``); without it a revoked or crashed
   task would re-execute and re-fire offensive work.
2. Otherwise sets ``status='running'``, ``started_at=now`` and, when a bound
   ``task`` is supplied, stamps ``celery_task_id`` from the live request so
   ``cancel_run``'s revoke can reach the running task (spec 10.7 item 2).
3. Yields a context bundle (session, run state, audit writer, blob store,
   actor) to the task body, with ``run_id`` / ``job_id`` / ``project_id``
   bound on the log context and a ``job.run`` OTel span open.
4. On success: marks ``status='succeeded'``, ``completed_at=now``. With
   ``emit_job_complete=True`` it first appends the ``job.complete`` audit row
   with the ``worker:<job type>`` service actor (spec 5.11 / 10.5); the ML
   task bodies currently write that row themselves, so the default is off.
5. On a *transient* error (DB/broker blip) when a bound ``task`` was supplied
   and retries remain: rolls the body back, resets the job to ``'queued'`` so
   the redelivery guard lets it run again, and re-raises via ``task.retry``.
6. On any other exception: marks ``status='failed'`` with the error captured
   (with ``emit_job_complete=True`` a ``job.complete`` row carries
   ``success=False`` and the error class).

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
``'running'`` rows past their TTL to ``'failed'`` and rolls the run up.

``commit_running`` (opt-in, default off): by default step 2 is only *flushed*,
so the body runs inside the same transaction and the Job/Run row locks taken
by that flush are held until the body finishes. A concurrent ``cancel_run``
UPDATE then blocks on those locks, and a body that polls ``Job.status`` from a
fresh session (the ML sandbox ``is_cancelled`` probe) keeps reading the
committed ``'queued'`` — a long sandbox run could never be cancelled. Tasks
that poll for cancellation pass ``commit_running=True`` to commit the
``'running'`` transition before the body starts; the body then continues in a
new transaction on the same session. Once ``'running'`` is durable the failure
and retry paths below see ``'running'`` (or ``'cancelled'``) after their
rollback, so ``running → failed`` / ``running → queued`` are the legal edges
and a row that went ``'cancelled'`` meanwhile is left untouched — on the
success path too: a terminal row is never overwritten with ``'succeeded'``.
"""

from __future__ import annotations

import logging
import os
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redsim.observability import bind_job_context, record_campaign_outcome, span

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.state import RunStateAPI
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

#: Celery task names whose terminal outcomes are counted on
#: ``redsim_ml_campaigns_total{status}``. Platform tasks (``scan_start``,
#: ``report_render``) are untouched, default-off for them.
ML_CAMPAIGN_TASK_NAMES: frozenset[str] = frozenset({"redsim.ml_campaign_run"})

#: Terminal job statuses (mirrors ``job_state.ALLOWED``'s sinks).
_TERMINAL = frozenset({"succeeded", "failed", "cancelled"})


def worker_actor(job_type: str | None) -> str:
    """The service actor a worker task writes on its own audit rows.

    ``worker:<task>`` in spec 10.5's vocabulary, where the task is the job
    type (``attack.run``, ``model.validate``, ...): e.g. ``worker:attack.run``.
    ``system:worker`` when the job type is unknown.
    """
    return f"worker:{job_type}" if job_type else "system:worker"


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
    # Celery task name (``task.name``) when a bound task was supplied.
    task_name: str | None = None
    # ``task.request.id`` stamped on the row at pickup, when available.
    celery_task_id: str | None = None
    # Service actor for rows the worker writes itself (``worker:<job type>``).
    worker_actor: str = "system:worker"
    # Non-secret fields a body may add to the ``job.complete`` audit detail
    # (spec 5.11: measurement count, envelope sha256, ...). Digests and
    # counts only — never payloads.
    completion_detail: dict[str, Any] = field(default_factory=dict)


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
    except Exception:  # SQLAlchemy is optional in minimal environments
        logger.debug("SQLAlchemy retryable exceptions unavailable", exc_info=True)
    return tuple(errs)


def _publish(run_id: str, job_id: str, status: str) -> None:
    """Best-effort lifecycle event to the run's WS channel (never raises)."""
    try:
        from redsim.workers.events import publish_job_event
        publish_job_event(run_id, job_id, status)
    except Exception:  # telemetry must never break the task
        logger.debug("event publish hook failed", exc_info=True)


def _task_name(task: Any) -> str | None:
    """``task.name`` when the bound task exposes a real string name."""
    name = getattr(task, "name", None) if task is not None else None
    return name if isinstance(name, str) and name else None


def _celery_task_id(task: Any) -> str | None:
    """``task.request.id`` when the bound task carries a real request id."""
    if task is None:
        return None
    request = getattr(task, "request", None)
    task_id = getattr(request, "id", None) if request is not None else None
    return task_id if isinstance(task_id, str) and task_id else None


def _completion_counts(sess: Any, run_id: str) -> dict[str, int]:
    """Row counts for the ``job.complete`` detail (findings, artifacts)."""
    try:
        from sqlalchemy import func, select

        from redsim.db.models import Artifact, Finding

        findings = sess.execute(
            select(func.count()).select_from(Finding).where(Finding.run_id == run_id)
        ).scalar()
        artifacts = sess.execute(
            select(func.count()).select_from(Artifact).where(Artifact.run_id == run_id)
        ).scalar()
        return {"findings": int(findings or 0), "artifacts": int(artifacts or 0)}
    except Exception:  # noqa: BLE001 - counts are informational
        logger.debug("job.complete counts unavailable", exc_info=True)
        return {}


def _emit_job_complete(
    ctx: TaskContext,
    *,
    job_type: str,
    status: str,
    allowlist: list[str],
    started_at: datetime | None,
    error: BaseException | None = None,
) -> None:
    """Append the ``job.complete`` audit row (spec 5.11 / 10.5).

    Success rows go through ``safety.authorize`` — the single emitter for ML
    events — with ``target=None`` (``allowlist_check="n/a"``). A failure row
    must carry ``success=False`` plus the error class, which ``authorize``
    cannot express for a target-less action, so it is appended through the
    same writer directly. Detail is digests, counts and ids only.
    """
    if ctx.audit_writer is None:
        return
    duration_s: float | None = None
    if started_at is not None:
        try:
            duration_s = round((_now() - started_at).total_seconds(), 3)
        except Exception:  # noqa: BLE001 - mocked clocks in tests
            duration_s = None
    detail: dict[str, Any] = {
        "job_id": ctx.job_id,
        "job_type": job_type,
        "status": status,
        "run_id": ctx.run_id,
        "duration_s": duration_s,
        **_completion_counts(ctx.session, ctx.run_id),
        **dict(ctx.completion_detail or {}),
    }
    if error is None:
        from redsim.safety import authorize

        authorize(
            "job.complete", None,
            allowlist=allowlist,
            actor=ctx.worker_actor, writer=ctx.audit_writer,
            run_id=ctx.run_id, project_id=ctx.project_id,
            detail=detail,
        )
        return
    detail["error_class"] = type(error).__name__
    detail["actor"] = ctx.worker_actor
    ctx.audit_writer.append(
        action="job.complete", actor=ctx.worker_actor, target=None,
        allowlist_check="n/a", override=False, success=False,
        detail=detail, run_id=ctx.run_id, project_id=ctx.project_id,
    )


@contextmanager
def task_context(
    job_id: str,
    task: Any = None,
    *,
    commit_running: bool = False,
    emit_job_complete: bool = False,
) -> Iterator[TaskContext]:
    """Wrap a job-scoped task body. See module docstring.

    ``task`` is the bound Celery task instance (``bind=True``); when supplied it
    enables transient-error retries and stamps ``Job.celery_task_id`` from the
    live request. Pass ``task=self`` from the task body.

    ``commit_running`` commits the ``queued → running`` transition (and the
    Run's ``running`` roll-up) *before* yielding, so other sessions can read
    and update the rows while the body runs. Off by default: only bodies that
    poll for a concurrent cancellation need it, and it means partial body
    writes are no longer implicitly discarded with the status transition.

    ``emit_job_complete`` makes ``task_context`` close the job's audit chain
    with the ``job.complete`` row (``worker:<job type>`` actor; ``success=False``
    plus the error class on failure). Off by default: the ML task bodies
    (``ml_campaign_run``, ``ml_model_validate``) append that row themselves
    today, and a chain must carry exactly one — a task opts in here *instead*
    of emitting its own, never both.
    """
    from redsim.audit.chain import PostgresAuditWriter
    from redsim.config import load_config
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session, init_engine
    from redsim.state import PostgresRunState
    from redsim.storage import open_blob_store
    from redsim.workers.job_state import ALLOWED, set_job_status

    db_url = os.environ.get("REDSIM_DB_URL")
    if db_url:
        init_engine(db_url)
    config = load_config()
    blob_store = open_blob_store()
    task_name = _task_name(task)
    counts_campaign = task_name in ML_CAMPAIGN_TASK_NAMES
    allowlist = list(getattr(config, "target_allowlist", None) or [])

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} not found")
        job_type = getattr(job, "type", "unknown")

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
                task_name=task_name, worker_actor=worker_actor(job_type),
            )
            return

        set_job_status(job, "running")
        started_at = _now()
        job.started_at = started_at
        # Spec 10.7 item 2: record the live Celery request id so cancel_run's
        # revoke reaches the running task. Admission stamps the AsyncResult id
        # at enqueue; a retry reuses it, so this is normally a no-op re-write.
        celery_task_id = _celery_task_id(task)
        if celery_task_id is not None:
            job.celery_task_id = celery_task_id
        run = sess.get(Run, job.run_id)
        if run is not None and run.status not in _TERMINAL:
            run.status = "running"
            table = dict(getattr(run, "stage_table", None) or {})
            jobs = dict(table.get("jobs") or {})
            jobs[job_id] = {"type": job_type, "status": "running"}
            table["jobs"] = jobs
            run.stage_table = table
        sess.flush()
        run_id = job.run_id
        project_id = job.project_id
        actor = job.created_by or "system:worker"
        if commit_running:
            # Make queued->running durable before the body starts. This
            # releases the Job/Run row locks the flush above took, so a
            # concurrent ``cancel_run`` can commit and a fresh-session poll in
            # the body observes it. The body continues in a new transaction on
            # this session; the success path re-reads and locks the rows before
            # its terminal write, so a cancellation is still honoured there.
            sess.commit()

        audit_writer = PostgresAuditWriter(session_factory=get_session)
        run_state = PostgresRunState(
            sess, run_id=run_id, project_id=project_id,
            output_dir=config.output_dir, blob_store=blob_store,
        )
        ctx = TaskContext(
            job_id=job_id, run_id=run_id, project_id=project_id,
            run_state=run_state, session=sess, audit_writer=audit_writer,
            blob_store=blob_store, actor=actor,
            task_name=task_name, celery_task_id=celery_task_id,
            worker_actor=worker_actor(job_type),
        )
        _publish(run_id, job_id, "running")
        with bind_job_context(run_id=run_id, job_id=job_id, project_id=project_id), \
                span("job.run", job_type=job_type, task=task_name):
            try:
                yield ctx
                # A cancellation may commit from another session while the body
                # is running. Flush body results, then refresh and lock only
                # Job/Run: expiring the whole identity map here would discard
                # pending Finding/artifact projection mutations from a
                # successful task.
                sess.flush()
                job = sess.get(
                    Job,
                    job_id,
                    populate_existing=True,
                    with_for_update=True,
                )
                run = sess.get(
                    Run,
                    run_id,
                    populate_existing=True,
                    with_for_update=True,
                )
                if (
                    job is None
                    or run is None
                    or "succeeded" not in ALLOWED.get(job.status, set())
                    or run.status == "cancelled"
                ):
                    # Spec 10.7 item 2: the row went terminal (cancelled) from
                    # another session while the body ran. Never overwrite it.
                    logger.info(
                        "task_context: suppressing stale success for job %s "
                        "(job=%r run=%r)",
                        job_id,
                        getattr(job, "status", None),
                        getattr(run, "status", None),
                    )
                    sess.rollback()
                    if counts_campaign:
                        record_campaign_outcome("cancelled")
                    return
                set_job_status(job, "succeeded")
                job.completed_at = _now()
                from redsim.services.runs import rollup_run_status
                table = dict((getattr(run, "stage_table", None) if run is not None else {}) or {})
                jobs = dict(table.get("jobs") or {})
                jobs[job_id] = {
                    **dict(jobs.get(job_id) or {}),
                    "type": job_type, "status": "succeeded",
                }
                table["jobs"] = jobs
                if run is not None:
                    run.stage_table = table
                rollup_run_status(sess, run_id)
                if emit_job_complete:
                    # Audit row before the status commit (chain order is the
                    # record of a completion racing a cancel; spec 10.7).
                    _emit_job_complete(
                        ctx, job_type=job_type, status="succeeded",
                        allowlist=allowlist, started_at=started_at,
                    )
                if counts_campaign:
                    record_campaign_outcome("succeeded")
            except Exception as exc:
                from celery.exceptions import Retry
                if isinstance(exc, Retry):
                    # task.retry() (below, or called by the body) already raised
                    # Retry; the row was reset to 'queued'. Nothing more to do.
                    raise

                # Transient blip + retries remain: requeue instead of failing,
                # so the redelivery guard lets the retry run (a 'failed' row
                # would be skipped). Reset on the body session after rolling
                # its partial writes back.
                if (task is not None and isinstance(exc, _transient_errors())
                        and task.request.retries < (task.max_retries or 0)):
                    sess.rollback()
                    # Read the live row, not the identity map: when the body
                    # made no writes on this session the rollback has nothing
                    # to expire and a plain get() would hand back the pre-body
                    # snapshot.
                    requeued = sess.get(
                        Job, job_id, populate_existing=True, with_for_update=True,
                    )
                    if (requeued is not None
                            and "queued" not in ALLOWED.get(requeued.status, set())):
                        # The row went terminal (cancelled) from another
                        # session while the body ran — reachable once
                        # 'running' has been committed. The redelivery guard
                        # would skip the retry anyway and ``cancelled →
                        # queued`` is illegal, so fall through to the terminal
                        # path, which leaves the row alone.
                        logger.info(
                            "task_context: job %s is %r after a transient error; "
                            "not retrying", job_id, requeued.status,
                        )
                    else:
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

                # Terminal failure. get_session() rolls back on exception,
                # which would discard a status write made here; roll back
                # ourselves first (releasing the job-row lock), then persist
                # 'failed' and commit so it survives the re-raise.
                sess.rollback()
                failed = sess.get(
                    Job, job_id, populate_existing=True, with_for_update=True,
                )
                if (failed is not None
                        and "failed" not in ALLOWED.get(failed.status, set())):
                    # 'failed' is not a legal transition from the row's
                    # current status (it was cancelled from another session
                    # while the body ran). The state machine forbids
                    # overwriting a terminal status and publishing 'failed'
                    # for a cancelled job would mislead consumers: surface the
                    # body's error and stop.
                    logger.info(
                        "task_context: job %s is %r; 'failed' is not a legal "
                        "transition from it, leaving the row untouched",
                        job_id, failed.status,
                    )
                    if counts_campaign:
                        record_campaign_outcome("cancelled")
                    raise
                if failed is not None:
                    set_job_status(failed, "failed")
                    failed.completed_at = _now()
                    failed.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
                    failed_run = sess.get(Run, run_id)
                    if failed_run is not None:
                        table = dict(getattr(failed_run, "stage_table", None) or {})
                        jobs = dict(table.get("jobs") or {})
                        jobs[job_id] = {
                            "type": getattr(failed, "type", job_type), "status": "failed",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                        table["jobs"] = jobs
                        table["error"] = f"{type(exc).__name__}: {exc}"
                        failed_run.stage_table = table
                    from redsim.services.runs import rollup_run_status
                    rollup_run_status(sess, run_id)
                    if emit_job_complete:
                        # Best-effort: the failure row must never mask the
                        # body's own error.
                        try:
                            _emit_job_complete(
                                ctx, job_type=job_type, status="failed",
                                allowlist=allowlist, started_at=started_at,
                                error=exc,
                            )
                        except Exception:  # noqa: BLE001
                            logger.warning(
                                "task_context: job.complete (failed) row for %s "
                                "could not be written", job_id, exc_info=True,
                            )
                    sess.commit()
                if counts_campaign:
                    record_campaign_outcome("failed")
                _publish(run_id, job_id, "failed")
                raise
    # Reached only when the body succeeded and ``get_session`` committed the
    # 'succeeded' status — publish after the commit so a consumer that reacts to
    # the event sees a durable row.
    _publish(run_id, job_id, "succeeded")


__all__ = [
    "ML_CAMPAIGN_TASK_NAMES",
    "TaskContext",
    "task_context",
    "worker_actor",
]
