"""Run lifecycle service.

Phase 4 v0.3.1 F6: admission boundary for ``run.cancel``. The API route
calls ``cancel_run`` which emits a chained audit event before mutating
the Run + Job DB rows and revoking the Celery task.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redsim.config import RedsimConfig
from redsim.safety import authorize

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter

logger = logging.getLogger(__name__)


@dataclass
class CancelOutcome:
    run_id: str
    status: str
    jobs_cancelled: int


class TerminalRunError(RuntimeError):
    """Cancellation was requested after the run reached a terminal state."""

    code = "run_terminal"

    def __init__(self, run_id: str, run_status: str) -> None:
        self.run_id = run_id
        self.run_status = run_status
        super().__init__(
            f"run {run_id} is already terminal with status {run_status!r}"
        )


#: ``runs.status`` values no roll-up may move away from (spec 6.2: "a
#: terminal run never becomes running again"; ``cancelled`` is written only by
#: :func:`cancel_run`).
TERMINAL_RUN_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "cancelled"})


def rollup_run_status(session: Session, run_id: str) -> str:
    """Derive ``Run.status`` from its jobs (spec 6.2) without reopening a terminal run.

    Rules, evaluated over every ``Job`` of the run in the caller's session:

    * all jobs ``queued`` → ``queued``;
    * any job ``running``, or a mix of ``queued`` and terminal → ``running``;
    * all jobs terminal, at least one ``succeeded``, none ``failed`` → ``succeeded``;
    * all jobs terminal and at least one ``failed`` → ``failed``;
    * all jobs ``cancelled`` → ``cancelled`` (the run was normally cancelled
      by :func:`cancel_run` first, which this function then leaves alone).

    ``completed_at`` is set when the status becomes terminal and cleared
    otherwise. A run already in :data:`TERMINAL_RUN_STATUSES` is returned
    unchanged — follow-on jobs attach to the run for ``run_id``/RLS purposes
    but never reopen it. A run with no jobs keeps its status.
    """
    from sqlalchemy import select

    from redsim.db.models import Job, Run

    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run not found: {run_id}")
    if run.status in TERMINAL_RUN_STATUSES:
        return run.status
    statuses = list(session.execute(
        select(Job.status).where(Job.run_id == run_id)
    ).scalars())
    if not statuses:
        return run.status
    if all(value in TERMINAL_RUN_STATUSES for value in statuses):
        new_status = ("failed" if "failed" in statuses else
                      "succeeded" if "succeeded" in statuses else "cancelled")
        run.status = new_status
        run.completed_at = datetime.now(UTC)
    elif all(value == "queued" for value in statuses):
        run.status = "queued"
        run.completed_at = None
    else:
        run.status = "running"
        run.completed_at = None
    return run.status


def cancel_run(
    *,
    run_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
) -> CancelOutcome:
    """Admission boundary for ``run.cancel``.

    Order: audit row first, then mutate Run + Job rows and best-effort
    revoke the Celery tasks. If revoke fails the row is still marked
    cancelled — ``task_context`` skips any job whose status is no longer
    ``queued``, so a redelivered/late-starting task short-circuits instead
    of re-running.
    """
    from sqlalchemy import select

    from redsim.db.models import Job, Run
    from redsim.db.session import get_session
    from redsim.workers.job_state import set_job_status

    def _refuse_terminal(run_status: str, project: str) -> TerminalRunError:
        # A refused admission still leaves a chained ``success=False`` row
        # (``authorize`` cannot express a refusal for a target-less action).
        audit_writer.append(
            action="run.cancel", actor=actor, target=None,
            allowlist_check="n/a", override=False, success=False,
            detail={"actor": actor, "run_id": run_id,
                    "reason": TerminalRunError.code, "run_status": run_status},
            run_id=run_id, project_id=project,
        )
        return TerminalRunError(run_id, run_status)

    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise LookupError(f"run not found: {run_id}")
        project_id = run.project_id
        if run.status in TERMINAL_RUN_STATUSES:
            raise _refuse_terminal(run.status, project_id)

    authorize(
        "run.cancel", None,
        allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer,
        project_id=project_id, run_id=run_id,
        detail={"actor": actor, "run_id": run_id},
    )

    now = datetime.now(UTC)
    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise LookupError(f"run not found: {run_id}")
        # Recheck after authorization: a worker may have completed meanwhile.
        if run.status in TERMINAL_RUN_STATUSES:
            raise _refuse_terminal(run.status, project_id)
        run.status = "cancelled"
        run.completed_at = now
        jobs = sess.execute(
            select(Job).where(Job.run_id == run_id,
                              Job.status.in_(["queued", "running"]))
        ).scalars().all()
        for j in jobs:
            # Both selected states (queued, running) legally transition to
            # cancelled; the guard keeps this write single-sourced.
            set_job_status(j, "cancelled")
            j.completed_at = now
            if j.celery_task_id:
                try:
                    from redsim.workers.celery_app import app
                    app.control.revoke(j.celery_task_id, terminate=True)
                except Exception:
                    # Broker unreachable: status flip stands; the worker
                    # short-circuits on its next heartbeat (F11).
                    logger.warning("celery revoke failed for task %s",
                                   j.celery_task_id, exc_info=True)
        cancelled_count = len(jobs)

    return CancelOutcome(run_id=run_id, status="cancelled",
                         jobs_cancelled=cancelled_count)


__all__ = [
    "TERMINAL_RUN_STATUSES", "CancelOutcome", "TerminalRunError", "cancel_run",
    "rollup_run_status",
]
