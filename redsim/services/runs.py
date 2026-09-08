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
    from redsim.audit.chain import AuditWriter

logger = logging.getLogger(__name__)


@dataclass
class CancelOutcome:
    run_id: str
    status: str
    jobs_cancelled: int


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

    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise LookupError(f"run not found: {run_id}")
        project_id = run.project_id

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
