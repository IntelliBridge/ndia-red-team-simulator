"""Run lifecycle service.

Phase 4 v0.3.1 F6: admission boundary for ``run.cancel``. The API route
calls ``cancel_run`` which emits a chained audit event before mutating
the Run + Job DB rows and revoking the Celery task.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from aegis.config import AegisConfig
from aegis.safety import authorize


@dataclass
class CancelOutcome:
    run_id: str
    status: str
    jobs_cancelled: int


def cancel_run(
    *,
    run_id: str,
    actor: str,
    config: AegisConfig,
    audit_writer,
) -> CancelOutcome:
    """Admission boundary for ``run.cancel``.

    Order: audit row first, then mutate Run + Job rows and best-effort
    revoke the Celery tasks. If revoke fails the row is still marked
    cancelled — the worker will see the status flip and short-circuit
    on next heartbeat (handled in F11).
    """
    from sqlalchemy import select
    from aegis.db.models import Job, Run
    from aegis.db.session import get_session

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

    now = datetime.now(timezone.utc)
    with get_session() as sess:
        run = sess.get(Run, run_id)
        run.status = "cancelled"
        run.completed_at = now
        jobs = sess.execute(
            select(Job).where(Job.run_id == run_id,
                              Job.status.in_(["queued", "running"]))
        ).scalars().all()
        for j in jobs:
            j.status = "cancelled"
            j.completed_at = now
            if j.celery_task_id:
                try:
                    from aegis.workers.celery_app import app
                    app.control.revoke(j.celery_task_id, terminate=True)
                except Exception:
                    pass
        cancelled_count = len(jobs)

    return CancelOutcome(run_id=run_id, status="cancelled",
                         jobs_cancelled=cancelled_count)
