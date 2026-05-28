"""POST /v1/runs/{id}/cancel — mark run cancelled (best-effort revoke)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("/{run_id}/cancel")
def cancel(run_id: str, user: CurrentUser = Depends(get_current_user)):
    from sqlalchemy import select
    from aegis.db.models import Job, Run
    from aegis.db.session import get_session

    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="run not found")
        check(user, Action.RUN_CANCEL, run.project_id)
        run.status = "cancelled"
        run.completed_at = datetime.now(timezone.utc)
        jobs = sess.execute(
            select(Job).where(Job.run_id == run_id,
                              Job.status.in_(["queued", "running"]))
        ).scalars().all()
        for j in jobs:
            j.status = "cancelled"
            j.completed_at = datetime.now(timezone.utc)
            try:
                from aegis.workers.celery_app import app
                if j.celery_task_id:
                    app.control.revoke(j.celery_task_id, terminate=True)
            except Exception:
                pass
    return {"run_id": run_id, "status": "cancelled",
            "jobs_cancelled": len(jobs)}
