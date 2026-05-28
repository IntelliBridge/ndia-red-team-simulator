"""POST /v1/scans — enqueue a scan."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
def start(
    body: dict = Body(default_factory=dict),
    user: CurrentUser = Depends(get_current_user),
):
    project_id = body.get("project_id") or "default"
    target = body.get("target")
    scanner = body.get("scanner", "strix")
    if not target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="target required")
    check(user, Action.SCAN_START, project_id)

    from datetime import datetime, timezone
    from aegis.db.models import Job, Run
    from aegis.db.session import get_session

    run_id = f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Run(
            id=run_id, project_id=project_id, mode="api", status="queued",
            scanner=scanner, created_by=user.sub, stage_table={},
        ))
        sess.flush()    # FK precedence: Run must exist before Job references it.
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="scan.start", status="queued",
            created_by=user.sub,
            detail={"target": target, "scanner": scanner,
                    "instruction": body.get("instruction")},
        ))
        sess.flush()

    # Enqueue via Celery if available (M5).
    try:
        from aegis.workers.tasks.scan import scan_start
        scan_start.delay(job_id)
    except Exception:
        # Worker not running / Celery not configured — leave the job queued.
        pass

    return {
        "run_id": run_id, "job_id": job_id,
        "status_url": f"/v1/runs/{run_id}",
    }
