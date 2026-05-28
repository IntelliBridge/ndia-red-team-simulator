"""POST /v1/findings/{id}/verify — enqueue a verification."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check

router = APIRouter(prefix="/findings", tags=["verify"])


@router.post("/{finding_id}/verify")
def verify(finding_id: str, user: CurrentUser = Depends(get_current_user)):
    from aegis.db.models import Finding, Job
    from aegis.db.session import get_session

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="finding not found")
        check(user, Action.VERIFY_REPLAY, finding.project_id)
        job_id = f"job-{uuid4().hex[:12]}"
        sess.add(Job(
            id=job_id, run_id=finding.run_id, project_id=finding.project_id,
            type="verify.replay", status="queued", created_by=user.sub,
            detail={"finding_id": finding_id},
        ))
        sess.flush()

    try:
        from aegis.workers.tasks.verify import verify_replay
        verify_replay.delay(job_id)
    except Exception:
        pass

    return {"job_id": job_id}
