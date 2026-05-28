"""POST /v1/findings/{id}/fix — enqueue a remediation."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check

router = APIRouter(prefix="/findings", tags=["fix"])


@router.post("/{finding_id}/fix")
def fix(finding_id: str,
        body: dict = Body(default_factory=dict),
        user: CurrentUser = Depends(get_current_user)):
    from aegis.db.models import Finding, Job
    from aegis.db.session import get_session

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="finding not found")
        project_id = finding.project_id
        strategy = body.get("strategy", "patch")
        apply = bool(body.get("apply", False))
        check(user, Action.FIX_APPLY if apply else Action.FIX_GENERATE,
              project_id)

        job_id = f"job-{uuid4().hex[:12]}"
        sess.add(Job(
            id=job_id, run_id=finding.run_id, project_id=project_id,
            type="fix.generate", status="queued",
            created_by=user.sub,
            detail={"finding_id": finding_id, "strategy": strategy,
                    "apply": apply, "open_pr": bool(body.get("open_pr", False)),
                    "repo": body.get("repo")},
        ))
        sess.flush()

    try:
        from aegis.workers.tasks.fix import fix_generate
        fix_generate.delay(job_id)
    except Exception:
        pass

    return {"job_id": job_id, "run_id": finding.run_id}
