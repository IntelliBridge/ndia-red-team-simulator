"""POST /v1/findings/{id}/fix — enqueue a remediation via admission service."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.fixes import create_fix_job

router = APIRouter(prefix="/findings", tags=["fix"])


@router.post("/{finding_id}/fix")
def fix(finding_id: str,
        body: dict = Body(default_factory=dict),
        user: CurrentUser = Depends(get_current_user)):
    """F6 admission entry — looks up the finding, runs RBAC, then
    delegates to ``services.fixes.create_fix_job``.
    """
    from aegis.db.models import Finding
    from aegis.db.session import get_session

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="finding not found")
        project_id = finding.project_id
        run_id = finding.run_id

    strategy = body.get("strategy", "patch")
    apply = bool(body.get("apply", False))
    check(user, Action.FIX_APPLY if apply else Action.FIX_GENERATE,
          project_id)

    config = load_config()
    try:
        handle = create_fix_job(
            finding_id=finding_id, strategy=strategy,
            apply=apply, open_pr=bool(body.get("open_pr", False)),
            repo=body.get("repo"),
            project_id=project_id, run_id=run_id,
            actor=f"user:{user.sub}",
            config=config,
            audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc))

    return {"job_id": handle.job_id, "run_id": handle.run_id}
