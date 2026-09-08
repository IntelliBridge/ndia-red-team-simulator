"""POST /v1/findings/{id}/verify — enqueue a verification via admission service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.verify import create_verify_job

router = APIRouter(prefix="/findings", tags=["verify"])


@router.post("/{finding_id}/verify")
def verify(finding_id: str,
           user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """F6 admission entry — looks up the finding, runs RBAC, then
    delegates to ``services.verify.create_verify_job``.
    """
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="finding not found")
        project_id = finding.project_id
        run_id = finding.run_id

    check(user, Action.VERIFY_REPLAY, project_id)

    config = load_config()
    try:
        handle = create_verify_job(
            finding_id=finding_id, project_id=project_id, run_id=run_id,
            actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc
    return handle.to_response()
