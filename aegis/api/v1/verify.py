"""POST /v1/findings/{id}/verify — enqueue a verification via admission service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.verify import create_verify_job

router = APIRouter(prefix="/findings", tags=["verify"])


@router.post("/{finding_id}/verify")
def verify(finding_id: str,
           user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """F6 admission entry — looks up the finding, runs RBAC, then
    delegates to ``services.verify.create_verify_job``.
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
