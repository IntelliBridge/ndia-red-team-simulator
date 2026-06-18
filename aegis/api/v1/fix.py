"""POST /v1/findings/{id}/fix — enqueue a remediation via admission service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.fixes import create_fix_job

if TYPE_CHECKING:
    from aegis.services.fixes import Strategy

router = APIRouter(prefix="/findings", tags=["fix"])


class FixBody(BaseModel):
    strategy: str = "patch"
    apply: bool = False
    open_pr: bool = False
    repo: str | None = None
    override_authorized: bool = False


@router.post("/{finding_id}/fix")
def fix(finding_id: str,
        body: FixBody = FixBody(),
        user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
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

    strategy = body.strategy
    apply = bool(body.apply)
    check(user,
          Action.FIX_APPLY if (apply or bool(body.open_pr)) else Action.FIX_GENERATE,
          project_id)

    config = load_config()
    try:
        handle = create_fix_job(
            # ``strategy`` is a free-form ``str`` here (any value accepted,
            # exactly as the previous raw-dict body did); the service maps
            # unknown strategies to an error outcome at runtime rather than
            # rejecting them. Cast at the boundary so the type-checker is
            # satisfied without narrowing/validating the runtime value.
            finding_id=finding_id, strategy=cast("Strategy", strategy),
            apply=apply, open_pr=bool(body.open_pr),
            repo=body.repo,
            override_authorized=bool(body.override_authorized),
            project_id=project_id, run_id=run_id,
            actor=f"user:{user.sub}",
            config=config,
            audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc

    return handle.to_response()
