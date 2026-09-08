"""POST /v1/runs/{id}/cancel — admission service emits audit + cancels."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.runs import cancel_run

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("/{run_id}/cancel")
def cancel(run_id: str,
           user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """F6 admission entry — RBAC then delegate to ``services.runs.cancel_run``."""
    from redsim.db.models import Run
    from redsim.db.session import get_session

    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="run not found")
        project_id = run.project_id

    check(user, Action.RUN_CANCEL, project_id)

    config = load_config()
    try:
        outcome = cancel_run(
            run_id=run_id, actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="run not found") from exc
    return {"run_id": outcome.run_id, "status": outcome.status,
            "jobs_cancelled": outcome.jobs_cancelled}
