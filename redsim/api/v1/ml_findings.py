"""ML finding action admissions."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import ApiError
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.ml_findings import (
    MLFindingAdmissionError,
    create_finding_action_job,
    review_finding,
)

router = APIRouter(prefix="/findings", tags=["ml-findings"])


class ExplainBody(BaseModel):
    explain_k: int | None = Field(default=None, ge=0, le=32)
    seed: int | None = None


class HardenBody(BaseModel):
    llm_narrative: bool = False


class ReviewBody(BaseModel):
    status: Literal["false_positive"]
    expected_status: str
    reason: str = Field(min_length=1)


def _finding_project(finding_id: str) -> str:
    from redsim.db.models import Finding
    from redsim.db.session import get_session
    with get_session() as session:
        row = session.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return row.project_id


def _error(exc: MLFindingAdmissionError) -> HTTPException:
    detail: dict[str, Any] = {"code": exc.code, "message": str(exc)}
    if exc.phase:
        detail["phase"] = exc.phase
    return HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED
                         if exc.code == "not_implemented" else status.HTTP_409_CONFLICT,
                         detail=detail)


@router.post("/{finding_id}/explain", status_code=status.HTTP_202_ACCEPTED)
def explain(finding_id: str, body: ExplainBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = _finding_project(finding_id)
    check(user, Action.EXPLAIN_RUN, project_id)
    config = load_config()
    try:
        return create_finding_action_job(finding_id=finding_id, action="explain",
                                         body=body.model_dump(exclude_none=True),
                                         actor=f"user:{user.sub}", config=config,
                                         audit_writer=resolve_writer(config)).to_response()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except (MLFindingAdmissionError, AuthorizationError) as exc:
        raise _error(exc) if isinstance(exc, MLFindingAdmissionError) else HTTPException(403, detail=str(exc))


@router.post("/{finding_id}/harden", status_code=status.HTTP_202_ACCEPTED)
def harden(finding_id: str, body: HardenBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = _finding_project(finding_id)
    check(user, Action.HARDEN_RECOMMEND, project_id)
    config = load_config()
    try:
        return create_finding_action_job(finding_id=finding_id, action="harden",
                                         body=body.model_dump(), actor=f"user:{user.sub}",
                                         config=config, audit_writer=resolve_writer(config)).to_response()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except (MLFindingAdmissionError, AuthorizationError) as exc:
        raise _error(exc) if isinstance(exc, MLFindingAdmissionError) else HTTPException(403, detail=str(exc))


@router.patch("/{finding_id}/status")
def dismiss(finding_id: str, body: ReviewBody,
            user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Reviewer dismissal (spec 6.4, 7.7, 17.1).

    ``FINDING_REVIEW`` (approver) gate, then the independence rule in the
    service: the campaign creator and system principals are refused with 403,
    a stale ``expected_status`` or a source status outside ``open | failed``
    with ``409 run_terminal``. The ``finding.review`` audit row is written
    before the status changes; refusals write a ``success=False`` row.
    """
    project_id = _finding_project(finding_id)
    check(user, Action.FINDING_REVIEW, project_id)
    config = load_config()
    try:
        return review_finding(finding_id=finding_id, expected_status=body.expected_status,
                              reason=body.reason, actor=f"user:{user.sub}", config=config,
                              audit_writer=resolve_writer(config),
                              reviewer_is_system=bool(user.is_system))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MLFindingAdmissionError as exc:
        raise _error(exc) from exc