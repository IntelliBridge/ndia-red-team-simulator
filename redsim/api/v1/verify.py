"""POST /v1/findings/{id}/verify — enqueue a verification via admission service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.verify import create_verify_job

router = APIRouter(prefix="/findings", tags=["verify"])


class VerifyBody(BaseModel):
    defense: str = "feature_squeezing"
    params: dict[str, Any] = Field(default_factory=dict)
    recommendation_id: str | None = None


@router.post("/{finding_id}/verify")
def verify(finding_id: str, body: VerifyBody | None = None,
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
        is_ml = isinstance(finding.schema_blob, dict) and isinstance(
            finding.schema_blob.get("ml"), dict,
        )

    check(user, Action.VERIFY_REPLAY, project_id)

    body = body or VerifyBody()
    config = load_config()
    try:
        if is_ml:
            from redsim.services.ml_campaigns import create_verify_campaign

            if not body.recommendation_id:
                raise ValueError(
                    "recommendation_required: recommendation_id is required "
                    "for ML verification"
                )
            campaign_handle = create_verify_campaign(
                finding_id=finding_id,
                defense_id=body.defense,
                params=body.params,
                recommendation_id=body.recommendation_id,
                actor=f"user:{user.sub}",
                config=config,
                audit_writer=resolve_writer(config),
            )
            return campaign_handle.to_response()
        legacy_handle = create_verify_job(
            finding_id=finding_id, project_id=project_id, run_id=run_id,
            actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "finding_not_found", "message": str(exc)},
        ) from exc
    except ValueError as exc:
        message = str(exc)
        code = message.split(":", 1)[0] if ":" in message else (
            "unknown_defense" if "unknown defense" in message else
            "params_out_of_range"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT
            if code in {"campaign_not_terminal", "job_in_flight"}
            else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": code, "message": message},
        ) from exc
    return legacy_handle.to_response()
