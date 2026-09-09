"""POST /v1/findings/{id}/verify — enqueue a verification via admission service.

Two admissions share the route. A finding that carries ML campaign evidence
(``schema_blob["ml"]``, the ``MLFindingDetail`` projection) is verified through
:func:`redsim.services.ml_campaigns.create_verify_campaign`: body
``{defense?, params?, recommendation_id?}`` (spec 17.2; the defense defaults per
spec 16.5 and ``recommendation_id`` is optional), ``202`` with a JobHandle, and
every refusal is a typed :class:`redsim.api.errors.ApiError` rendered as the
section 17.3 envelope (``unknown_defense``, ``defense_modality_mismatch``,
``params_out_of_range``, ``campaign_not_terminal``, ``job_in_flight``,
``score_unavailable``, ``not_implemented``, ``queue_unavailable``). Any other
finding takes the retained aegis path (``services.verify.create_verify_job``)
unchanged.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import ApiError
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.verify import create_verify_job

router = APIRouter(prefix="/findings", tags=["verify"])


class VerifyBody(BaseModel):
    defense: str | None = None                      # id from GET /v1/defenses; spec 16.5 default when omitted
    params: dict[str, Any] = Field(default_factory=dict)
    recommendation_id: str | None = None            # optional: the candidate whose defense is measured


@router.post("/{finding_id}/verify")
def verify(finding_id: str, response: Response, body: VerifyBody | None = None,
           user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """F6 admission entry — looks up the finding, runs RBAC, then delegates.

    ML findings go to ``services.ml_campaigns.create_verify_campaign`` (``202``);
    every other finding to ``services.verify.create_verify_job``.
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
    if is_ml:
        from redsim.services.ml_campaigns import create_verify_campaign

        try:
            campaign_handle = create_verify_campaign(
                finding_id=finding_id,
                defense_id=body.defense,
                params=body.params,
                recommendation_id=body.recommendation_id,
                actor=f"user:{user.sub}",
                config=config,
                audit_writer=resolve_writer(config),
            )
        except ApiError as exc:
            raise exc.as_http_exception() from exc
        except AuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=str(exc)) from exc
        response.status_code = status.HTTP_202_ACCEPTED
        return campaign_handle.to_response()

    try:
        legacy_handle = create_verify_job(
            finding_id=finding_id, project_id=project_id, run_id=run_id,
            actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="finding not found") from exc
    return legacy_handle.to_response()
