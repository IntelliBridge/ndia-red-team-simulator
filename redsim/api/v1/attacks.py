"""Attack catalog and campaign admission endpoint."""

from __future__ import annotations

import inspect
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check, ensure_project_access

router = APIRouter(tags=["ml-attacks"])


def _error(code: str, message: str, *, phase: str | None = None) -> dict[str, str]:
    detail = {"code": code, "message": message}
    if phase:
        detail["phase"] = phase
    return detail


@router.get("/attacks")
def list_attack_catalog(
    modality: str | None = None,
    _user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        from redsim.ml.attacks import list_attacks

        attacks = [row.model_dump(mode="json", exclude_none=True) for row in list_attacks()]
    except ImportError:
        attacks = []
    if modality:
        attacks = [row for row in attacks if row.get("domain") == modality]
    return {"attacks": attacks, "count": len(attacks)}


@router.post("/models/{model_id}/attacks", status_code=status.HTTP_202_ACCEPTED)
def start_attack_campaign(
    model_id: str,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in {"ml_model_artifact", "ml_model_endpoint"}:
            raise HTTPException(status_code=404, detail=_error("model_not_found", "model not found"))
        project_id = target.project_id
        detail = getattr(target, "detail", None) or {}
        kind = target.kind
    ensure_project_access(user, project_id)
    check(user, Action.ATTACK_RUN, project_id)
    if kind == "ml_model_endpoint":
        raise HTTPException(status_code=501, detail=_error(
            "not_implemented", "black-box endpoint campaigns are not implemented", phase="B"))
    if detail.get("status") not in {None, "available"}:
        raise HTTPException(status_code=409, detail=_error(
            "model_load_refused", f"model is {detail.get('status', 'not available')}"))

    try:
        from redsim.services.ml_campaigns import create_attack_campaign
    except ImportError as exc:
        raise HTTPException(status_code=501, detail=_error(
            "campaign_not_implemented", "attack campaign admission service is unavailable")) from exc

    # Keep this route compatible with the planned seam while allowing its
    # admission service to own all deep validation and orchestration.
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config

    app_config = load_config()
    campaign = {
        **body,
        "target_id": model_id,
        "modality": body.get("modality") or detail.get("modality")
        or (detail.get("manifest") or {}).get("modality"),
        "target_snapshot": {
            "id": model_id,
            "kind": kind,
            "value": str(target.value),
            "detail": detail,
        },
    }
    available = {
        "target_id": model_id, "model_id": model_id, "project_id": project_id,
        "body": campaign, "request": campaign, "campaign": campaign,
        "campaign_config": campaign,
        "actor": f"user:{user.sub}", "user": user,
        "config": app_config, "app_config": app_config,
        "audit_writer": resolve_writer(app_config),
    }
    parameters = inspect.signature(create_attack_campaign).parameters
    kwargs: dict[str, Any] = {
        name: available[name] for name in parameters if name in available
    }
    try:
        result = create_attack_campaign(**kwargs)
    except (LookupError, ValueError) as exc:
        message = str(exc)
        candidate = message.split(":", 1)[0]
        code = candidate if candidate.replace("_", "").isalnum() else "campaign_invalid"
        raise HTTPException(status_code=422, detail=_error(code, message)) from exc
    if hasattr(result, "to_response"):
        return result.to_response()
    if isinstance(result, dict):
        return result
    return {
        "run_id": result.run_id,
        "job_ids": list(result.job_ids),
        "status_url": getattr(result, "status_url", f"/v1/runs/{result.run_id}"),
    }