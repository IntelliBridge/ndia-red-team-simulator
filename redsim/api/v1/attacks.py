"""Attack catalog and campaign admission endpoint.

``POST /v1/models/{id}/attacks`` is the spec 17.2 campaign launcher. The route
only locates the model, runs the membership and ``ATTACK_RUN`` gates and hands
the body to :func:`redsim.services.ml_campaigns.create_attack_campaign`; every
refusal the service raises is a typed :class:`redsim.api.errors.ApiError` whose
section 17.3 code and status become the ``{"detail": {"code", ...}}`` envelope
here. Nothing is parsed out of exception text. An optional ``parent_run_id`` in
the body admits a rerun of a failed or cancelled campaign with the parent's
configuration (spec 10.6, lineage in ``ml_campaigns.parent_run_id``).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, ApiError, api_error
from redsim.api.policy import Action, check, ensure_project_access
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError

router = APIRouter(tags=["ml-attacks"])

_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})


def _catalog_unavailable(exc: ImportError) -> HTTPException:
    """The catalog registry could not be imported in this API process.

    Say so with a 503 and the ImportError text; an empty ``200`` would present a
    deployment that can neither list nor launch anything as a healthy one.
    """
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
        "code": "ml_catalog_unavailable",
        "message": "attack catalog is unavailable in this API process",
        "reason": str(exc),
    })


@router.get("/attacks")
def list_attack_catalog(
    modality: str | None = None,
    _user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        from redsim.ml.attacks import list_attacks

        attacks = [row.model_dump(mode="json", exclude_none=True) for row in list_attacks()]
    except ImportError as exc:
        raise _catalog_unavailable(exc) from exc
    if modality:
        attacks = [row for row in attacks if row.get("domain") == modality]
    return {"attacks": attacks, "count": len(attacks)}


@router.post("/models/{model_id}/attacks", status_code=status.HTTP_202_ACCEPTED)
def start_attack_campaign(
    model_id: str,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Admit a campaign (``202`` JobHandle) or refuse it with a spec 17.3 envelope.

    The admission service owns every deep check (target status, attack registry,
    grid rules, dataset binding, rerun lineage) and writes the ``attack.run``
    audit row, ``success=False`` on refusal, before any row or enqueue.
    """
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS:
            raise api_error(NOT_FOUND, "model not found")
        project_id = target.project_id
    ensure_project_access(user, project_id)
    check(user, Action.ATTACK_RUN, project_id)

    # The service module reaches the attack registry (numpy) and is imported per
    # request so the API process stays light at start-up.
    from redsim.services.ml_campaigns import create_attack_campaign

    app_config = load_config()
    parent_run_id = body.get("parent_run_id")
    campaign = {key: value for key, value in body.items() if key != "parent_run_id"}
    campaign["target_id"] = model_id
    try:
        handle = create_attack_campaign(
            campaign=campaign,
            project_id=project_id,
            actor=f"user:{user.sub}",
            config=app_config,
            audit_writer=resolve_writer(app_config),
            parent_run_id=parent_run_id,
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return handle.to_response()
