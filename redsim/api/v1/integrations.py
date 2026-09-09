"""Interoperability routes (spec section 27): ATLAS coverage, the integrations roster and the Foundry push.

Plan 12 wave B3, ``atlas-foundry`` track (register INTEROP-21, -24, -27, -29).
Wave B0 mounted every route here as a truthful ``501`` stub; this module
replaces three of them with their handlers and keeps the fourth
(``POST /v1/runs/{run_id}/dataset``, the Croissant export) as the B0 stub
until the interop-contribute and interop-consume tracks wire it (the datasets
router, mounted before this one, wins when it carries the same path).

* ``GET /v1/runs/{run_id}/atlas-coverage`` (membership): the techniques the
  declared attack set exercised, the declared attacks recorded ``not_run`` and
  the catalog techniques outside the declared set, computed from the run's
  digest-checked ``ml.run_record``. Never a score: the view carries no numeric
  field (``redsim.ml.atlas.coverage`` refuses one). A probe run is refused with
  ``409 llm_target_required`` (D9), a run without a campaign record is ``404``.
* ``GET /v1/integrations`` (authenticated): which pushes this deployment has
  configured, as status strings and booleans. Foundry is ``disabled`` until
  ``REDSIM_INTEGRATION_FOUNDRY_URL`` is set on the worker environment; Lattice
  is ``not_implemented`` with the D3 reason and stays text only.
* ``POST /v1/runs/{run_id}/integrations/foundry`` (``integration.push``, admin):
  the opt-in push job. ``501 integration_disabled`` when Foundry is not
  configured; otherwise the admission boundary in ``redsim.integrations``
  writes the audit row, the follow-up ``Run`` and ``Job`` and enqueues
  ``redsim.integration_push`` on the ``default`` queue (``202`` JobHandle).

Every handler runs the lookup, membership and role gates before anything
else. Nothing here imports an ML library.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    NOT_FOUND,
    NOT_IMPLEMENTED,
    PARAMS_OUT_OF_RANGE,
    SCORE_UNAVAILABLE,
    ApiError,
    api_error,
)
from redsim.api.policy import Action, check, ensure_run_access

router = APIRouter(tags=["ml-interop"])


def phase_b_action(name: str, fallback: Action) -> Action:
    """``Action.<name>`` once the actions-and-codes track adds it, else the nearest Phase A gate."""
    member = getattr(Action, name, None)
    return member if isinstance(member, Action) else fallback


# ``Action.DATASET_EXPORT`` ("dataset.export") and ``Action.INTEGRATION_PUSH`` ("integration.push", admin) are
# on this tree (wave B0 actions-and-codes). They are resolved by name so this module also imports on a tree
# where ``policy.py`` lags (a partial cherry-pick); the stand-ins are then the nearest Phase A gates.
DATASET_EXPORT: Action = phase_b_action("DATASET_EXPORT", Action.REPORT_EXPORT)
INTEGRATION_PUSH: Action = phase_b_action("INTEGRATION_PUSH", Action.TARGET_MANAGE)


def not_built(message: str, *, wave: str, track: str, **fields: Any) -> HTTPException:
    """The ``501 not_implemented`` envelope every Phase B stub raises after its gates.

    ``message`` says what is not implemented, ``reason`` names the wave and track
    of the Phase B plan that builds it, and ``phase`` is always ``"B"``.
    """
    return api_error(
        NOT_IMPLEMENTED, message, phase="B",
        reason=f"built in wave {wave} ({track} track) of docs/plans/12-phase-b-plan.md",
        **fields,
    )


@router.post("/runs/{run_id}/dataset", status_code=status.HTTP_202_ACCEPTED)
def export_run_dataset(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Croissant export of a campaign run (spec 27.1): membership, ``dataset.export``, then 501.

    The interop-contribute track builds the export and the interop-consume track
    wires the route in the datasets router; this stub stays until then.
    """
    project_id = ensure_run_access(user, run_id)
    check(user, DATASET_EXPORT, project_id)
    raise not_built("Croissant dataset export of a campaign run is not implemented",
                    wave="B3", track="interop-contribute")


# --------------------------------------------------------------------------- ATLAS coverage (INTEROP-21)


def _load_campaign_record(run_id: str) -> dict[str, Any]:
    """The digest-checked ``ml.run_record`` of a campaign run as a mapping, or the typed refusal.

    A probe run is ``409 llm_target_required`` (D9: no attack set, no
    coverage), a run without a campaign row or record is ``404``, and bytes that
    no longer match their digest are ``409 score_unavailable`` with the reason.
    """
    from redsim.db.session import get_session
    from redsim.services.ml_llm import refuse_llm_probe_run
    from redsim.services.reports import load_run_record, ml_campaign_row
    from redsim.storage.blobs import open_blob_store

    with get_session() as sess:
        refuse_llm_probe_run(sess, run_id, route="GET /v1/runs/{run_id}/atlas-coverage")
        if ml_campaign_row(sess, run_id) is None:
            raise ApiError(NOT_FOUND, "campaign record not found")
        try:
            payload, _digest = load_run_record(sess, open_blob_store(), run_id)
        except LookupError:
            raise ApiError(NOT_FOUND, "campaign record not found") from None
        except ValueError as exc:
            raise ApiError(SCORE_UNAVAILABLE, str(exc), reasons=["artifact_digest_mismatch"], run_id=run_id) from None
    return payload


def _catalog_attacks() -> list[tuple[str, str]] | None:
    """``(attack_id, family)`` of the registry, or ``None`` when it cannot be imported in this process."""
    try:
        from redsim.ml.attacks import list_attacks
    except ImportError:
        return None
    return [(str(row.id), str(row.family)) for row in list_attacks()]


@router.get("/runs/{run_id}/atlas-coverage")
def atlas_coverage(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """ATLAS coverage of the declared attack set (spec 27.2 "Coverage view"): membership, then the record."""
    from redsim.ml.atlas import coverage

    ensure_run_access(user, run_id)
    try:
        record = _load_campaign_record(run_id)
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    view = coverage(record, catalog_attacks=_catalog_attacks())
    view["run_id"] = run_id
    view["status_url"] = f"/v1/runs/{run_id}"
    view["campaign_url"] = f"/v1/runs/{run_id}/campaign"
    return view


# --------------------------------------------------------------------------- the roster (INTEROP-29)


@router.get("/integrations")
def list_integrations(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The integrations this deployment enables (spec 27.5): status strings and booleans, never a value."""
    from redsim.config import load_config
    from redsim.integrations import roster

    config = load_config()
    return roster(allowlist=list(getattr(config, "target_allowlist", None) or []))


# --------------------------------------------------------------------------- the Foundry push (INTEROP-24)


@router.post("/runs/{run_id}/integrations/foundry", status_code=status.HTTP_202_ACCEPTED)
def push_to_foundry(
    run_id: str,
    body: dict[str, Any] | None = Body(default=None),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Admit a Foundry scorecard push (``202`` JobHandle) or refuse it with a spec 17.3 envelope.

    Membership and the ``integration.push`` gate (admin) run first; the body is
    validated as :class:`redsim.integrations.FoundryPushRequest` (``422
    params_out_of_range`` naming the field); the admission service owns every
    deeper check and writes the ``integration.push`` row, ``success=False`` on
    refusal, before any row or enqueue.
    """
    from pydantic import ValidationError

    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.integrations import FoundryPushRequest, create_foundry_push

    project_id = ensure_run_access(user, run_id)
    check(user, INTEGRATION_PUSH, project_id)
    try:
        request = FoundryPushRequest.model_validate(body if isinstance(body, dict) else {})
    except ValidationError as exc:
        errors = exc.errors()
        loc: tuple[Any, ...] = tuple(errors[0]["loc"]) if errors and errors[0].get("loc") else ("body",)
        raise api_error(PARAMS_OUT_OF_RANGE, "the push request is not valid",
                        field=".".join(str(part) for part in loc),
                        reasons=[str(e.get("msg")) for e in errors][:5]) from exc
    config = load_config()
    try:
        handle = create_foundry_push(
            run_id=run_id, body=request, actor=f"user:{user.sub}", config=config,
            audit_writer=resolve_writer(config),
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    return handle.to_response()


__all__ = [
    "DATASET_EXPORT",
    "INTEGRATION_PUSH",
    "atlas_coverage",
    "export_run_dataset",
    "list_integrations",
    "not_built",
    "phase_b_action",
    "push_to_foundry",
    "router",
]
