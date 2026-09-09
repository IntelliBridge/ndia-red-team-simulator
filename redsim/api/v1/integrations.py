"""Phase B interoperability routes (spec section 27), mounted as truthful ``501`` stubs.

Wave B0 of ``docs/plans/12-phase-b-plan.md`` mounts every route a later wave
builds so the tree is honest about its surface from the first push (register
row INTEROP-01). Each handler runs the same lookup, membership and role gates
its real handler will run (``404`` for an unknown run, ``403`` for a non-member
or an under-ranked role) and only then answers ``501 not_implemented`` with
``phase`` and a ``reason`` through :func:`redsim.api.errors.api_error`. Nothing
is faked: no row, no audit event, no enqueue, no manifest, no push.

* ``POST /v1/runs/{run_id}/dataset``: Croissant export of a campaign's clean,
  adversarial and control slices (wave B3, interop-contribute; gate
  ``dataset.export``).
* ``GET /v1/runs/{run_id}/atlas-coverage``: the ATLAS techniques the declared
  attack set exercised, never a score (wave B3, atlas-foundry; membership).
* ``POST /v1/runs/{run_id}/integrations/foundry``: the opt-in Foundry push job
  (wave B3, atlas-foundry; gate ``integration.push``, admin).
* ``GET /v1/integrations``: the integrations this deployment has enabled (wave
  B3, atlas-foundry; authenticated).

``GET /v1/datasets/{id}`` and ``POST /v1/datasets`` are the dataset router's
stubs (``redsim/api/v1/datasets.py``). Nothing here imports an ML library.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_IMPLEMENTED, api_error
from redsim.api.policy import Action, check, ensure_run_access

router = APIRouter(tags=["ml-interop"])


def phase_b_action(name: str, fallback: Action) -> Action:
    """``Action.<name>`` once the actions-and-codes track adds it, else the nearest Phase A gate."""
    member = getattr(Action, name, None)
    return member if isinstance(member, Action) else fallback


# ``Action.DATASET_EXPORT`` ("dataset.export") and ``Action.INTEGRATION_PUSH``
# ("integration.push", admin) are added by the actions-and-codes track of the same
# wave (register INTEROP-02) and are the gates in force once both tracks are on the
# tree. They are resolved by name so this module also imports on a tree where
# ``policy.py`` lags (a partial cherry-pick); the stand-ins are then the nearest
# Phase A gates, ``report.export`` for the export and ``target.manage`` for the push.
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
    """Croissant export of a campaign run (spec 27.1): membership, ``dataset.export``, then 501."""
    project_id = ensure_run_access(user, run_id)
    check(user, DATASET_EXPORT, project_id)
    raise not_built("Croissant dataset export of a campaign run is not implemented",
                    wave="B3", track="interop-contribute")


@router.get("/runs/{run_id}/atlas-coverage")
def atlas_coverage(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """ATLAS coverage of the declared attack set (spec 27.4): membership, then 501."""
    ensure_run_access(user, run_id)
    raise not_built("ATLAS technique coverage for a campaign run is not implemented",
                    wave="B3", track="atlas-foundry")


@router.post("/runs/{run_id}/integrations/foundry", status_code=status.HTTP_202_ACCEPTED)
def push_to_foundry(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Foundry push of a run's scorecard (spec 27.5): membership, ``integration.push``, then 501."""
    project_id = ensure_run_access(user, run_id)
    check(user, INTEGRATION_PUSH, project_id)
    raise not_built("the Palantir Foundry push is not implemented", wave="B3", track="atlas-foundry",
                    integration="foundry")


@router.get("/integrations")
def list_integrations(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The integrations this deployment enables (spec 27.5): authenticated, then 501."""
    raise not_built("the integrations roster is not implemented", wave="B3", track="atlas-foundry")
