"""Phase B bulk and batch routes, mounted as truthful ``501`` stubs.

Wave B0 of ``docs/plans/12-phase-b-plan.md`` mounts the owner's bulk-operations
surface (register scope BULK) and two report-snapshot routes so the tree is
honest about them before waves B2 and B3 build them. Each handler runs the
gates its real handler will run (``404`` for an unknown run, model or finding,
``422`` for a body without ``project_id``, ``403`` for a non-member or an
under-ranked role) and only then answers ``501 not_implemented`` with
``phase`` and a ``reason``. Nothing is faked: no batch row, no run, no job,
no audit event, no enqueue.

Batch campaigns (wave B3, bulk-service-routes):

* ``POST /v1/campaigns/batch`` (membership on the body's ``project_id``, gate
  ``batch.run``), ``GET /v1/campaigns/batch?project=`` (membership when a
  project is named).
* ``GET /v1/campaigns/batch/{batch_id}``, ``GET .../{batch_id}/compare`` and
  ``POST .../{batch_id}/cancel``: no batch row can exist before the batch
  service is built, so there is no project to resolve a membership or role
  against; these three answer 501 after authentication and the real handlers
  add the 404, membership and ``run.cancel`` gates with the ``ml_batches``
  lookup.

Bulk upload, bulk verify and capacity (wave B3, bulk-upload-capacity-cli and
bulk-service-routes):

* ``POST /v1/models/bulk`` (membership on ``project_id``, gate ``model.register``).
* ``POST /v1/findings/{finding_id}/verify/bulk`` (404, gate ``verify.replay``
  on the finding's project).
* ``GET /v1/ml/capacity?project=`` (membership when a project is named).

The two report-snapshot stubs wave B0 hosted here (``POST
/v1/runs/{run_id}/report.render``, ``GET /v1/runs/{run_id}/snapshots``) moved
to ``redsim/api/v1/reports.py`` when wave B2 (reports-compare-weights) built
them.

Nothing here imports an ML library.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import PARAMS_OUT_OF_RANGE, api_error
from redsim.api.policy import Action, check, ensure_project_access
from redsim.api.v1.integrations import not_built, phase_b_action

router = APIRouter(tags=["ml-batches"])


# ``Action.BATCH_RUN`` ("batch.run") is added by the actions-and-codes track of the
# same wave (plan section 5, wave B0) and is the gate in force once both tracks are
# on the tree. Resolved by name so this module also imports on a tree where
# ``policy.py`` lags; the stand-in is then ``attack.run``, the gate register
# BULK-05 names (a batch is N attack campaigns).
BATCH_RUN: Action = phase_b_action("BATCH_RUN", Action.ATTACK_RUN)


async def project_field(request: Request, project: str | None) -> str | None:
    """``project_id`` from the query string, a JSON body or a form body, else ``None``.

    The bulk routes take multipart bodies once built and the batch route JSON; the
    stub reads whichever the client sent so the membership and role gates run on
    the project the request names. A body that cannot be parsed yields ``None``
    (the caller answers ``422``), never a 500.
    """
    if project:
        return project
    content_type = request.headers.get("content-type", "")
    try:
        if content_type.startswith("application/json"):
            body = await request.json()
            value = body.get("project_id") if isinstance(body, dict) else None
        elif content_type.startswith(("multipart/form-data", "application/x-www-form-urlencoded")):
            form = await request.form()
            value = form.get("project_id")
        else:
            value = None
    except Exception:  # noqa: BLE001 - a malformed body is a 422 at the caller, not a 500
        return None
    return str(value) if isinstance(value, str) and value else None


def project_required() -> HTTPException:
    """``422 params_out_of_range`` for a batch or bulk body that names no project."""
    return api_error(PARAMS_OUT_OF_RANGE, "project_id is required", field="project_id")


def _finding_project(finding_id: str) -> str:
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        return str(row.project_id)


# --------------------------------------------------------------------------- batch campaigns


@router.post("/campaigns/batch", status_code=status.HTTP_202_ACCEPTED)
async def start_batch(request: Request, project: str | None = None,
                      user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """One campaign config across N models (register BULK-05): 422, membership, ``batch.run``, then 501."""
    project_id = await project_field(request, project)
    if project_id is None:
        raise project_required()
    ensure_project_access(user, project_id)
    check(user, BATCH_RUN, project_id)
    raise not_built("batch campaigns are not implemented", wave="B3", track="bulk-service-routes")


@router.get("/campaigns/batch")
def list_batches(project: str | None = None,
                 user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batches of the caller's projects (BULK-05): membership on ``?project=`` when named, then 501."""
    if project is not None:
        ensure_project_access(user, project)
    raise not_built("batch listing is not implemented", wave="B3", track="bulk-service-routes")


@router.get("/campaigns/batch/{batch_id}")
def get_batch(batch_id: str, _user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch roll-up (BULK-06): no batch row can exist yet, so 501 after authentication."""
    raise not_built("batch roll-up reads are not implemented", wave="B3", track="bulk-service-routes",
                    batch_id=batch_id)


@router.get("/campaigns/batch/{batch_id}/compare")
def compare_batch(batch_id: str, _user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch compare table (BULK-07): no batch row can exist yet, so 501 after authentication."""
    raise not_built("batch comparison is not implemented", wave="B3", track="bulk-service-routes",
                    batch_id=batch_id)


@router.post("/campaigns/batch/{batch_id}/cancel")
def cancel_batch(batch_id: str, _user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch cancel (BULK-08): no batch row can exist yet, so 501 after authentication.

    The real handler resolves the batch's project from ``ml_batches`` and gates on
    ``run.cancel`` before touching any member.
    """
    raise not_built("batch cancel is not implemented", wave="B3", track="bulk-service-routes",
                    batch_id=batch_id)


# --------------------------------------------------------------------------- bulk upload, verify, capacity


@router.post("/models/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_upload(request: Request, project: str | None = None,
                      user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Several model files in one request (BULK-13): 422, membership, ``model.register``, then 501."""
    project_id = await project_field(request, project)
    if project_id is None:
        raise project_required()
    ensure_project_access(user, project_id)
    check(user, Action.MODEL_REGISTER, project_id)
    raise not_built("bulk model upload is not implemented", wave="B3", track="bulk-upload-capacity-cli")


@router.post("/findings/{finding_id}/verify/bulk", status_code=status.HTTP_202_ACCEPTED)
def bulk_verify(finding_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Bulk verify (BULK-15, owner decision BULK-16): 404, ``verify.replay``, then 501."""
    project_id = _finding_project(finding_id)
    check(user, Action.VERIFY_REPLAY, project_id)
    raise not_built("bulk verify is not implemented", wave="B3", track="bulk-service-routes")


@router.get("/ml/capacity")
def ml_capacity(project: str | None = None,
                user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Per-project capacity view (BULK-22): membership on ``?project=`` when named, then 501."""
    if project is not None:
        ensure_project_access(user, project)
    raise not_built("the ML capacity view is not implemented", wave="B3", track="bulk-upload-capacity-cli")
