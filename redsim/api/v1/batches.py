"""Batch campaign and bulk verify routes (register BULK-05..08, -15; plan 12 wave B3).

* ``POST /v1/campaigns/batch``: body ``{project_id, target_ids: [...], campaign: {<POST
  /v1/models/{id}/attacks body minus target_id>}, max_parallel?}`` (a flat body whose
  campaign fields sit beside ``target_ids`` is accepted too). Gate order: ``422`` without
  ``project_id``, membership on the project, ``batch.run`` (scanner), then
  :func:`redsim.services.ml_batches.create_campaign_batch`. ``202`` with the batch id, the
  member run ids and the collected per-member refusals. ``Idempotency-Key`` is honoured by
  the wave B2 middleware (``redsim.api.middleware.idempotency``): a replay returns the
  stored 202 body and admits nothing.
* ``GET /v1/campaigns/batch?project=&limit=``: summaries scoped to the caller's memberships
  (membership on ``?project=`` when named).
* ``GET /v1/campaigns/batch/{batch_id}``: the roll-up (statuses, counts, per-member scorecard
  links; never an aggregate score). ``404`` unknown, ``403`` non-member.
* ``GET /v1/campaigns/batch/{batch_id}/compare``: the members' scorecards grouped by
  comparability (:func:`redsim.ml.compare.comparability_groups`); ``200`` when the scored
  members form one group, ``409 incompatible_campaigns`` listing the groups when they do not,
  ``409 score_unavailable`` when no member carries a complete score. No delta, mean or rank.
* ``POST /v1/campaigns/batch/{batch_id}/cancel``: gate ``run.cancel`` (remediator); one
  ``batch.cancel`` row, then ``cancel_run`` per live member; ``409 run_terminal`` when every
  member is terminal.
* ``POST /v1/findings/{finding_id}/verify/bulk``: ``404``, gate ``verify.replay`` on the
  finding's project, then :func:`redsim.services.ml_batches.create_verify_batch` (owner
  decision BULK-16: one defended run per (defense, params) over every selected finding of
  the finding's run).

The bulk upload (``POST /v1/models/bulk``) and capacity (``GET /v1/ml/capacity``) routes
live in ``redsim/api/v1/models_bulk.py`` (mounted once by ``redsim.api.app``); their wave B0
``501`` stubs were removed from this module with the B3 integration, so no path on the Phase B
surface is served twice and nothing here answers ``501 not_implemented``
(``tests/ml/test_phase_b_stubs.py``). ``project_field`` / ``project_required`` stay exported
for the bulk and dataset routes that share the body-or-query project resolution.

Every service import is lazy and nothing here imports an ML library
(``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    INCOMPATIBLE_CAMPAIGNS,
    PARAMS_OUT_OF_RANGE,
    SCORE_UNAVAILABLE,
    ApiError,
    api_error,
)
from redsim.api.policy import Action, accessible_project_ids, check, ensure_project_access

router = APIRouter(tags=["ml-batches"])

#: The batch admission gate (spec 7.3 addendum: a batch is N attack admissions, scanner tier).
BATCH_RUN: Action = Action.BATCH_RUN

#: Request keys that are the batch envelope rather than campaign fields (flat-body form).
_ENVELOPE_KEYS = frozenset({"project_id", "target_ids", "campaign", "max_parallel", "kind"})
_MAX_LIST_LIMIT = 200


async def project_field(request: Request, project: str | None) -> str | None:
    """``project_id`` from the query string, a JSON body or a form body, else ``None``.

    A body that cannot be parsed yields ``None`` (the caller answers ``422``), never a 500.
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


def _actor(user: CurrentUser) -> str:
    return f"user:{user.sub}"


def _finding_project(finding_id: str) -> str:
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        return str(row.project_id)


def _batch_project(batch_id: str) -> str:
    from redsim.services.ml_batches import batch_project_id

    try:
        return batch_project_id(batch_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="batch not found") from exc


def _idempotency_key(request: Request) -> str | None:
    value = request.headers.get("idempotency-key")
    return value if isinstance(value, str) and value else None


# --------------------------------------------------------------------------- batch campaigns


@router.post("/campaigns/batch", status_code=status.HTTP_202_ACCEPTED)
async def start_batch(request: Request, project: str | None = None,
                      user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """One campaign configuration across N models of one modality (BULK-03..05)."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.safety import AuthorizationError
    from redsim.services.ml_batches import create_campaign_batch

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - a malformed body is a 422, never a 500
        body = None
    if not isinstance(body, dict):
        body = {}
    project_id = project or body.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise project_required()
    ensure_project_access(user, project_id)
    check(user, BATCH_RUN, project_id)

    campaign = body.get("campaign")
    if campaign is None:
        campaign = {k: v for k, v in body.items() if k not in _ENVELOPE_KEYS}
    if not isinstance(campaign, dict):
        raise api_error(PARAMS_OUT_OF_RANGE, "campaign must be an object", field="campaign")
    raw_ids = body.get("target_ids")
    target_ids: list[Any] = list(raw_ids) if isinstance(raw_ids, list) else []
    config = load_config()
    try:
        handle = create_campaign_batch(
            project_id=project_id, actor=_actor(user), config=config, audit_writer=resolve_writer(config),
            target_ids=target_ids, campaign=campaign, max_parallel=body.get("max_parallel"),
            idempotency_key=_idempotency_key(request),
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return handle.to_response()


@router.get("/campaigns/batch")
def list_batches(project: str | None = None,
                 limit: int = Query(50, ge=1, le=_MAX_LIST_LIMIT),
                 user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batches of the caller's projects, newest first (membership on ``?project=`` when named)."""
    from redsim.db.session import get_session
    from redsim.services.ml_batches import list_batches as _list

    if project is not None:
        ensure_project_access(user, project)
        scope: list[str] | None = [project]
    else:
        scope = accessible_project_ids(user)
    with get_session() as sess:
        rows = _list(sess, project_ids=scope, limit=limit)
    return {"batches": rows, "count": len(rows)}


@router.get("/campaigns/batch/{batch_id}")
def get_batch(batch_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch roll-up (BULK-06): 404 unknown, membership, then statuses and per-member scorecard links."""
    from redsim.db.session import get_session
    from redsim.services.ml_batches import batch_view

    ensure_project_access(user, _batch_project(batch_id))
    with get_session() as sess:
        return batch_view(sess, batch_id)


@router.get("/campaigns/batch/{batch_id}/compare")
def compare_batch(batch_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch compare table (BULK-07): scorecards grouped by comparability, no delta, mean or rank."""
    from redsim.api.v1.compare import _load_campaign
    from redsim.db.session import get_session
    from redsim.ml.compare import comparability_groups
    from redsim.services.ml_batches import batch_member_rows, batch_view

    ensure_project_access(user, _batch_project(batch_id))
    with get_session() as sess:
        view = batch_view(sess, batch_id)
        members = batch_member_rows(sess, batch_id)
    runs: list[tuple[str, dict[str, Any] | None, dict[str, Any] | None]] = []
    for member in members:
        run_id = str(member["run_id"])
        if member["status"] in {"queued", "running"}:
            runs.append((run_id, None, {"unavailable_reason": f"{run_id}: run is {member['status']}; no record yet"}))
            continue
        try:
            record, overlay = _load_campaign(run_id)
        except HTTPException as exc:
            detail = exc.detail
            reason = detail.get("message") if isinstance(detail, dict) else str(detail)
            runs.append((run_id, None, {"unavailable_reason": f"{run_id}: {reason}"}))
            continue
        runs.append((run_id, record, overlay))
    table = comparability_groups(runs)  # type: ignore[arg-type]
    if not table["groups"]:
        raise api_error(
            SCORE_UNAVAILABLE, "no member of the batch carries a complete score (MRI computed)",
            reasons=[r for item in table["unavailable"] for r in item["reasons"]], batch_id=batch_id,
        )
    if table["n_groups"] > 1:
        raise api_error(
            INCOMPATIBLE_CAMPAIGNS,
            f"the batch members fall into {table['n_groups']} comparability groups; scores are not compared "
            "across settings (compare each group through GET /v1/runs/compare?ids=)",
            batch_id=batch_id,
            groups=[{"run_ids": g["run_ids"], "key": g["key"]} for g in table["groups"]],
            pairs=table["incompatible_pairs"],
            reasons=sorted({r for pair in table["incompatible_pairs"] for r in pair["reasons"]}),
            unavailable=table["unavailable"],
        )
    return {"batch_id": batch_id, "kind": view["kind"], "modality": view["modality"], **table}


@router.post("/campaigns/batch/{batch_id}/cancel")
def cancel_batch(batch_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Batch cancel (BULK-08): 404, ``run.cancel``, one ``batch.cancel`` row, then every live member."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.safety import AuthorizationError
    from redsim.services.ml_batches import cancel_batch as _cancel

    project_id = _batch_project(batch_id)
    check(user, Action.RUN_CANCEL, project_id)
    config = load_config()
    try:
        return _cancel(batch_id=batch_id, actor=_actor(user), config=config, audit_writer=resolve_writer(config))
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="batch not found") from exc
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


# --------------------------------------------------------------------------- bulk verify


@router.post("/findings/{finding_id}/verify/bulk", status_code=status.HTTP_202_ACCEPTED)
async def bulk_verify(finding_id: str, request: Request,
                      user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Bulk verify (BULK-15, owner decision BULK-16): 404, ``verify.replay``, then one defended run per defense."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.safety import AuthorizationError
    from redsim.services.ml_batches import create_verify_batch

    project_id = _finding_project(finding_id)
    check(user, Action.VERIFY_REPLAY, project_id)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - an empty or malformed body is the default request
        body = None
    if body is not None and not isinstance(body, dict):
        raise api_error(PARAMS_OUT_OF_RANGE, "the request body must be an object", field="body")
    config = load_config()
    try:
        handle = create_verify_batch(
            finding_id=finding_id, actor=_actor(user), config=config, audit_writer=resolve_writer(config),
            body=body or {}, idempotency_key=_idempotency_key(request),
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return handle.to_response()


__all__ = ["BATCH_RUN", "project_field", "project_required", "router"]
