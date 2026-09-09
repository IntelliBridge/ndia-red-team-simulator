"""Audit-chain verify route (admin).

``GET /v1/audit/verify`` proves the hash chain of one campaign or project
(spec 5.11, 17.1): ``?run=<id>`` verifies ``run:<id>`` after resolving the
run's project through ``ensure_run_access`` (so an admin of another project
learns nothing about it), ``?project_id=<id>`` verifies ``project:<id>``, and
``?all=1`` verifies every chain the caller may verify and answers
``{"chains": [...]}``, the shape the audit page renders. Every form is gated by
``AUDIT_VERIFY`` (admin) on the chain's project.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check, ensure_run_access
from redsim.audit.chain import AuditWriter, verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])

SYSTEM_CHAIN = "system"


def _may_verify(user: CurrentUser, project_id: str) -> bool:
    try:
        check(user, Action.AUDIT_VERIFY, project_id)
    except HTTPException:
        return False
    return True


def _verify_one(writer: AuditWriter, chain_id: str) -> dict[str, Any]:
    events = list(writer.read_chain(chain_id))
    result = verify_chain(events)
    head = events[-1].get("this_hash") if events else None
    return {
        "chain_id": chain_id,
        "verified": result.verified,
        "count": result.count,
        "event_count": result.count,
        "head_hash": head,
        "broken_at": result.broken_at,
        "reason": result.reason,
    }


def _chain_project(chain_id: str) -> str | None:
    """The project a chain belongs to: ``project:<id>`` directly, ``run:<id>`` through
    the Run row. ``None`` for the system chain or an unresolvable run."""
    if chain_id.startswith("project:"):
        return chain_id.split(":", 1)[1] or None
    if chain_id.startswith("run:"):
        from redsim.db.models import Run
        from redsim.db.session import get_session

        with get_session() as sess:
            run = sess.get(Run, chain_id.split(":", 1)[1])
            return None if run is None else str(run.project_id)
    return None


def _verify_all(writer: AuditWriter, user: CurrentUser) -> dict[str, Any]:
    admin_projects = [pid for pid in user.project_memberships if _may_verify(user, pid)]
    if not user.is_system and not admin_projects:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="audit.verify on every chain needs an admin role")
    chains: list[dict[str, Any]] = []
    for chain_id in sorted(set(writer.iter_chain_ids())):
        if user.is_system:
            allowed = True
        elif chain_id == SYSTEM_CHAIN:
            # Beat tasks (WORM export, tenant integrity): visible to any admin.
            allowed = True
        else:
            project_id = _chain_project(chain_id)
            allowed = project_id is not None and _may_verify(user, project_id)
        if allowed:
            chains.append(_verify_one(writer, chain_id))
    return {"chains": chains}


@router.get("/verify")
def verify(
    project_id: str = "default",
    run: str | None = None,
    all_: bool = Query(False, alias="all"),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config

    writer = resolve_writer(load_config())
    if all_:
        return _verify_all(writer, user)
    if run:
        # The run names the project; the caller's ``project_id`` argument does not.
        project_id = ensure_run_access(user, run)
    check(user, Action.AUDIT_VERIFY, project_id)
    chain_id = f"run:{run}" if run else f"project:{project_id}"
    return _verify_one(writer, chain_id)
