"""Audit-chain verify route (admin)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check
from redsim.audit.chain import verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/verify")
def verify(
    project_id: str = "default",
    run: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    check(user, Action.AUDIT_VERIFY, project_id)
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    writer = resolve_writer(load_config())
    chain_id = f"run:{run}" if run else f"project:{project_id}"
    events = list(writer.read_chain(chain_id))
    result = verify_chain(events)
    return {
        "chain_id": chain_id,
        "verified": result.verified,
        "count": result.count,
        "broken_at": result.broken_at,
        "reason": result.reason,
    }
