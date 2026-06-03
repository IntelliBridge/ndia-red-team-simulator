"""POST /v1/tools/kali/{tool} — authorized Kali pass-through."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.config import load_config
from aegis.effects import kali_tool_effect, requires_approval
from aegis.services.tools import run_kali_tool
from aegis.state import open_run_state

router = APIRouter(prefix="/tools", tags=["tools"])


class KaliRunBody(BaseModel):
    execute: bool = False
    params: dict[str, Any] | None = None


@router.post("/kali/{tool}")
def kali_run(
    tool: str,
    body: KaliRunBody = KaliRunBody(),
    project: str = "default",
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    # Generic shell is never exposed, for any role.
    if tool == "command":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="generic shell ('command') is not exposed via the API",
        )

    # Active tools (sqlmap/hydra/metasploit/...) are state-changing: they need
    # the approver role + an explicit execute flag, exactly like an active
    # agent or fix.apply. Read tools (nmap/enum4linux/...) stay at remediator.
    effect = kali_tool_effect(tool)
    if requires_approval(effect):
        if not bool(body.execute):
            check(user, Action.TOOL_INVOKE, project)
            return {
                "tool": tool, "status": "pending_approval", "effect": effect,
                "params": body.params or {},
                "message": ("active tool: resubmit with execute=true "
                            "(requires the approver role)"),
            }
        check(user, Action.AGENT_EXECUTE, project)
    else:
        check(user, Action.TOOL_INVOKE, project)

    config = load_config()
    state = open_run_state(config, project_id=project, created_by=user.sub)
    try:
        outcome = run_kali_tool(
            name=tool,
            params=body.params or {},
            run_state=state,
            actor=f"user:{user.sub}",
            config=config,
        )
    finally:
        # Release the factory-owned DB session (commit + close) on the
        # Postgres path; a no-op on the filesystem backend.
        state.close()
    return {
        "tool": outcome.tool, "success": outcome.success,
        "return_code": outcome.return_code,
        "stdout": outcome.stdout, "stderr": outcome.stderr,
        "error": outcome.error,
    }
