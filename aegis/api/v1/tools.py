"""POST /v1/tools/kali/{tool} — authorized Kali pass-through."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.config import load_config
from aegis.services.tools import run_kali_tool
from aegis.state_factory import open_run_state

router = APIRouter(prefix="/tools", tags=["tools"])


@router.post("/kali/{tool}")
def kali_run(
    tool: str,
    body: dict = Body(default_factory=dict),
    project: str = "default",
    user: CurrentUser = Depends(get_current_user),
):
    check(user, Action.TOOL_INVOKE, project)
    if tool == "command":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="generic shell ('command') is not exposed via the API",
        )
    config = load_config()
    state = open_run_state(config, project_id=project, created_by=user.sub)
    outcome = run_kali_tool(
        name=tool,
        params=body.get("params") or {},
        run_state=state,
        actor=f"user:{user.sub}",
        config=config,
    )
    return {
        "tool": outcome.tool, "success": outcome.success,
        "return_code": outcome.return_code,
        "stdout": outcome.stdout, "stderr": outcome.stderr,
        "error": outcome.error,
    }
