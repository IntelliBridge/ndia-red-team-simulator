"""Resource-scoped RBAC policy."""

from __future__ import annotations

from enum import Enum

from fastapi import HTTPException, status

from aegis.api.auth import CurrentUser


class Action(str, Enum):
    SCAN_START = "scan.start"
    FIX_GENERATE = "fix.generate"
    FIX_APPLY = "fix.apply"
    VERIFY_REPLAY = "verify.replay"
    TARGET_MANAGE = "target.manage"
    AUDIT_VERIFY = "audit.verify"
    RUN_CANCEL = "run.cancel"
    TOOL_INVOKE = "tool.invoke"


_ROLE_RANK = {
    "scanner": 1,
    "remediator": 2,
    "approver": 3,
    "admin": 4,
}

_ACTION_MIN_ROLE: dict[Action, str] = {
    Action.SCAN_START: "scanner",
    Action.FIX_GENERATE: "remediator",
    Action.FIX_APPLY: "approver",
    Action.VERIFY_REPLAY: "remediator",
    Action.TARGET_MANAGE: "admin",
    Action.AUDIT_VERIFY: "admin",
    Action.RUN_CANCEL: "remediator",
    Action.TOOL_INVOKE: "remediator",
}


def check(user: CurrentUser, action: Action, project_id: str) -> None:
    if user.is_system:
        return
    role = user.project_memberships.get(project_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user.email} has no membership on project {project_id}",
        )
    required = _ACTION_MIN_ROLE[action]
    if _ROLE_RANK.get(role, 0) < _ROLE_RANK[required]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{role}' cannot perform '{action.value}' on project {project_id}",
        )
