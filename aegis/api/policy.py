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


def ensure_project_access(user: CurrentUser, project_id: str) -> None:
    """403 unless the user has *any* membership on ``project_id``.

    Phase 4 v0.3.1 F12: read-side authorization gate. Used by report,
    export, and WebSocket routes — any membership is sufficient for
    read; mutation routes still go through ``check()`` for role-rank.
    """
    if user.is_system:
        return
    if project_id not in user.project_memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user.email} has no membership on project {project_id}",
        )


def ensure_run_access(user: CurrentUser, run_id: str) -> str:
    """Resolve the run's project, then enforce membership.

    Returns the project_id so callers can use it for blob keys / log
    correlation. 404 if the run is unknown; 403 if the caller has no
    membership on its project.
    """
    from aegis.db.models import Run
    from aegis.db.session import get_session
    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="run not found",
            )
        project_id = run.project_id
    ensure_project_access(user, project_id)
    return project_id
