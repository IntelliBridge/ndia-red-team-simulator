"""Resource-scoped RBAC policy."""

from __future__ import annotations

from enum import Enum

from fastapi import HTTPException, status

from aegis.api.auth import CurrentUser


class Action(str, Enum):
    SCAN_START = "scan.start"
    AGENT_RUN = "agent.run"
    AGENT_EXECUTE = "agent.execute"
    FIX_GENERATE = "fix.generate"
    FIX_APPLY = "fix.apply"
    VERIFY_REPLAY = "verify.replay"
    TARGET_MANAGE = "target.manage"
    AUTH_PROFILE_MANAGE = "auth_profile.manage"
    AUDIT_VERIFY = "audit.verify"
    RUN_CANCEL = "run.cancel"
    TOOL_INVOKE = "tool.invoke"
    TICKET_SYNC = "ticket.sync"


_ROLE_RANK = {
    "scanner": 1,
    "remediator": 2,
    "approver": 3,
    "admin": 4,
}

_ACTION_MIN_ROLE: dict[Action, str] = {
    Action.SCAN_START: "scanner",
    Action.AGENT_RUN: "remediator",
    # Executing an active/external agent (exploit, live hardening, PR) is the
    # state-changing step — same bar as applying a fix.
    Action.AGENT_EXECUTE: "approver",
    Action.FIX_GENERATE: "remediator",
    Action.FIX_APPLY: "approver",
    Action.VERIFY_REPLAY: "remediator",
    Action.TARGET_MANAGE: "admin",
    # Auth profiles hold scan credentials — same bar as managing targets.
    Action.AUTH_PROFILE_MANAGE: "admin",
    Action.AUDIT_VERIFY: "admin",
    Action.RUN_CANCEL: "remediator",
    Action.TOOL_INVOKE: "remediator",
    # Pushing a finding to an external tracker is a remediation-workflow
    # action — same bar as fix.generate / verify.replay.
    Action.TICKET_SYNC: "remediator",
}


def check(user: CurrentUser, action: Action, project_id: str) -> None:
    """Role-gate ``action`` on ``project_id`` for ``user`` (raise 403 on deny).

    The decision is delegated to the configured :class:`PolicyEngine`
    (``AEGIS_POLICY_ENGINE``): the default :class:`StaticPolicyEngine`
    reproduces the historical role-rank table exactly (see ``_ROLE_RANK``
    / ``_ACTION_MIN_ROLE`` below), while ``opa`` / ``cedar`` delegate to an
    external policy service. A deny raises the same ``HTTPException(403)``
    as before, carrying the engine's ``reason`` as the detail. All call
    sites are unchanged.
    """
    from aegis.policy.engine import build_request, resolve_policy_engine

    req = build_request(user, action.value, project_id)
    decision = resolve_policy_engine().evaluate(req)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason or (
                f"role check failed for '{action.value}' on project {project_id}"
            ),
        )


def has_project_access(user: CurrentUser, project_id: str) -> bool:
    """True if the user may read resources scoped to ``project_id``.

    The boolean form for per-row list filtering; ``ensure_project_access``
    is the raising form for single-resource gates. Both share this rule so
    read authorization has one definition.
    """
    return user.is_system or project_id in user.project_memberships


def accessible_project_ids(user: CurrentUser) -> list[str] | None:
    """Project IDs the user may read, or ``None`` when unrestricted.

    System principals read across all projects (``None`` = no filter).
    Used to scope list queries to the caller's memberships so listings
    never leak rows from projects the caller cannot access.
    """
    if user.is_system:
        return None
    return list(user.project_memberships)


def ensure_project_access(user: CurrentUser, project_id: str) -> None:
    """403 unless the user has *any* membership on ``project_id``.

    Phase 4 v0.3.1 F12: read-side authorization gate. Used by report,
    export, and WebSocket routes — any membership is sufficient for
    read; mutation routes still go through ``check()`` for role-rank.
    """
    if not has_project_access(user, project_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user.email} has no membership on project {project_id}",
        )


def has_org_access(user: CurrentUser, org_id: str) -> bool:
    """True if the user may read resources scoped to ``org_id``.

    Org-tier mirror of ``has_project_access``: a system principal always
    passes; otherwise the caller must be a member of at least one project that
    belongs to ``org_id``. Membership lives in ``project_memberships`` (keyed by
    project id), so the project→org mapping is resolved from the DB.

    Degrades safely without a DB / on lookup error: returns ``False`` (no
    access) rather than raising, so a missing session can't open the gate.
    """
    if user.is_system:
        return True
    project_ids = list(user.project_memberships)
    if not project_ids:
        return False
    try:
        from sqlalchemy import select

        from aegis.db.models import Project
        from aegis.db.session import get_session
        with get_session() as sess:
            match = sess.execute(
                select(Project.id)
                .where(Project.org_id == org_id,
                       Project.id.in_(project_ids))
                .limit(1)
            ).first()
        return match is not None
    except Exception:
        return False


def ensure_org_access(user: CurrentUser, org_id: str) -> None:
    """403 unless the user has access to ``org_id`` (see ``has_org_access``)."""
    if not has_org_access(user, org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user.email} has no access to organization {org_id}",
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
        project_id: str = run.project_id
    ensure_project_access(user, project_id)
    return project_id
