"""Resource-scoped RBAC policy."""

from __future__ import annotations

from enum import Enum

from fastapi import HTTPException, status

from redsim.api.auth import CurrentUser


class Action(str, Enum):
    """RBAC action vocabulary.

    Live callers in this fork: ``SCAN_START`` (the offline ``redsim scan``
    admission path), ``VERIFY_REPLAY``, ``TARGET_MANAGE``,
    ``AUTH_PROFILE_MANAGE``, ``AUDIT_VERIFY`` and ``RUN_CANCEL``. The seven
    ``MODEL_REGISTER`` to ``REPORT_EXPORT`` members are the adversarial-ML
    vertical's gates (spec section 7.4); their routes land in M1 to M6. The
    pentest-era members (agent, fix, tool, ticket) were pruned at M0 with the
    routes that used them. The table is mirrored verbatim in
    ``deploy/opa/redsim-authz.rego`` and ``deploy/cedar/redsim-policy.cedar``.
    Change all three together: an unknown action fails closed.
    """

    SCAN_START = "scan.start"
    VERIFY_REPLAY = "verify.replay"
    TARGET_MANAGE = "target.manage"
    AUTH_PROFILE_MANAGE = "auth_profile.manage"
    AUDIT_VERIFY = "audit.verify"
    RUN_CANCEL = "run.cancel"
    # Adversarial-ML vertical (spec section 7.4).
    MODEL_REGISTER = "model.register"
    ATTACK_RUN = "attack.run"
    EXPLAIN_RUN = "explain.run"
    HARDEN_RECOMMEND = "harden.recommend"
    FINDING_REVIEW = "finding.review"
    FINDING_ANNOTATE = "finding.annotate"
    REPORT_EXPORT = "report.export"


# ``viewer`` ranks 0: it passes every membership (read) gate and fails every
# ``check()`` on a gated action, the same as an unknown role.
_ROLE_RANK = {
    "viewer": 0,
    "scanner": 1,
    "remediator": 2,
    "approver": 3,
    "admin": 4,
}

_ACTION_MIN_ROLE: dict[Action, str] = {
    Action.SCAN_START: "scanner",
    Action.VERIFY_REPLAY: "remediator",
    Action.TARGET_MANAGE: "admin",
    # Auth profiles hold scan credentials — same bar as managing targets.
    Action.AUTH_PROFILE_MANAGE: "admin",
    Action.AUDIT_VERIFY: "admin",
    Action.RUN_CANCEL: "remediator",
    # Registering a model (bundled pick or upload) admits untrusted bytes to
    # the worker sandbox: remediator tier. Endpoint registration is
    # TARGET_MANAGE (admin).
    Action.MODEL_REGISTER: "remediator",
    Action.ATTACK_RUN: "scanner",
    Action.EXPLAIN_RUN: "scanner",
    Action.HARDEN_RECOMMEND: "remediator",
    # Dismissing a finding is a review verdict: approver tier, plus the
    # independence check in the service layer (spec section 7.7).
    Action.FINDING_REVIEW: "approver",
    Action.FINDING_ANNOTATE: "remediator",
    Action.REPORT_EXPORT: "scanner",
}


def check(user: CurrentUser, action: Action, project_id: str) -> None:
    """Role-gate ``action`` on ``project_id`` for ``user`` (raise 403 on deny).

    The decision is delegated to the configured :class:`PolicyEngine`
    (``REDSIM_POLICY_ENGINE``): the default :class:`StaticPolicyEngine`
    reproduces the historical role-rank table exactly (see ``_ROLE_RANK``
    / ``_ACTION_MIN_ROLE`` below), while ``opa`` / ``cedar`` delegate to an
    external policy service. A deny raises the same ``HTTPException(403)``
    as before, carrying the engine's ``reason`` as the detail. All call
    sites are unchanged.
    """
    from redsim.policy.engine import build_request, resolve_policy_engine

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

        from redsim.db.models import Project
        from redsim.db.session import get_session
        with get_session() as sess:
            match = sess.execute(
                select(Project.id)
                .where(Project.org_id == org_id,
                       Project.id.in_(project_ids))
                .limit(1)
            ).first()
        return match is not None
    except Exception:  # noqa: BLE001 - degrade to no access, never open the gate
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
    from redsim.db.models import Run
    from redsim.db.session import get_session
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
