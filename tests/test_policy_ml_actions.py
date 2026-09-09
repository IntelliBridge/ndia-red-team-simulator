"""M0 policy table: the seven ML ``Action`` members, the ``viewer`` rank, the pruned members,
the seven Phase B members (spec 7.4 addendum of 2026-09-09) and the OPA / Cedar mirrors
(spec section 7.4).

The two mirror tests parse the policy files rather than substring-matching them, so a
member whose minimum role differs between Python, Rego and Cedar fails here, not in a
deployment that runs ``REDSIM_POLICY_ENGINE=opa`` or ``cedar``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from redsim.api.auth import CurrentUser
from redsim.api.policy import (
    _ACTION_MIN_ROLE,
    _ROLE_RANK,
    Action,
    check,
    ensure_project_access,
    has_project_access,
)
from redsim.policy.engine import StaticPolicyEngine, build_request, reset_policy_engine

ROOT = Path(__file__).resolve().parents[1]
REGO = ROOT / "deploy" / "opa" / "redsim-authz.rego"
CEDAR = ROOT / "deploy" / "cedar" / "redsim-policy.cedar"

EXPECTED = {
    Action.MODEL_REGISTER: ("model.register", "remediator"),
    Action.ATTACK_RUN: ("attack.run", "scanner"),
    Action.EXPLAIN_RUN: ("explain.run", "scanner"),
    Action.HARDEN_RECOMMEND: ("harden.recommend", "remediator"),
    Action.FINDING_REVIEW: ("finding.review", "approver"),
    Action.FINDING_ANNOTATE: ("finding.annotate", "remediator"),
    Action.REPORT_EXPORT: ("report.export", "scanner"),
}
# Phase B (plan 12 wave B0, actions-and-codes track; spec 7.4 addendum 2026-09-09).
EXPECTED_PHASE_B = {
    Action.LLM_PROBE_RUN: ("llm.probe.run", "remediator"),
    Action.DATASET_REGISTER: ("dataset.register", "remediator"),
    Action.DATASET_EXPORT: ("dataset.export", "scanner"),
    Action.INTEGRATION_PUSH: ("integration.push", "admin"),
    Action.BATCH_RUN: ("batch.run", "scanner"),
    Action.REPORT_RENDER: ("report.render", "scanner"),
    Action.FINDING_AUTHOR: ("finding.author", "remediator"),
}
PRUNED = ("AGENT_RUN", "AGENT_EXECUTE", "FIX_GENERATE", "FIX_APPLY", "TOOL_INVOKE", "TICKET_SYNC")
ROLES = ("viewer", "scanner", "remediator", "approver", "admin")


@pytest.fixture(autouse=True)
def _reset():
    reset_policy_engine()
    yield
    reset_policy_engine()


def _user(role: str | None) -> CurrentUser:
    return CurrentUser(sub="u", email="u@redsim.local",
                       project_memberships={"p1": role} if role else {})


def _roles_at_or_above(min_role: str) -> set[str]:
    return {r for r in ROLES if _ROLE_RANK[r] >= _ROLE_RANK[min_role]}


def test_seven_ml_actions_resolve_their_minimum_roles():
    for action, (value, role) in EXPECTED.items():
        assert action.value == value
        assert _ACTION_MIN_ROLE[action] == role


def test_seven_phase_b_actions_resolve_their_minimum_roles():
    for action, (value, role) in EXPECTED_PHASE_B.items():
        assert action.value == value
        assert _ACTION_MIN_ROLE[action] == role
    # Additive only: the Phase A members and their roles are untouched.
    for action, (value, role) in EXPECTED.items():
        assert _ACTION_MIN_ROLE[action] == role, action
    # The values double as audit action names: dotted, lower-case, short.
    for action in EXPECTED_PHASE_B:
        assert re.fullmatch(r"[a-z_]+(\.[a-z_]+)+", action.value), action
        assert len(action.value) <= 64


def test_every_action_has_a_min_role_row():
    assert set(_ACTION_MIN_ROLE) == set(Action)
    assert set(_ACTION_MIN_ROLE.values()) <= set(_ROLE_RANK)
    assert "viewer" not in _ACTION_MIN_ROLE.values()


def test_pruned_members_are_gone():
    names = {a.name for a in Action}
    for name in PRUNED:
        assert name not in names
    values = {a.value for a in Action}
    for value in ("agent.run", "agent.execute", "fix.generate", "fix.apply", "tool.invoke", "ticket.sync"):
        assert value not in values


def test_viewer_ranks_zero_reads_but_never_acts():
    assert _ROLE_RANK["viewer"] == 0
    assert _ROLE_RANK["viewer"] < _ROLE_RANK["scanner"] < _ROLE_RANK["remediator"] \
        < _ROLE_RANK["approver"] < _ROLE_RANK["admin"]
    viewer = _user("viewer")
    assert has_project_access(viewer, "p1")
    ensure_project_access(viewer, "p1")  # no raise
    engine = StaticPolicyEngine()
    for action in Action:
        decision = engine.evaluate(build_request(viewer, action.value, "p1"))
        assert decision.allowed is False, action
        assert "viewer" in (decision.reason or "")


def test_check_honours_the_ml_table():
    from fastapi import HTTPException

    check(_user("scanner"), Action.ATTACK_RUN, "p1")
    check(_user("remediator"), Action.MODEL_REGISTER, "p1")
    check(_user("approver"), Action.FINDING_REVIEW, "p1")
    with pytest.raises(HTTPException) as exc:
        check(_user("scanner"), Action.MODEL_REGISTER, "p1")
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException):
        check(_user("remediator"), Action.FINDING_REVIEW, "p1")
    with pytest.raises(HTTPException):
        check(_user("viewer"), Action.REPORT_EXPORT, "p1")


@pytest.mark.parametrize("action", sorted(EXPECTED_PHASE_B, key=lambda a: a.value))
def test_phase_b_actions_gate_exactly_at_their_minimum_role(action: Action):
    """Every role at or above the bar passes ``check``; every role below it is a 403.

    The 403 detail is the engine's reason (role and action), never a hint about
    whether the route behind the gate exists yet (they are 501 stubs in wave B0).
    """
    from fastapi import HTTPException

    _, min_role = EXPECTED_PHASE_B[action]
    allowed = _roles_at_or_above(min_role)
    assert allowed, action
    for role in ROLES:
        if role in allowed:
            check(_user(role), action, "p1")  # no raise
        else:
            with pytest.raises(HTTPException) as exc:
                check(_user(role), action, "p1")
            assert exc.value.status_code == 403
            assert role in exc.value.detail and action.value in exc.value.detail
            assert "not_implemented" not in exc.value.detail
    # No membership at all is a 403 for everyone, including the admin of another project.
    stranger = CurrentUser(sub="s", email="s@redsim.local", project_memberships={"other": "admin"})
    with pytest.raises(HTTPException) as exc:
        check(stranger, action, "p1")
    assert exc.value.status_code == 403
    assert "no membership" in exc.value.detail


def test_phase_b_register_scenarios():
    """The register's own acceptance rows (LLM-25, INTEROP-02, BULK-05, REVIEW_REPORTS-05, -21)."""
    from fastapi import HTTPException

    # LLM-25: scanner 403, remediator passes, viewer 403; registration stays TARGET_MANAGE.
    with pytest.raises(HTTPException):
        check(_user("scanner"), Action.LLM_PROBE_RUN, "p1")
    check(_user("remediator"), Action.LLM_PROBE_RUN, "p1")
    with pytest.raises(HTTPException):
        check(_user("viewer"), Action.LLM_PROBE_RUN, "p1")
    assert _ACTION_MIN_ROLE[Action.TARGET_MANAGE] == "admin"
    # INTEROP-02: approver denied on integration.push, admin allowed; scanner denied on
    # dataset.register, remediator allowed.
    with pytest.raises(HTTPException):
        check(_user("approver"), Action.INTEGRATION_PUSH, "p1")
    check(_user("admin"), Action.INTEGRATION_PUSH, "p1")
    with pytest.raises(HTTPException):
        check(_user("scanner"), Action.DATASET_REGISTER, "p1")
    check(_user("remediator"), Action.DATASET_REGISTER, "p1")
    # Plan 12 brief: dataset.export, batch.run and report.render sit at the scanner tier
    # with attack.run and report.export.
    for action in (Action.DATASET_EXPORT, Action.BATCH_RUN, Action.REPORT_RENDER):
        check(_user("scanner"), action, "p1")
        with pytest.raises(HTTPException):
            check(_user("viewer"), action, "p1")
    # REVIEW_REPORTS-05: analyst drafts are remediator; the verdict stays approver.
    check(_user("remediator"), Action.FINDING_AUTHOR, "p1")
    with pytest.raises(HTTPException):
        check(_user("scanner"), Action.FINDING_AUTHOR, "p1")
    with pytest.raises(HTTPException):
        check(_user("remediator"), Action.FINDING_REVIEW, "p1")


# --- OPA / Cedar mirrors ---------------------------------------------------------------


def _rego_table(text: str) -> dict[str, str]:
    """``action_min_role`` of the rego bundle as ``{action: role}``."""
    match = re.search(r"action_min_role\s*:=\s*\{(?P<body>.*?)\n\}", text, re.S)
    assert match, "action_min_role table not found in the rego bundle"
    table: dict[str, str] = {}
    for line in match.group("body").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        row = re.fullmatch(r'"(?P<action>[a-z_.]+)"\s*:\s*"(?P<role>[a-z]+)"\s*,?', line)
        assert row, f"unparsed rego row: {line!r}"
        assert row.group("action") not in table, f"duplicate rego row for {row.group('action')}"
        table[row.group("action")] = row.group("role")
    return table


def _cedar_table(text: str) -> dict[str, str]:
    """Minimum role per action from the Cedar permits: the lowest role a permit lists."""
    table: dict[str, str] = {}
    for permit in re.findall(r"permit\s*\((?P<head>.*?)\)\s*when\s*\{(?P<when>.*?)\}\s*;", text, re.S):
        head, when = permit
        actions = re.findall(r'Action::"([a-z_.]+)"', head)
        if not actions:
            continue  # the is_system bypass names no action
        roles = re.findall(r'principal\.role == "([a-z]+)"', when)
        assert roles, f"permit without roles for {actions}"
        # Each permit lists every role at or above its bar, so the set must be contiguous.
        assert set(roles) == _roles_at_or_above(min(roles, key=_ROLE_RANK.__getitem__)), actions
        for action in actions:
            assert action not in table, f"{action} appears in two Cedar permits"
            table[action] = min(roles, key=_ROLE_RANK.__getitem__)
    return table


def test_opa_bundle_mirrors_the_python_table():
    rego = REGO.read_text()
    assert _rego_table(rego) == {a.value: role for a, role in _ACTION_MIN_ROLE.items()}
    assert '"viewer": 0' in rego
    for stale in ("agent.run", "fix.apply", "tool.invoke", "ticket.sync"):
        assert f'"{stale}"' not in rego


def test_cedar_bundle_mirrors_the_python_table():
    cedar = CEDAR.read_text()
    assert _cedar_table(cedar) == {a.value: role for a, role in _ACTION_MIN_ROLE.items()}
    for action in Action:
        assert f'Action::"{action.value}"' in cedar, action
    for stale in ("agent.run", "agent.execute", "fix.generate", "fix.apply", "tool.invoke"):
        assert f'Action::"{stale}"' not in cedar
    # viewer appears in no permit clause
    assert not re.search(r'principal\.role == "viewer"', cedar)


def test_three_policy_files_agree_on_the_phase_b_actions():
    """The register's parity check (INTEROP-02): the same seven strings, the same roles, in all three."""
    rego = _rego_table(REGO.read_text())
    cedar = _cedar_table(CEDAR.read_text())
    for action, (value, role) in EXPECTED_PHASE_B.items():
        assert _ACTION_MIN_ROLE[action] == role, value
        assert rego[value] == role, f"rego disagrees on {value}"
        assert cedar[value] == role, f"cedar disagrees on {value}"
