"""M0 policy table: the seven ML ``Action`` members, the ``viewer`` rank, the pruned members,
and the OPA / Cedar mirrors (spec section 7.4)."""

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

EXPECTED = {
    Action.MODEL_REGISTER: ("model.register", "remediator"),
    Action.ATTACK_RUN: ("attack.run", "scanner"),
    Action.EXPLAIN_RUN: ("explain.run", "scanner"),
    Action.HARDEN_RECOMMEND: ("harden.recommend", "remediator"),
    Action.FINDING_REVIEW: ("finding.review", "approver"),
    Action.FINDING_ANNOTATE: ("finding.annotate", "remediator"),
    Action.REPORT_EXPORT: ("report.export", "scanner"),
}
PRUNED = ("AGENT_RUN", "AGENT_EXECUTE", "FIX_GENERATE", "FIX_APPLY", "TOOL_INVOKE", "TICKET_SYNC")


@pytest.fixture(autouse=True)
def _reset():
    reset_policy_engine()
    yield
    reset_policy_engine()


def _user(role: str | None) -> CurrentUser:
    return CurrentUser(sub="u", email="u@redsim.local",
                       project_memberships={"p1": role} if role else {})


def test_seven_ml_actions_resolve_their_minimum_roles():
    for action, (value, role) in EXPECTED.items():
        assert action.value == value
        assert _ACTION_MIN_ROLE[action] == role


def test_every_action_has_a_min_role_row():
    assert set(_ACTION_MIN_ROLE) == set(Action)


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


def test_opa_bundle_mirrors_the_python_table():
    rego = (ROOT / "deploy" / "opa" / "redsim-authz.rego").read_text()
    for action, role in _ACTION_MIN_ROLE.items():
        assert f'"{action.value}": "{role}"' in rego, action
    assert '"viewer": 0' in rego
    for stale in ("agent.run", "fix.apply", "tool.invoke", "ticket.sync"):
        assert f'"{stale}"' not in rego


def test_cedar_bundle_mirrors_the_python_table():
    cedar = (ROOT / "deploy" / "cedar" / "redsim-policy.cedar").read_text()
    for action in Action:
        assert f'Action::"{action.value}"' in cedar, action
    for stale in ("agent.run", "agent.execute", "fix.generate", "fix.apply", "tool.invoke"):
        assert f'Action::"{stale}"' not in cedar
    # viewer appears in no permit clause
    assert not re.search(r'principal\.role == "viewer"', cedar)
