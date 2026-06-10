"""Tests for the pluggable PolicyEngine (role-gate seam).

Covers:
- StaticPolicyEngine reproduces the historical role-rank table exactly
  across an (Action x role x is_system) matrix, cross-checked against the
  shared ``_ROLE_RANK`` / ``_ACTION_MIN_ROLE`` tables.
- ``resolve_policy_engine`` selects the right class per
  ``AEGIS_POLICY_ENGINE`` and resets cleanly.
- OPA / Cedar engines parse allow/deny and fail closed on transport
  errors, non-200, and malformed bodies; the request body shape is
  asserted.
- ``aegis.api.policy.check`` still raises 403 identically under the
  static default, and honours OPA allow/deny when configured.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import httpx
import pytest

from aegis.api.auth import CurrentUser
from aegis.api.policy import (
    _ACTION_MIN_ROLE,
    _ROLE_RANK,
    Action,
)
from aegis.policy.engine import (
    CedarPolicyEngine,
    OPAPolicyEngine,
    PolicyRequest,
    StaticPolicyEngine,
    build_request,
    reset_policy_engine,
    resolve_policy_engine,
)

_ROLES = ["scanner", "remediator", "approver", "admin"]


@pytest.fixture(autouse=True)
def _reset_engine_singleton():
    """Never leak engine state between tests."""
    reset_policy_engine()
    yield
    reset_policy_engine()


def _user(*, memberships=None, is_system=False) -> CurrentUser:
    return CurrentUser(
        sub="u-1",
        email="alice@aegis.local",
        project_memberships=memberships or {},
        is_system=is_system,
    )


def _expected_static_allow(action: Action, role: str | None,
                           is_system: bool) -> bool:
    """The historical decision, computed straight from the tables."""
    if is_system:
        return True
    if not role:
        return False
    required = _ACTION_MIN_ROLE[action]
    return _ROLE_RANK.get(role, 0) >= _ROLE_RANK[required]


# ----------------------------------------------------------------------------
# StaticPolicyEngine: behaviour-identical matrix
# ----------------------------------------------------------------------------


class TestStaticPolicyEngineMatrix:
    def test_full_matrix_matches_tables(self):
        engine = StaticPolicyEngine()
        for action in Action:
            for role in _ROLES:
                user = _user(memberships={"p1": role})
                req = build_request(user, action.value, "p1")
                decision = engine.evaluate(req)
                expected = _expected_static_allow(action, role, False)
                assert decision.allowed is expected, (
                    f"{action.value} / {role}: got {decision.allowed}, "
                    f"want {expected}"
                )

    def test_no_membership_denies_every_action(self):
        engine = StaticPolicyEngine()
        user = _user(memberships={"other": "admin"})
        for action in Action:
            req = build_request(user, action.value, "p1")
            decision = engine.evaluate(req)
            assert decision.allowed is False
            assert "no membership" in (decision.reason or "")

    def test_is_system_allows_every_action_without_membership(self):
        engine = StaticPolicyEngine()
        user = _user(memberships={}, is_system=True)
        for action in Action:
            req = build_request(user, action.value, "p1")
            assert engine.evaluate(req).allowed is True

    def test_low_role_deny_reason_mentions_role_and_action(self):
        engine = StaticPolicyEngine()
        user = _user(memberships={"p1": "scanner"})
        req = build_request(user, Action.FIX_APPLY.value, "p1")
        decision = engine.evaluate(req)
        assert decision.allowed is False
        assert "scanner" in decision.reason
        assert Action.FIX_APPLY.value in decision.reason

    def test_unknown_role_treated_as_rank_zero(self):
        engine = StaticPolicyEngine()
        user = _user(memberships={"p1": "intern"})
        req = build_request(user, Action.SCAN_START.value, "p1")
        # Unknown role has rank 0 < scanner(1) -> deny, matching the table.
        assert engine.evaluate(req).allowed is False


# ----------------------------------------------------------------------------
# build_request routing
# ----------------------------------------------------------------------------


class TestBuildRequest:
    def test_routes_extra_keys(self):
        user = _user(memberships={"p1": "admin"})
        req = build_request(
            user, Action.FIX_APPLY.value, "p1",
            target="http://localhost", run_id="r1",
            effect_class="active", override_authorized=True,
        )
        assert req.resource == {
            "project_id": "p1", "target": "http://localhost",
            "run_id": "r1", "effect_class": "active",
        }
        assert req.context == {"override_authorized": True}
        assert req.subject["is_system"] is False
        assert req.subject["project_memberships"] == {"p1": "admin"}

    def test_to_input_shape(self):
        req = PolicyRequest(
            subject={"sub": "x"}, action="scan.start",
            resource={"project_id": "p1"}, context={},
        )
        assert req.to_input() == {
            "subject": {"sub": "x"}, "action": "scan.start",
            "resource": {"project_id": "p1"}, "context": {},
        }


# ----------------------------------------------------------------------------
# resolve_policy_engine selection + reset
# ----------------------------------------------------------------------------


class TestResolvePolicyEngine:
    def test_defaults_to_static(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            assert isinstance(resolve_policy_engine(), StaticPolicyEngine)

    def test_selects_opa(self):
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "opa",
                                     "AEGIS_OPA_URL": "http://opa:8181"},
                        clear=False):
            reset_policy_engine()
            engine = resolve_policy_engine()
            assert isinstance(engine, OPAPolicyEngine)
            assert engine.url == "http://opa:8181/v1/data/aegis/authz"

    def test_selects_opa_with_custom_path(self):
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "opa",
                                     "AEGIS_OPA_URL": "http://opa:8181/",
                                     "AEGIS_OPA_PATH": "v1/data/custom"},
                        clear=False):
            reset_policy_engine()
            engine = resolve_policy_engine()
            assert isinstance(engine, OPAPolicyEngine)
            assert engine.url == "http://opa:8181/v1/data/custom"

    def test_selects_cedar(self):
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "cedar",
                                     "AEGIS_CEDAR_URL": "http://cedar:8180"},
                        clear=False):
            reset_policy_engine()
            engine = resolve_policy_engine()
            assert isinstance(engine, CedarPolicyEngine)
            assert engine.url == "http://cedar:8180/v1/is_authorized"

    def test_unknown_backend_falls_back_to_static(self):
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "bogus"},
                        clear=False):
            reset_policy_engine()
            assert isinstance(resolve_policy_engine(), StaticPolicyEngine)

    def test_config_used_when_env_absent(self):
        from aegis.config import AegisConfig
        cfg = AegisConfig(policy_engine="opa", opa_url="http://cfg:8181")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            os.environ.pop("AEGIS_OPA_URL", None)
            reset_policy_engine()
            engine = resolve_policy_engine(cfg)
            assert isinstance(engine, OPAPolicyEngine)
            assert engine.url == "http://cfg:8181/v1/data/aegis/authz"

    def test_singleton_cached_until_reset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            first = resolve_policy_engine()
            second = resolve_policy_engine()
            assert first is second
            reset_policy_engine()
            third = resolve_policy_engine()
            assert third is not first


# ----------------------------------------------------------------------------
# External engine helpers (mock httpx transport)
# ----------------------------------------------------------------------------


class _CapturingClient:
    """Drop-in for httpx.Client that records the last request and replies
    from a programmable handler. Used to assert request body shape without
    a live server.
    """

    last_url: str | None = None
    last_json: dict | None = None

    def __init__(self, handler):
        self._handler = handler

    def __call__(self, *args, **kwargs):  # constructor stand-in
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None):
        type(self).last_url = url
        type(self).last_json = json
        return self._handler(url, json)


def _resp(status_code, json_body=None, *, raise_json=False):
    request = httpx.Request("POST", "http://policy.test")
    if raise_json:
        return httpx.Response(status_code, content=b"not json{",
                              request=request)
    return httpx.Response(status_code, json=json_body, request=request)


class TestOPAPolicyEngine:
    def test_allow(self):
        client = _CapturingClient(
            lambda url, body: _resp(200, {"result": {"allow": True}})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            engine = OPAPolicyEngine("http://opa:8181")
            decision = engine.evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.FIX_APPLY.value, "p1")
            )
        assert decision.allowed is True
        # Request body is OPA's {"input": {...}} envelope.
        assert client.last_url == "http://opa:8181/v1/data/aegis/authz"
        assert "input" in client.last_json
        inp = client.last_json["input"]
        assert inp["action"] == Action.FIX_APPLY.value
        assert inp["resource"]["project_id"] == "p1"
        assert inp["subject"]["project_memberships"] == {"p1": "admin"}

    def test_deny_with_reason(self):
        client = _CapturingClient(
            lambda url, body: _resp(
                200, {"result": {"allow": False, "reason": "nope"}})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = OPAPolicyEngine("http://opa:8181").evaluate(
                build_request(_user(memberships={"p1": "scanner"}),
                              Action.FIX_APPLY.value, "p1")
            )
        assert decision.allowed is False
        assert decision.reason == "nope"

    def test_connection_error_fails_closed(self):
        def _boom(url, body):
            raise httpx.ConnectError("refused")

        client = _CapturingClient(_boom)
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = OPAPolicyEngine("http://opa:8181").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "unavailable" in decision.reason

    def test_500_fails_closed(self):
        client = _CapturingClient(lambda url, body: _resp(500, {}))
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = OPAPolicyEngine("http://opa:8181").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "unavailable" in decision.reason

    def test_malformed_json_fails_closed(self):
        client = _CapturingClient(
            lambda url, body: _resp(200, raise_json=True)
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = OPAPolicyEngine("http://opa:8181").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "unavailable" in decision.reason

    def test_missing_allow_key_fails_closed(self):
        client = _CapturingClient(
            lambda url, body: _resp(200, {"result": {}})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = OPAPolicyEngine("http://opa:8181").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "malformed" in decision.reason


class TestCedarPolicyEngine:
    def test_allow(self):
        client = _CapturingClient(
            lambda url, body: _resp(200, {"decision": "Allow"})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = CedarPolicyEngine("http://cedar:8180").evaluate(
                build_request(_user(memberships={"p1": "approver"}),
                              Action.FIX_APPLY.value, "p1")
            )
        assert decision.allowed is True
        assert client.last_url == "http://cedar:8180/v1/is_authorized"
        # Cedar body carries principal/action/resource/context (no envelope).
        assert client.last_json["action"] == Action.FIX_APPLY.value
        assert client.last_json["principal"]["email"] == "alice@aegis.local"
        assert client.last_json["resource"]["project_id"] == "p1"

    def test_deny_with_reason(self):
        client = _CapturingClient(
            lambda url, body: _resp(
                200, {"decision": "Deny", "reason": "denied by policy"})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = CedarPolicyEngine("http://cedar:8180").evaluate(
                build_request(_user(memberships={"p1": "scanner"}),
                              Action.FIX_APPLY.value, "p1")
            )
        assert decision.allowed is False
        assert decision.reason == "denied by policy"

    def test_connection_error_fails_closed(self):
        def _boom(url, body):
            raise httpx.ConnectTimeout("timeout")

        client = _CapturingClient(_boom)
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = CedarPolicyEngine("http://cedar:8180").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "unavailable" in decision.reason

    def test_malformed_decision_fails_closed(self):
        client = _CapturingClient(
            lambda url, body: _resp(200, {"verdict": "Allow"})
        )
        with patch("aegis.policy.engine.httpx.Client", client):
            decision = CedarPolicyEngine("http://cedar:8180").evaluate(
                build_request(_user(memberships={"p1": "admin"}),
                              Action.SCAN_START.value, "p1")
            )
        assert decision.allowed is False
        assert "malformed" in decision.reason


# ----------------------------------------------------------------------------
# Integration: aegis.api.policy.check() through the engine seam
# ----------------------------------------------------------------------------


class TestCheckIntegration:
    """check() must keep its exact 403 behaviour under the static default."""

    def test_check_static_allows_admin(self):
        from aegis.api.policy import check
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            user = _user(memberships={"p1": "admin"})
            # Should not raise.
            check(user, Action.TARGET_MANAGE, "p1")

    def test_check_static_denies_no_membership_403(self):
        from fastapi import HTTPException

        from aegis.api.policy import check
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            user = _user(memberships={})
            with pytest.raises(HTTPException) as exc:
                check(user, Action.SCAN_START, "p1")
            assert exc.value.status_code == 403
            assert "no membership" in exc.value.detail

    def test_check_static_denies_low_role_403(self):
        from fastapi import HTTPException

        from aegis.api.policy import check
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            user = _user(memberships={"p1": "scanner"})
            with pytest.raises(HTTPException) as exc:
                check(user, Action.FIX_APPLY, "p1")
            assert exc.value.status_code == 403
            assert "scanner" in exc.value.detail

    def test_check_static_system_bypasses(self):
        from aegis.api.policy import check
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_POLICY_ENGINE", None)
            reset_policy_engine()
            user = _user(memberships={}, is_system=True)
            check(user, Action.AUDIT_VERIFY, "p1")  # no raise

    def test_check_opa_allow_permits(self):
        from aegis.api.policy import check
        client = _CapturingClient(
            lambda url, body: _resp(200, {"result": {"allow": True}})
        )
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "opa",
                                     "AEGIS_OPA_URL": "http://opa:8181"},
                        clear=False), \
                patch("aegis.policy.engine.httpx.Client", client):
            reset_policy_engine()
            user = _user(memberships={"p1": "scanner"})
            # Static would deny FIX_APPLY for a scanner; OPA allow wins.
            check(user, Action.FIX_APPLY, "p1")

    def test_check_opa_deny_raises_403_with_reason(self):
        from fastapi import HTTPException

        from aegis.api.policy import check
        client = _CapturingClient(
            lambda url, body: _resp(
                200, {"result": {"allow": False, "reason": "opa says no"}})
        )
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "opa",
                                     "AEGIS_OPA_URL": "http://opa:8181"},
                        clear=False), \
                patch("aegis.policy.engine.httpx.Client", client):
            reset_policy_engine()
            user = _user(memberships={"p1": "admin"})
            with pytest.raises(HTTPException) as exc:
                check(user, Action.SCAN_START, "p1")
            assert exc.value.status_code == 403
            assert exc.value.detail == "opa says no"

    def test_check_opa_unreachable_fails_closed_403(self):
        from fastapi import HTTPException

        from aegis.api.policy import check

        def _boom(url, body):
            raise httpx.ConnectError("refused")

        client = _CapturingClient(_boom)
        with patch.dict(os.environ, {"AEGIS_POLICY_ENGINE": "opa",
                                     "AEGIS_OPA_URL": "http://opa:8181"},
                        clear=False), \
                patch("aegis.policy.engine.httpx.Client", client):
            reset_policy_engine()
            user = _user(memberships={"p1": "admin"})
            with pytest.raises(HTTPException) as exc:
                check(user, Action.SCAN_START, "p1")
            assert exc.value.status_code == 403
            assert "unavailable" in exc.value.detail
