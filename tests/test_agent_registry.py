"""The CAI agent registry resolves every slot to a real upstream agent.

CAI is mocked (the bundle is fabricated), so no Postgres/Redis/Keycloak and no
real CAI runtime are needed. Offline, the loader degrades unavailable agents to
None; these tests fabricate the bundle so dispatch returns "ok". The real
upstream import paths are verified separately and not exercised here.
"""

from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch as mpatch

from aegis.agents.cai import builtins
from aegis.agents.registry import AgentContext, dispatch, list_agents
from aegis.integrations.cai_loader import CAIBundle

_NEW_WIRED = [
    "memory_analysis",
    "network_traffic_analyzer",
    "reverse_engineering",
    "android_sast_agent",
    "subghz_sdr_agent",
    "wifi_security_tester",
    "replay_attack_agent",
]

_ORIGINAL = [
    "codeagent",
    "blueteam_agent",
    "bug_bounter",
    "red_teamer",
    "dfir",
    "retester",
    "reporter",
    "web_pentester",
]

# The six slots that previously fell through to codeagent/blueteam_agent now
# resolve to their real specialist agents (slot name -> CAIBundle attr).
_CORRECTED = {
    "bug_bounter": "bug_bounter_agent",
    "red_teamer": "redteam_agent",
    "dfir": "dfir_agent",
    "retester": "retester_agent",
    "reporter": "reporting_agent",
    "web_pentester": "web_pentester_agent",
}

# Composed in the loader from read-only recon tools (B4: the recon domain).
_COMPOSED = ["recon"]


def _mock_bundle(**overrides):
    attrs = {a: MagicMock() for a in CAIBundle.__dataclass_fields__}
    attrs["cai_version"] = "deadbeef"
    attrs["Runner"] = MagicMock()
    attrs["Runner"].run_sync.return_value = MagicMock(final_output="ok")
    attrs.update(overrides)
    return MagicMock(**attrs)


class TestAgentRegistry(unittest.TestCase):
    def test_all_expected_agents_registered(self):
        names = {a["name"] for a in list_agents()}
        expected = set(_ORIGINAL) | set(_NEW_WIRED) | set(_COMPOSED)
        self.assertEqual(len(expected), 16)
        self.assertTrue(expected <= names,
                        f"missing: {expected - names}")

    def test_corrected_slots_map_to_real_specialist_agents(self):
        """The 6 mis-wired slots resolve to named specialists, not fallbacks."""
        wired = {name: cai_attr
                 for name, _domain, _effect, cai_attr in builtins._WIRED}
        for slot, expected_attr in _CORRECTED.items():
            self.assertEqual(
                wired[slot], expected_attr,
                f"{slot!r} should map to {expected_attr!r}, not a fallback")

    def test_recon_agent_registered_with_recon_domain(self):
        recon = {a["name"]: a for a in list_agents()}.get("recon")
        self.assertIsNotNone(recon, "recon agent not registered")
        self.assertEqual(recon["domain"], "recon")

    def test_recon_and_corrected_slots_dispatch_ok(self):
        # execute=True clears the effect-class gate so active agents actually
        # invoke; read agents ignore the flag. This verifies slot resolution.
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            for name in [*_CORRECTED, *_COMPOSED]:
                res = dispatch(name, "x", AgentContext(execute=True))
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                self.assertEqual(res.output, "ok")

    def test_newly_wired_agents_dispatch_ok(self):
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            for name in _NEW_WIRED:
                res = dispatch(name, "x", AgentContext(execute=True))
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                self.assertEqual(res.output, "ok")

    def test_not_wired_list_empty_and_no_stub_status(self):
        self.assertEqual(builtins._NOT_WIRED, [])
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            for a in list_agents():
                res = dispatch(a["name"], "x", AgentContext())
                self.assertNotEqual(res.status, "not_wired",
                                    f"{a['name']} still stubbed")

    def test_wired_cai_attrs_are_bundle_fields(self):
        fields = {f.name for f in dataclasses.fields(CAIBundle)}
        for name, _domain, _effect, cai_attr in builtins._WIRED:
            self.assertIn(cai_attr, fields,
                          f"{name!r} maps to unknown CAIBundle field {cai_attr!r}")

    def test_list_agents_exposes_effect_class(self):
        for a in list_agents():
            self.assertIn(a["effect"], {"read", "active", "external"},
                          f"{a['name']} has unexpected effect {a.get('effect')!r}")

    def test_active_agent_without_execute_is_gated_and_never_invokes(self):
        """An active agent without execute=True returns a proposal only.

        The effect-class gate lives in dispatch(), upstream of invoke(), so the
        underlying CAI agent (Runner.run_sync) is NEVER reached. This is the
        human-gate guarantee: propose -> approve -> act.
        """
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            res = dispatch("red_teamer", "attack the host", AgentContext())
        self.assertEqual(res.status, "pending_approval")
        self.assertIsNotNone(res.plan)
        self.assertTrue(res.plan["gated"])
        self.assertEqual(res.plan["required_role"], "approver")
        bundle.Runner.run_sync.assert_not_called()

    def test_read_agent_without_execute_invokes_frictionlessly(self):
        """Read-effect agents (recon/static analysis) need no execute flag."""
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            res = dispatch("recon", "enumerate", AgentContext())
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.output, "ok")

    def test_missing_upstream_agent_returns_error(self):
        # Simulate the upstream agent failing to import (attr is None).
        bundle = _mock_bundle(memory_analysis_agent=None)
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            res = dispatch("memory_analysis", "x", AgentContext())
        self.assertEqual(res.status, "error")


if __name__ == "__main__":
    unittest.main()
