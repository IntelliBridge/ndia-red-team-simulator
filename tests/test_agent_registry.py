"""Wave 1A — the 7 newly-wired CAI agents dispatch to real upstream agents.

CAI is mocked (the bundle is fabricated), so no Postgres/Redis/Keycloak and
no real CAI runtime are needed. The real upstream import paths are verified
separately and intentionally not exercised here.
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
        expected = set(_ORIGINAL) | set(_NEW_WIRED)
        self.assertEqual(len(expected), 15)
        self.assertTrue(expected <= names,
                        f"missing: {expected - names}")

    def test_newly_wired_agents_dispatch_ok(self):
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            for name in _NEW_WIRED:
                res = dispatch(name, "x", AgentContext())
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                self.assertEqual(res.output, "ok")

    def test_not_wired_list_empty_and_no_stub_status(self):
        self.assertEqual(builtins._NOT_WIRED, [])
        bundle = _mock_bundle()
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            for a in list_agents():
                res = dispatch(a["name"], "x", AgentContext())
                self.assertNotEqual(res.status, "not_wired_in_phase_3",
                                    f"{a['name']} still stubbed")

    def test_wired_cai_attrs_are_bundle_fields(self):
        fields = {f.name for f in dataclasses.fields(CAIBundle)}
        for name, _domain, cai_attr in builtins._WIRED:
            self.assertIn(cai_attr, fields,
                          f"{name!r} maps to unknown CAIBundle field {cai_attr!r}")

    def test_missing_upstream_agent_returns_error(self):
        # Simulate the upstream agent failing to import (attr is None).
        bundle = _mock_bundle(memory_analysis_agent=None)
        with mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            res = dispatch("memory_analysis", "x", AgentContext())
        self.assertEqual(res.status, "error")


if __name__ == "__main__":
    unittest.main()
