"""Scanner + agent registry smoke."""

import unittest

from aegis.scanners import dispatch, get, list_scanners
from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.agents import list_agents, dispatch as agent_dispatch
from aegis.agents.registry import AgentContext


class TestScannerRegistry(unittest.TestCase):
    def test_builtin_scanners_registered(self):
        names = set(list_scanners())
        for required in ("strix", "trivy", "semgrep", "nuclei"):
            self.assertIn(required, names)

    def test_capabilities_match_plan(self):
        self.assertEqual(get("strix").capabilities, {"dast"})
        self.assertEqual(get("trivy").capabilities, {"dependency"})
        self.assertEqual(get("semgrep").capabilities, {"sast"})
        self.assertEqual(get("nuclei").capabilities, {"dast"})

    def test_dispatch_by_name(self):
        class _Mock:
            name = "mock-dast"
            capabilities = {"dast"}
            default_timeout = 60

            def adapter_version(self):
                return "0.0.0-test"

            def health_check(self):
                return True

            def scan(self, run_state, options):
                return ScanResult(
                    findings=[], adapter_name=self.name,
                    adapter_version=self.adapter_version(),
                    command_str="mock", exit_code=0,
                )

        register(_Mock())
        result = dispatch("mock-dast", run_state=None,
                          options=ScanOptions(target="http://localhost"))
        self.assertEqual(result.adapter_name, "mock-dast")


class TestAgentRegistry(unittest.TestCase):
    def test_wired_and_unwired_present(self):
        agents = {a["name"]: a for a in list_agents()}
        # At least the wired ones from PLAN_PHASE3.md
        for wired in ("codeagent", "blueteam_agent", "bug_bounter",
                      "red_teamer", "dfir", "retester", "reporter",
                      "web_pentester"):
            self.assertIn(wired, agents)
            self.assertTrue(agents[wired]["wired_in_phase_3"])
        # And at least the unwired (Phase 4) ones
        for unwired in ("memory_analysis", "network_traffic_analyzer",
                        "reverse_engineering"):
            self.assertIn(unwired, agents)
            self.assertFalse(agents[unwired]["wired_in_phase_3"])

    def test_unwired_agent_returns_documented_status(self):
        result = agent_dispatch("memory_analysis", "anything",
                                AgentContext(finding_id="vuln-X"))
        self.assertEqual(result.status, "not_wired_in_phase_3")


if __name__ == "__main__":
    unittest.main()
