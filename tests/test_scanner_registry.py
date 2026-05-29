"""Scanner + agent registry smoke."""

import unittest

from aegis.agents import list_agents
from aegis.scanners import dispatch, get, list_scanners
from aegis.scanners.registry import ScanOptions, ScanResult, register


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
    def test_phase3_agents_wired(self):
        agents = {a["name"]: a for a in list_agents()}
        for wired in ("codeagent", "blueteam_agent", "bug_bounter",
                      "red_teamer", "dfir", "retester", "reporter",
                      "web_pentester"):
            self.assertIn(wired, agents)
            self.assertTrue(agents[wired]["wired"])

    def test_phase4_agents_now_wired(self):
        # v0.4.2 wired the formerly registered-only forensic/wireless agents;
        # full dispatch coverage lives in tests/test_agent_registry.py.
        agents = {a["name"]: a for a in list_agents()}
        for name in ("memory_analysis", "network_traffic_analyzer",
                     "reverse_engineering"):
            self.assertIn(name, agents)
            self.assertTrue(agents[name]["wired"])


if __name__ == "__main__":
    unittest.main()
