"""Scanner + agent registry smoke."""

import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from aegis.agents import list_agents
from aegis.scanners import dispatch, get, list_scanners
from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    which_available,
)


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


class TestCliVersion(unittest.TestCase):
    """``cli_version`` centralizes the version-probe contract every adapter
    shared: run the tool, swallow *any* failure to ``"unknown"``, and apply
    the small per-tool variations (subcommand / stderr-merge / first-line)."""

    @staticmethod
    def _proc(stdout: str = "", stderr: str = "") -> SimpleNamespace:
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

    def test_returns_stripped_stdout(self):
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="1.2.3\n")) as run:
            self.assertEqual(cli_version("tool"), "1.2.3")
        # Default probe is ``<tool> --version`` and never raises on non-zero.
        argv, kwargs = run.call_args
        self.assertEqual(argv[0], ["tool", "--version"])
        self.assertFalse(kwargs["check"])

    def test_custom_subcommand_is_used(self):
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="v9")) as run:
            cli_version("tool", subcommand="version")
        self.assertEqual(run.call_args.args[0], ["tool", "version"])

    def test_merge_stderr_appends_banner(self):
        # Tools that print the banner to stderr only surface it when asked.
        proc = self._proc(stdout="", stderr="Bandit 1.7.5")
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=proc):
            self.assertEqual(cli_version("bandit"), "unknown")
            self.assertEqual(
                cli_version("bandit", merge_stderr=True), "Bandit 1.7.5")

    def test_first_line_trims_multiline_banner(self):
        proc = self._proc(stdout="CodeQL 2.0\n(c) GitHub\n")
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=proc):
            self.assertEqual(
                cli_version("codeql", first_line=True), "CodeQL 2.0")

    def test_empty_output_is_unknown(self):
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="   ")):
            self.assertEqual(cli_version("tool"), "unknown")

    def test_any_failure_is_unknown(self):
        # Tool absent / probe timed out / anything → the swallowed "unknown".
        for exc in (FileNotFoundError(),
                    subprocess.TimeoutExpired(cmd="tool", timeout=3)):
            with mock.patch("aegis.scanners.registry.subprocess.run",
                            side_effect=exc):
                self.assertEqual(cli_version("tool"), "unknown")


class TestWhichAvailable(unittest.TestCase):
    def test_true_when_any_executable_resolves(self):
        # Falls back across alternatives (e.g. ``zap-cli`` OR ``zap.sh``).
        with mock.patch("aegis.scanners.registry.shutil.which",
                        side_effect=lambda exe: "/usr/bin/zap.sh"
                        if exe == "zap.sh" else None):
            self.assertTrue(which_available("zap-cli", "zap.sh"))

    def test_false_when_none_resolve(self):
        with mock.patch("aegis.scanners.registry.shutil.which",
                        return_value=None):
            self.assertFalse(which_available("nope", "also-nope"))


if __name__ == "__main__":
    unittest.main()
