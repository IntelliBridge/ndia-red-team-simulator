"""Scanner + agent registry smoke."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aegis.agents import list_agents
from aegis.scanners import dispatch, get, list_scanners
from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan_jsonl,
    which_available,
)
from aegis.schema import AegisFinding

_NOW = "2025-01-01T00:00:00+00:00"


def _finding(fid: str = "f1") -> AegisFinding:
    return AegisFinding(
        id=fid, title="t", severity="high", finding_type="dast",
        description="d", source_tool="fake", source_run_id="run-1",
        affected_component="c", confidence="high", status="open",
        created_at=_NOW, updated_at=_NOW,
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


class TestRunCliScanJsonl(unittest.TestCase):
    """``run_cli_scan_jsonl`` is the line-oriented sibling of ``run_cli_scan``:
    it parses stdout one line at a time, skips malformed lines instead of
    failing the scan, and lets the per-line ``convert`` callback filter a line
    out by returning ``None``."""

    @staticmethod
    def _adapter() -> mock.MagicMock:
        adapter = mock.MagicMock()
        adapter.name = "fake"
        adapter.default_timeout = 600
        adapter.adapter_version.return_value = "0.0.0"
        return adapter

    @staticmethod
    def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=[], returncode=returncode,
                                           stdout=stdout, stderr="")

    def _run(self, stdout, convert, *, returncode=0, run_path="/tmp/run"):
        rs = SimpleNamespace(run_id="run-1", run_path=run_path)
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=self._completed(stdout, returncode)):
            return run_cli_scan_jsonl(
                self._adapter(), ScanOptions(target="/repo"), rs,
                argv=["fake", "scan"], command_str="fake scan",
                convert=convert,
            )

    def test_parses_each_line_and_skips_malformed(self):
        # Two valid JSON lines, a non-JSON line, and a blank line between them;
        # only the two valid lines become findings (the scan never errors out).
        stdout = (json.dumps({"id": "a"}) + "\n"
                  + "NOT JSON\n"
                  + "\n"
                  + json.dumps({"id": "b"}) + "\n")
        seen: list[str] = []

        def convert(rec, run_id):
            self.assertEqual(run_id, "run-1")
            seen.append(rec["id"])
            return _finding(rec["id"])

        result = self._run(stdout, convert)
        self.assertEqual(seen, ["a", "b"])
        self.assertEqual([f.id for f in result.findings], ["a", "b"])
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.error)

    def test_none_from_callback_filters_line_out(self):
        # Mirrors bumblebee's record_type filter: keep only "finding" records.
        stdout = "\n".join(json.dumps(r) for r in [
            {"record_type": "package", "id": "pkg"},
            {"record_type": "finding", "id": "keep"},
            {"record_type": "scan_summary", "id": "sum"},
        ])

        def convert(rec, run_id):
            if rec.get("record_type") != "finding":
                return None
            return _finding(rec["id"])

        result = self._run(stdout, convert)
        self.assertEqual([f.id for f in result.findings], ["keep"])

    def test_persists_raw_stdout_and_empty_writes_empty_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            rs = SimpleNamespace(run_id="run-1", run_path=tmp)
            with mock.patch("aegis.scanners.registry.subprocess.run",
                            return_value=self._completed("", returncode=0)):
                result = run_cli_scan_jsonl(
                    self._adapter(), ScanOptions(target="/repo"), rs,
                    argv=["fake", "scan"], command_str="fake scan",
                    subdir="fake", raw_filename="results.jsonl",
                    convert=lambda rec, run_id: _finding(),
                )
            raw = Path(tmp) / "fake" / "results.jsonl"
            self.assertTrue(raw.exists())
            # JSONL placeholder for empty stdout is the empty string, not "{}".
            self.assertEqual(raw.read_text(), "")
        self.assertEqual(result.findings, [])

    def test_timeout_returns_error_envelope_no_raise(self):
        rs = SimpleNamespace(run_id="run-1", run_path="/tmp/run")
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="fake", timeout=1)):
            result = run_cli_scan_jsonl(
                self._adapter(), ScanOptions(target="/repo"), rs,
                argv=["fake", "scan"], command_str="fake scan",
                convert=lambda rec, run_id: _finding(),
            )
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    def test_file_not_found_returns_error_envelope_no_raise(self):
        rs = SimpleNamespace(run_id="run-1", run_path="/tmp/run")
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        side_effect=FileNotFoundError("fake not found")):
            result = run_cli_scan_jsonl(
                self._adapter(), ScanOptions(target="/repo"), rs,
                argv=["fake", "scan"], command_str="fake scan",
                convert=lambda rec, run_id: _finding(),
            )
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    def test_default_timeout_honoured_when_options_unset(self):
        rs = SimpleNamespace(run_id="run-1", run_path="/tmp/run")
        with mock.patch("aegis.scanners.registry.subprocess.run",
                        return_value=self._completed("")) as run:
            run_cli_scan_jsonl(
                self._adapter(), ScanOptions(target="/repo"), rs,
                argv=["fake", "scan"], command_str="fake scan",
                convert=lambda rec, run_id: None,
            )
        # ScanOptions left the timeout at the registry sentinel -> use the
        # adapter's default_timeout (600), same contract as run_cli_scan.
        self.assertEqual(run.call_args.kwargs["timeout"], 600)


class TestScanResultFromRunner(unittest.TestCase):
    """``ScanResult.from_runner`` collapses the verbatim re-wrap the strix and
    trivy adapters performed on a duck-typed runner result, preserving the exact
    field mapping (command_str / exit_code / error)."""

    @staticmethod
    def _runner(*, findings=None, return_code=0, error=None, command=...):
        attrs = dict(findings=findings or [], return_code=return_code, error=error)
        # ``command=...`` (default) means "no command attribute" — the trivy
        # shape; pass ``command=[...]`` for the strix shape.
        if command is not ...:
            attrs["command"] = command
        return SimpleNamespace(**attrs)

    def test_strix_shape_joins_command_and_coalesces_exit_code(self):
        f = _finding()
        runner = self._runner(
            findings=[f], return_code=0, error=None,
            command=["strix", "--target", "http://localhost"],
        )
        result = ScanResult.from_runner(
            runner, adapter_name="strix", adapter_version="1.2.3",
            duration_s=4.2,
        )
        self.assertEqual(result.findings, [f])
        self.assertEqual(result.adapter_name, "strix")
        self.assertEqual(result.adapter_version, "1.2.3")
        self.assertEqual(result.command_str, "strix --target http://localhost")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.duration_s, 4.2)
        self.assertIsNone(result.error)

    def test_none_command_becomes_empty_string(self):
        # StrixRunResult.command defaults to [] but be robust to None too.
        runner = self._runner(command=None)
        result = ScanResult.from_runner(
            runner, adapter_name="strix", adapter_version="1", duration_s=0.0,
        )
        self.assertEqual(result.command_str, "")

    def test_explicit_command_str_override_for_trivy_shape(self):
        # TrivyRunResult has no ``command`` attribute; the adapter supplies the
        # literal "trivy fs" instead of deriving it.
        runner = self._runner(findings=[], return_code=0, error=None)
        self.assertFalse(hasattr(runner, "command"))
        result = ScanResult.from_runner(
            runner, adapter_name="trivy", adapter_version="0.46.0",
            duration_s=1.0, command_str="trivy fs",
        )
        self.assertEqual(result.command_str, "trivy fs")
        self.assertEqual(result.exit_code, 0)

    def test_nonzero_exit_code_and_error_pass_through(self):
        runner = self._runner(return_code=-1, error="trivy CLI not found")
        result = ScanResult.from_runner(
            runner, adapter_name="trivy", adapter_version="0",
            duration_s=0.0, command_str="trivy fs",
        )
        self.assertEqual(result.exit_code, -1)
        self.assertEqual(result.error, "trivy CLI not found")
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
