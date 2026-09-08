"""Scanner registry smoke."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest import mock

from redsim.scanners import dispatch, list_scanners
from redsim.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan_jsonl,
    which_available,
)
from redsim.schema import RedsimFinding

_NOW = "2025-01-01T00:00:00+00:00"


def _finding(fid: str = "f1") -> RedsimFinding:
    return RedsimFinding(
        id=fid, title="t", severity="high", finding_type="dast",
        description="d", source_tool="fake", source_run_id="run-1",
        affected_component="c", confidence="high", status="open",
        created_at=_NOW, updated_at=_NOW,
    )


class TestScannerRegistry(unittest.TestCase):
    def test_registry_starts_without_builtin_adapters(self):
        # The pentest scanner adapters were removed; the registry has no
        # built-ins until an ML attack adapter (redsim.ml.attacks) registers.
        for removed in ("strix", "trivy", "semgrep", "nuclei"):
            self.assertNotIn(removed, set(list_scanners()))

    def test_dispatch_by_name(self):
        class _Mock:
            name = "mock-dast"
            capabilities: ClassVar[set[str]] = {"dast"}
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


class TestCliVersion(unittest.TestCase):
    """``cli_version`` centralizes the version-probe contract every adapter
    shared: run the tool, swallow *any* failure to ``"unknown"``, and apply
    the small per-tool variations (subcommand / stderr-merge / first-line)."""

    @staticmethod
    def _proc(stdout: str = "", stderr: str = "") -> SimpleNamespace:
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

    def test_returns_stripped_stdout(self):
        with mock.patch("redsim.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="1.2.3\n")) as run:
            self.assertEqual(cli_version("tool"), "1.2.3")
        # Default probe is ``<tool> --version`` and never raises on non-zero.
        argv, kwargs = run.call_args
        self.assertEqual(argv[0], ["tool", "--version"])
        self.assertFalse(kwargs["check"])

    def test_custom_subcommand_is_used(self):
        with mock.patch("redsim.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="v9")) as run:
            cli_version("tool", subcommand="version")
        self.assertEqual(run.call_args.args[0], ["tool", "version"])

    def test_merge_stderr_appends_banner(self):
        # Tools that print the banner to stderr only surface it when asked.
        proc = self._proc(stdout="", stderr="Bandit 1.7.5")
        with mock.patch("redsim.scanners.registry.subprocess.run",
                        return_value=proc):
            self.assertEqual(cli_version("bandit"), "unknown")
            self.assertEqual(
                cli_version("bandit", merge_stderr=True), "Bandit 1.7.5")

    def test_first_line_trims_multiline_banner(self):
        proc = self._proc(stdout="CodeQL 2.0\n(c) GitHub\n")
        with mock.patch("redsim.scanners.registry.subprocess.run",
                        return_value=proc):
            self.assertEqual(
                cli_version("codeql", first_line=True), "CodeQL 2.0")

    def test_empty_output_is_unknown(self):
        with mock.patch("redsim.scanners.registry.subprocess.run",
                        return_value=self._proc(stdout="   ")):
            self.assertEqual(cli_version("tool"), "unknown")

    def test_any_failure_is_unknown(self):
        # Tool absent / probe timed out / anything → the swallowed "unknown".
        for exc in (FileNotFoundError(),
                    subprocess.TimeoutExpired(cmd="tool", timeout=3)):
            with mock.patch("redsim.scanners.registry.subprocess.run",
                            side_effect=exc):
                self.assertEqual(cli_version("tool"), "unknown")


class TestWhichAvailable(unittest.TestCase):
    def test_true_when_any_executable_resolves(self):
        # Falls back across alternatives (e.g. ``zap-cli`` OR ``zap.sh``).
        with mock.patch("redsim.scanners.registry.shutil.which",
                        side_effect=lambda exe: "/usr/bin/zap.sh"
                        if exe == "zap.sh" else None):
            self.assertTrue(which_available("zap-cli", "zap.sh"))

    def test_false_when_none_resolve(self):
        with mock.patch("redsim.scanners.registry.shutil.which",
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
        with mock.patch("redsim.scanners.registry.subprocess.run",
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
            with mock.patch("redsim.scanners.registry.subprocess.run",
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
        with mock.patch("redsim.scanners.registry.subprocess.run",
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
        with mock.patch("redsim.scanners.registry.subprocess.run",
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
        with mock.patch("redsim.scanners.registry.subprocess.run",
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
    """``ScanResult.from_runner`` wraps a duck-typed runner result (the seam a
    delegating adapter, e.g. an ML attack adapter in ``redsim.ml.attacks``, uses
    to hand its result back), preserving the exact field mapping
    (command_str / exit_code / error)."""

    @staticmethod
    def _runner(*, findings=None, return_code=0, error=None, command=...):
        attrs = {"findings": findings or [], "return_code": return_code, "error": error}
        # ``command=...`` (default) means "no command attribute" (a runner that
        # is not a CLI wrapper); pass ``command=[...]`` for a CLI-style runner.
        if command is not ...:
            attrs["command"] = command
        return SimpleNamespace(**attrs)

    def test_command_list_is_joined_and_exit_code_coalesced(self):
        f = _finding()
        runner = self._runner(
            findings=[f], return_code=0, error=None,
            command=["fake-cli", "--target", "http://localhost"],
        )
        result = ScanResult.from_runner(
            runner, adapter_name="fake-cli", adapter_version="1.2.3",
            duration_s=4.2,
        )
        self.assertEqual(result.findings, [f])
        self.assertEqual(result.adapter_name, "fake-cli")
        self.assertEqual(result.adapter_version, "1.2.3")
        self.assertEqual(result.command_str, "fake-cli --target http://localhost")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.duration_s, 4.2)
        self.assertIsNone(result.error)

    def test_none_command_becomes_empty_string(self):
        # A runner whose ``command`` is None (not just []) still yields "".
        runner = self._runner(command=None)
        result = ScanResult.from_runner(
            runner, adapter_name="fake-cli", adapter_version="1", duration_s=0.0,
        )
        self.assertEqual(result.command_str, "")

    def test_explicit_command_str_override_when_runner_has_no_command(self):
        # A runner with no ``command`` attribute (e.g. an in-process library
        # call); the adapter supplies a literal command_str instead.
        runner = self._runner(findings=[], return_code=0, error=None)
        self.assertFalse(hasattr(runner, "command"))
        result = ScanResult.from_runner(
            runner, adapter_name="fake-lib", adapter_version="0.46.0",
            duration_s=1.0, command_str="fake-lib scan",
        )
        self.assertEqual(result.command_str, "fake-lib scan")
        self.assertEqual(result.exit_code, 0)

    def test_nonzero_exit_code_and_error_pass_through(self):
        runner = self._runner(return_code=-1, error="fake-lib not found")
        result = ScanResult.from_runner(
            runner, adapter_name="fake-lib", adapter_version="0",
            duration_s=0.0, command_str="fake-lib scan",
        )
        self.assertEqual(result.exit_code, -1)
        self.assertEqual(result.error, "fake-lib not found")
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
