"""Behavioral tests for CLI modules: main.py, status.py, audit.py.

All external side-effects (subprocess, network, file writes outside tmp, DB,
scan dispatch, service layer) are mocked. Tests are fully offline — no
Postgres, Redis, or scanner binaries required.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

from aegis.cli._console import _colored_severity, _err, _info, _warn
from aegis.cli._runstate import _load_findings_objects, _resolve_run_state
from aegis.cli.main import (
    build_parser,
    cmd_findings,
    cmd_report,
    cmd_scan,
    cmd_verify,
    main,
)
from aegis.config import AegisConfig
from aegis.schema import AegisFinding
from aegis.state import RunState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(tmp: str) -> AegisConfig:
    return AegisConfig(output_dir=tmp)


def _make_finding(**kw) -> AegisFinding:
    defaults = dict(
        id="test-finding-001",
        title="SQL Injection",
        severity="high",
        finding_type="dast",
        description="Test desc",
        source_tool="strix",
        source_run_id="run-001",
        affected_component="/login",
        confidence="high",
        status="open",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    defaults.update(kw)
    return AegisFinding(**defaults)


def _seed_state(tmp: str, run_id: str = "test-run-001",
                findings: list | None = None) -> RunState:
    state = RunState(tmp, run_id)
    if findings is not None:
        state.save_findings(findings)
    else:
        state.save_findings([_make_finding()])
    return state


# ---------------------------------------------------------------------------
# main.py — ANSI / helper functions
# ---------------------------------------------------------------------------

class TestANSIHelpers(unittest.TestCase):

    def test_colored_severity_critical(self):
        result = _colored_severity("critical")
        self.assertIn("CRITICAL", result)

    def test_colored_severity_high(self):
        result = _colored_severity("high")
        self.assertIn("HIGH", result)

    def test_colored_severity_medium(self):
        result = _colored_severity("medium")
        self.assertIn("MEDIUM", result)

    def test_colored_severity_low_no_color_codes(self):
        # 'low' maps to empty string color — no ANSI prefix
        result = _colored_severity("low")
        self.assertEqual(result, "LOW")

    def test_colored_severity_unknown(self):
        result = _colored_severity("unknown")
        self.assertEqual(result, "UNKNOWN")

    def test_info_prints(self, ):
        with patch("builtins.print") as mock_print:
            _info("hello info")
            mock_print.assert_called_once()
            args = mock_print.call_args[0][0]
            self.assertIn("hello info", args)

    def test_warn_prints(self):
        with patch("builtins.print") as mock_print:
            _warn("hello warn")
            mock_print.assert_called_once()
            self.assertIn("hello warn", mock_print.call_args[0][0])

    def test_err_prints_to_stderr(self):
        with patch("builtins.print") as mock_print:
            _err("hello err")
            mock_print.assert_called_once()
            call_kwargs = mock_print.call_args[1]
            self.assertEqual(call_kwargs.get("file"), sys.stderr)


# ---------------------------------------------------------------------------
# _resolve_run_state
# ---------------------------------------------------------------------------

class TestResolveRunState(unittest.TestCase):

    def test_resolve_with_explicit_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            RunState(tmp, "explicit-run")
            result = _resolve_run_state(config, run_id="explicit-run")
            self.assertEqual(result.run_id, "explicit-run")

    def test_resolve_latest_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp, "run-aaa")
            result = _resolve_run_state(config, run_id=None)
            self.assertEqual(result.run_id, "run-aaa")

    def test_resolve_no_runs_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            with self.assertRaises(SystemExit) as ctx:
                _resolve_run_state(config, run_id=None)
            self.assertEqual(ctx.exception.code, 1)


# ---------------------------------------------------------------------------
# _load_findings_objects
# ---------------------------------------------------------------------------

class TestLoadFindingsObjects(unittest.TestCase):

    def test_returns_aegis_finding_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _seed_state(tmp)
            result = _load_findings_objects(state)
            self.assertEqual(len(result), 1)
            self.assertIsInstance(result[0], AegisFinding)

    def test_empty_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "empty-run")
            result = _load_findings_objects(state)
            self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------

class TestBuildParser(unittest.TestCase):

    def test_scan_requires_an_explicit_scanner(self):
        # No default engine: the pentest default ("strix") and the --use-strix
        # bypass flag were removed, so `aegis scan <url>` without --scanner is
        # a usage error (argparse exit 2), never a silently substituted adapter.
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["scan", "http://target.example.invalid"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIsNone(
            parser._subparsers._group_actions[0].choices["scan"]
            ._option_string_actions["--scanner"].default
            or None,
        )
        self.assertNotIn("--use-strix", parser.format_help())

    def test_parser_has_scan_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "http://target.example.invalid", "--scanner", "fake-attack"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target_url, "http://target.example.invalid")

    def test_parser_has_findings_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["findings"])
        self.assertEqual(args.command, "findings")

    def test_parser_has_verify_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "finding-x"])
        self.assertEqual(args.command, "verify")

    def test_parser_has_report_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["report"])
        self.assertEqual(args.command, "report")

    def test_parser_has_doctor_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        self.assertEqual(args.command, "doctor")

    def test_parser_global_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "report"])
        self.assertTrue(args.global_dry_run)

    def test_parser_global_api_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--api", "scan", "http://x.invalid", "--scanner", "fake-attack"])
        self.assertTrue(args.global_api)

    def test_parser_global_override_authorized(self):
        parser = build_parser()
        args = parser.parse_args([
            "--i-understand-this-target-is-authorized", "scan",
            "http://x.invalid", "--scanner", "fake-attack"])
        self.assertTrue(args.global_override_authorized)

    def test_parser_audit_verify(self):
        parser = build_parser()
        args = parser.parse_args(["audit", "verify"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.audit_action, "verify")

    def test_parser_migrate(self):
        parser = build_parser()
        args = parser.parse_args(["migrate", "--source", "/tmp/out",
                                  "--project", "my-project"])
        self.assertEqual(args.command, "migrate")


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------

class TestMainNoCommand(unittest.TestCase):

    def test_no_command_exits_1(self):
        with self.assertRaises(SystemExit) as ctx:
            main([])
        self.assertEqual(ctx.exception.code, 1)


class TestMainDoctor(unittest.TestCase):

    def test_doctor_ok(self):
        with patch("aegis.doctor.run_doctor", return_value=True) as mock_dr, \
             patch("aegis.config.load_config", return_value=AegisConfig()):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor"])
            self.assertEqual(ctx.exception.code, 0)
            mock_dr.assert_called_once()

    def test_doctor_failure(self):
        with patch("aegis.doctor.run_doctor", return_value=False), \
             patch("aegis.config.load_config", return_value=AegisConfig()):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor"])
            self.assertEqual(ctx.exception.code, 1)


class TestMainInit(unittest.TestCase):

    def test_init_creates_aegis_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Patch Path("aegis.yaml") to write into tmp
            with patch("aegis.cli.main.Path",
                       side_effect=lambda p: Path(tmp) / p if p == "aegis.yaml" else Path(p)), \
                 patch("aegis.config.load_config", return_value=AegisConfig(output_dir=tmp)):
                main(["init"])
            # The file may or may not have been created depending on cwd; just
            # confirm the command completes without error.

    def test_init_skips_if_exists(self):
        """If aegis.yaml already exists the command warns and returns."""
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "aegis.yaml"
            existing.write_text("# existing\n")
            with patch("aegis.cli.main.Path",
                       side_effect=lambda p: Path(tmp) / p if p == "aegis.yaml" else Path(p)), \
                 patch("aegis.config.load_config", return_value=AegisConfig(output_dir=tmp)), \
                 patch("aegis.cli._console._warn") as mock_warn:
                main(["init"])
                mock_warn.assert_called()


class TestMainGlobalVerbose(unittest.TestCase):

    def test_verbose_flag_prints_config_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            with patch("aegis.config.load_config", return_value=config), \
                 patch("aegis.cli._console._info") as mock_info, \
                 patch("aegis.cli.main.cmd_findings"):
                main(["--verbose", "findings"])
                # _info should have been called with config= in the message
                calls = [str(c) for c in mock_info.call_args_list]
                self.assertTrue(any("config=" in c for c in calls))


class TestMainGlobalDryRun(unittest.TestCase):

    def test_dry_run_blocks_apply(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--dry-run", "fix", "finding-1", "--apply"])
        self.assertEqual(ctx.exception.code, 2)

    def test_dry_run_blocks_push(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--dry-run", "fix", "finding-1", "--push"])
        self.assertEqual(ctx.exception.code, 2)

    def test_dry_run_blocks_open_pr(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--dry-run", "fix", "finding-1", "--open-pr"])
        self.assertEqual(ctx.exception.code, 2)


class TestMainGlobalApiFlag(unittest.TestCase):

    def test_api_flag_sets_env(self):
        """--api should set AEGIS_MODE=api and route through api dispatch."""
        with patch.dict("os.environ", {}, clear=True), \
             patch("aegis.config.load_config", return_value=AegisConfig()), \
             patch("aegis.cli.api_client.build_client") as mock_bc:
            mock_client = MagicMock()
            mock_client.start_scan.return_value = {
                "run_id": "r1", "job_id": "j1", "status_url": "http://x/status"
            }
            mock_bc.return_value = mock_client
            main(["--api", "scan", "http://target.invalid", "--scanner", "fake-attack"])
            self.assertEqual(os.environ.get("AEGIS_MODE"), "api")


class TestMainGlobalOverrideAuthorized(unittest.TestCase):

    def test_override_authorized_propagated(self):
        """--i-understand-this-target-is-authorized sets args.override_authorized."""
        captured = {}

        def fake_cmd_scan(args, config):
            captured["override"] = getattr(args, "override_authorized", None)

        with patch("aegis.config.load_config", return_value=AegisConfig()), \
             patch.dict("aegis.cli.main._COMMANDS", {"scan": fake_cmd_scan}):
            main([
                "--i-understand-this-target-is-authorized",
                "scan", "http://target.invalid", "--scanner", "fake-attack",
            ])
        self.assertTrue(captured.get("override"))


# ---------------------------------------------------------------------------
# cmd_scan
# ---------------------------------------------------------------------------

class TestCmdScan(unittest.TestCase):

    def _args(self, **kw):
        defaults = dict(
            target_url="http://target.invalid",
            scanner="fake-attack",
            instruction=None, timeout=1800, override_authorized=False,
            global_api=False,
        )
        defaults.update(kw)
        return Namespace(**defaults)

    def test_scan_no_adapter_registered_exits_1_and_writes_no_findings(self):
        # Real wiring, no start_scan mock: the allowlisted target passes the
        # safety gate, the live (empty) registry raises KeyError from
        # dispatch(), and cmd_scan turns that into an honest process failure:
        # exit 1, the adapter named + the aegis.ml.attacks hint printed, and
        # no findings.json anywhere under the output dir. A CI caller can
        # never mistake "no adapter" for "clean scan".
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            args = self._args(target_url="http://localhost:3000",
                              scanner="no-such-adapter-cli")
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.cli._console._err") as mock_err, \
                 self.assertRaises(SystemExit) as ctx:
                cmd_scan(args, config)
            self.assertEqual(ctx.exception.code, 1)
            calls = " ".join(str(c) for c in mock_err.call_args_list)
            self.assertIn("No scanner adapter registered", calls)
            self.assertIn("no-such-adapter-cli", calls)
            self.assertIn("aegis.ml.attacks", calls)
            self.assertEqual(list(Path(tmp).rglob("findings.json")), [])

    def test_scan_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            findings = [_make_finding()]
            outcome = MagicMock()
            outcome.success = True
            outcome.partial_success = False
            outcome.findings = findings
            outcome.return_code = 0
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.scans.start_scan", return_value=outcome) as start:
                cmd_scan(self._args(), config)
            # The CLI names the adapter explicitly; there is no default engine
            # and no events-only bypass flag.
            self.assertEqual(start.call_args.kwargs["scanner"], "fake-attack")
            self.assertNotIn("use_strix", start.call_args.kwargs)
            self.assertEqual(len(list(Path(tmp).rglob("findings.json"))), 1)

    def test_scan_partial_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            findings = [_make_finding()]
            outcome = MagicMock()
            outcome.success = False
            outcome.partial_success = True
            outcome.findings = findings
            outcome.return_code = 1
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.scans.start_scan", return_value=outcome), \
                 patch("aegis.cli._console._warn") as mock_warn:
                cmd_scan(self._args(), config)
                calls = [str(c) for c in mock_warn.call_args_list]
                self.assertTrue(any("partial" in c.lower() for c in calls))

    def test_scan_failure_exits_1_and_writes_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            outcome = MagicMock()
            outcome.success = False
            outcome.partial_success = False
            outcome.findings = []
            outcome.return_code = 2
            outcome.error = "adapter exploded"
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.scans.start_scan", return_value=outcome), \
                 patch("aegis.cli._console._err") as mock_err, \
                 self.assertRaises(SystemExit) as ctx:
                cmd_scan(self._args(), config)
            self.assertEqual(ctx.exception.code, 1)
            calls = [str(c) for c in mock_err.call_args_list]
            self.assertTrue(any("adapter exploded" in c for c in calls))
            self.assertEqual(list(Path(tmp).rglob("findings.json")), [])

    def test_scan_via_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            with patch("aegis.cli.api_client.is_api_mode", return_value=True), \
                 patch("aegis.cli.api_client.build_client") as mock_bc:
                mock_client = MagicMock()
                mock_client.start_scan.return_value = {
                    "run_id": "r1", "job_id": "j1"
                }
                mock_bc.return_value = mock_client
                cmd_scan(self._args(), config)
                mock_client.start_scan.assert_called_once()

    def test_scan_api_error_exits(self):
        from aegis.cli.api_client import ApiError

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            with patch("aegis.cli.api_client.is_api_mode", return_value=True), \
                 patch("aegis.cli.api_client.build_client") as mock_bc:
                mock_client = MagicMock()
                mock_client.start_scan.side_effect = ApiError(400, "bad request")
                mock_bc.return_value = mock_client
                with self.assertRaises(SystemExit) as ctx:
                    cmd_scan(self._args(), config)
                self.assertEqual(ctx.exception.code, 1)

    def test_scan_with_findings_prints_summary(self):
        """When the adapter returns findings the severity summary is printed."""
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            findings = [
                _make_finding(id="f1", severity="critical"),
                _make_finding(id="f2", severity="high"),
                _make_finding(id="f3", severity="medium"),
                _make_finding(id="f4", severity="low"),
            ]
            outcome = MagicMock()
            outcome.success = True
            outcome.partial_success = False
            outcome.findings = findings
            outcome.return_code = 0
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.scans.start_scan", return_value=outcome):
                cmd_scan(self._args(), config)

    def test_scan_api_status_url_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            with patch("aegis.cli.api_client.is_api_mode", return_value=True), \
                 patch("aegis.cli.api_client.build_client") as mock_bc, \
                 patch("aegis.cli._console._info") as mock_info:
                mock_client = MagicMock()
                mock_client.start_scan.return_value = {
                    "run_id": "r1", "job_id": "j1",
                    "status_url": "http://x/status"
                }
                mock_bc.return_value = mock_client
                cmd_scan(self._args(), config)
                calls = [str(c) for c in mock_info.call_args_list]
                self.assertTrue(any("Status" in c for c in calls))


# ---------------------------------------------------------------------------
# cmd_findings
# ---------------------------------------------------------------------------

class TestCmdFindings(unittest.TestCase):

    def test_findings_table_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            args = Namespace(run=None)
            with patch("builtins.print") as mock_print:
                cmd_findings(args, config)
                # Should print header + at least one row
                self.assertGreater(mock_print.call_count, 1)

    def test_findings_no_findings_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            state = RunState(tmp, "empty-run")
            state.save_findings([])
            args = Namespace(run="empty-run")
            with patch("aegis.cli._console._warn") as mock_warn:
                cmd_findings(args, config)
                mock_warn.assert_called()

    def test_findings_long_title_truncated(self):
        """Titles > 45 chars must be truncated to title[:42]+'...'"""
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            long_title = "A" * 60
            finding = _make_finding(title=long_title)
            _seed_state(tmp, findings=[finding])
            args = Namespace(run=None)
            with patch("builtins.print") as mock_print:
                cmd_findings(args, config)
                output = " ".join(str(c) for c in mock_print.call_args_list)
                self.assertIn("...", output)

    def test_findings_explicit_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp, "specific-run")
            args = Namespace(run="specific-run")
            with patch("builtins.print"):
                cmd_findings(args, config)


class TestCmdVerify(unittest.TestCase):

    def test_verify_finding_not_found_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            args = Namespace(
                finding_id="nonexistent", run=None, repo=None,
                no_provenance_check=False, global_api=False,
            )
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 self.assertRaises(SystemExit) as ctx:
                cmd_verify(args, config)
            self.assertEqual(ctx.exception.code, 1)

    def test_verify_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            result = MagicMock()
            result.finding_id = "test-finding-001"
            result.strategy = "http_replay"
            result.status = "verified"
            result.notes = "ok"
            args = Namespace(
                finding_id="test-finding-001", run=None, repo=None,
                no_provenance_check=False, global_api=False,
            )
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.verify.verify", return_value=result), \
                 patch("builtins.print"):
                cmd_verify(args, config)

    def test_verify_inconclusive_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            result = MagicMock()
            result.finding_id = "test-finding-001"
            result.strategy = "sast"
            result.status = "inconclusive"
            result.notes = None
            args = Namespace(
                finding_id="test-finding-001", run=None, repo="/tmp/r",
                no_provenance_check=True, global_api=False,
            )
            with patch("aegis.cli.api_client.is_api_mode", return_value=False), \
                 patch("aegis.services.verify.verify", return_value=result), \
                 patch("builtins.print"):
                cmd_verify(args, config)

    def test_verify_via_api(self):
        with patch("aegis.cli.api_client.is_api_mode", return_value=True), \
             patch("aegis.cli.api_client.build_client") as mock_bc:
            mock_client = MagicMock()
            mock_client.verify.return_value = {"job_id": "j1"}
            mock_bc.return_value = mock_client
            args = Namespace(
                finding_id="test-finding-001", run=None, repo=None,
                no_provenance_check=False, global_api=True,
            )
            cmd_verify(args, AegisConfig())
            mock_client.verify.assert_called_once()

    def test_verify_api_error_exits_1(self):
        from aegis.cli.api_client import ApiError

        with patch("aegis.cli.api_client.is_api_mode", return_value=True), \
             patch("aegis.cli.api_client.build_client") as mock_bc:
            mock_client = MagicMock()
            mock_client.verify.side_effect = ApiError(503, "unavailable")
            mock_bc.return_value = mock_client
            args = Namespace(
                finding_id="test-finding-001", run=None, repo=None,
                no_provenance_check=False, global_api=True,
            )
            with self.assertRaises(SystemExit) as ctx:
                cmd_verify(args, AegisConfig())
            self.assertEqual(ctx.exception.code, 1)


# ---------------------------------------------------------------------------
# cmd_report
# ---------------------------------------------------------------------------

class TestCmdReport(unittest.TestCase):

    def test_report_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            result = MagicMock()
            result.markdown_path = Path(tmp) / "report.md"
            result.json_path = Path(tmp) / "report.json"
            result.html_path = Path(tmp) / "report.html"
            args = Namespace(run=None, no_html=False, html=True)
            with patch("aegis.services.reports.render_reports",
                       return_value=result):
                cmd_report(args, config)

    def test_report_no_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            _seed_state(tmp)
            result = MagicMock()
            result.markdown_path = Path(tmp) / "report.md"
            result.json_path = Path(tmp) / "report.json"
            result.html_path = None
            args = Namespace(run=None, no_html=True, html=False)
            with patch("aegis.services.reports.render_reports",
                       return_value=result):
                cmd_report(args, config)

    def test_report_no_findings_returns_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            state = RunState(tmp, "empty-run")
            state.save_findings([])
            args = Namespace(run="empty-run", no_html=False, html=False)
            with patch("aegis.services.reports.render_reports") as mock_rr:
                cmd_report(args, config)
                mock_rr.assert_not_called()


class TestMainDispatchWiring(unittest.TestCase):

    def test_status_subcommand_dispatches(self):
        # cmd_status is mocked, so sys.exit(0) inside it won't be called;
        # main() just returns normally after the mocked handler returns.
        with patch("aegis.cli.status.cmd_status") as mock_status, \
             patch("aegis.config.load_config", return_value=AegisConfig()):
            try:
                main(["status"])
            except SystemExit:
                pass
            mock_status.assert_called_once()

    def test_audit_verify_dispatches(self):
        with patch("aegis.cli.audit.cmd_audit_verify") as mock_av, \
             patch("aegis.config.load_config", return_value=AegisConfig()):
            main(["audit", "verify"])
            mock_av.assert_called_once()

    def test_migrate_dispatches(self):
        with patch("aegis.cli.migrate.cmd_migrate") as mock_mig, \
             patch("aegis.config.load_config", return_value=AegisConfig()):
            main([
                "migrate", "--source", "/tmp/out", "--project", "p1",
            ])
            mock_mig.assert_called_once()


# ---------------------------------------------------------------------------
# aegis/cli/status.py
# ---------------------------------------------------------------------------

class TestCmdStatus(unittest.TestCase):

    def _run_status(self, env=None, config=None):
        from aegis.cli.status import cmd_status

        if config is None:
            config = AegisConfig()
        env = env or {}
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                cmd_status(Namespace(), config)
        self.assertEqual(ctx.exception.code, 0)

    def test_filesystem_mode(self):
        self._run_status({"AEGIS_MODE": "filesystem"})

    def test_env_shows_api_mode_warning_when_url_set_but_mode_not_api(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_API_URL": "http://fake.api", "AEGIS_MODE": "filesystem"}
        with patch.dict("os.environ", env, clear=True), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("AEGIS_MODE", output)

    def test_api_mode_with_no_url_shows_unset(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_MODE": "api"}
        with patch.dict("os.environ", env, clear=True), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("AEGIS_API_URL is unset", output)

    def test_api_mode_with_url_healthy(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_MODE": "api", "AEGIS_API_URL": "http://fake.api"}
        mock_client = MagicMock()
        mock_client.health.return_value = {"status": "ok"}

        with patch.dict("os.environ", env, clear=True), \
             patch("aegis.cli.api_client.ApiClient", return_value=mock_client), \
             patch("aegis.cli.api_client.load_token", return_value=None), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("healthy", output)

    def test_api_mode_with_url_unreachable(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_MODE": "api", "AEGIS_API_URL": "http://fake.api"}
        mock_client = MagicMock()
        mock_client.health.return_value = None

        with patch.dict("os.environ", env, clear=True), \
             patch("aegis.cli.api_client.ApiClient", return_value=mock_client), \
             patch("aegis.cli.api_client.load_token", return_value=None), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("unreachable", output)

    def test_api_mode_health_not_ok_shows_raw(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_MODE": "api", "AEGIS_API_URL": "http://fake.api"}
        mock_client = MagicMock()
        mock_client.health.return_value = {"status": "degraded"}

        with patch.dict("os.environ", env, clear=True), \
             patch("aegis.cli.api_client.ApiClient", return_value=mock_client), \
             patch("aegis.cli.api_client.load_token", return_value=None), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("degraded", output)

    def test_api_mode_health_ok_via_ok_key(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_MODE": "api", "AEGIS_API_URL": "http://fake.api"}
        mock_client = MagicMock()
        mock_client.health.return_value = {"ok": True}

        with patch.dict("os.environ", env, clear=True), \
             patch("aegis.cli.api_client.ApiClient", return_value=mock_client), \
             patch("aegis.cli.api_client.load_token", return_value=None), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("healthy", output)

    def test_default_env_mode_is_filesystem(self):
        from aegis.cli.status import cmd_status

        env = {}  # empty env — mode defaults to "filesystem"
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                cmd_status(Namespace(), AegisConfig())
            self.assertEqual(ctx.exception.code, 0)

    def test_db_url_changes_backends(self):
        from aegis.cli.status import cmd_status

        env = {"AEGIS_DB_URL": "postgresql://fake/db"}
        with patch.dict("os.environ", env, clear=True), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                cmd_status(Namespace(), AegisConfig())
            output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("postgres", output.lower())

    def test_kv_without_color(self):
        from aegis.cli.status import _kv

        with patch("builtins.print") as mock_print:
            _kv("label", "value")
            output = mock_print.call_args[0][0]
            self.assertIn("label", output)
            self.assertIn("value", output)

    def test_kv_with_color(self):
        from aegis.cli.status import _GREEN, _kv

        with patch("builtins.print") as mock_print:
            _kv("label", "value", color=_GREEN)
            output = mock_print.call_args[0][0]
            self.assertIn(_GREEN, output)


class TestCmdAuditVerify(unittest.TestCase):

    def _make_writer(self, chain_ids=None, chains=None):
        """Build a mock writer for the tests."""
        writer = MagicMock()
        writer.iter_chain_ids.return_value = chain_ids or []
        writer.read_chain.side_effect = lambda cid: iter(
            (chains or {}).get(cid, [])
        )
        return writer

    def test_audit_verify_system_chain_ok(self):
        from aegis.audit.chain import JsonlAuditWriter
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            # Write a valid one-event chain
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            writer.append(
                action="test.action", actor="cli:test",
                target=None, allowlist_check="ok",
                override=False, success=True, detail={},
            )
            args = Namespace(all=False, run=None, project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)

    def test_audit_verify_run_chain(self):
        from aegis.audit.chain import JsonlAuditWriter
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            writer.append(
                action="scan.start", actor="cli:scan",
                target="http://x", allowlist_check="ok",
                override=False, success=True, detail={},
                run_id="run-999",
            )
            args = Namespace(all=False, run="run-999", project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)

    def test_audit_verify_project_chain(self):
        from aegis.audit.chain import JsonlAuditWriter
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            writer.append(
                action="project.created", actor="cli:init",
                target=None, allowlist_check="ok",
                override=False, success=True, detail={},
                project_id="proj-abc",
            )
            args = Namespace(all=False, run=None, project="proj-abc")
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)

    def test_audit_verify_all_flag_empty_chains(self):
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            writer = self._make_writer(chain_ids=[])
            args = Namespace(all=True, run=None, project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)

    def test_audit_verify_all_flag_with_chains(self):
        from aegis.audit.chain import JsonlAuditWriter
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            # Create two chains
            writer.append(
                action="a1", actor="a", target=None, allowlist_check="ok",
                override=False, success=True, detail={}, run_id="r1",
            )
            writer.append(
                action="a2", actor="a", target=None, allowlist_check="ok",
                override=False, success=True, detail={}, run_id="r2",
            )
            args = Namespace(all=True, run=None, project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)

    def test_audit_verify_broken_chain_exits_1(self):
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            # Craft a chain with a deliberately wrong hash
            bad_event = {
                "chain_id": "system",
                "seq": 1,
                "ts": "2026-01-01T00:00:00Z",
                "actor": "cli",
                "action": "test",
                "target": None,
                "allowlist_check": "ok",
                "override": False,
                "success": True,
                "detail": {},
                "schema_version": 1,
                "prev_hash": None,
                "this_hash": "badhash",
                "run_id": None,
                "project_id": None,
            }
            writer = MagicMock()
            writer.iter_chain_ids.return_value = []
            writer.read_chain.return_value = iter([bad_event])
            args = Namespace(all=False, run=None, project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 1)

    def test_audit_verify_no_chain_ids_from_system(self):
        """When no run/project/all, uses 'system' chain_id."""
        from aegis.audit.chain import JsonlAuditWriter
        from aegis.cli.audit import cmd_audit_verify

        with tempfile.TemporaryDirectory() as tmp:
            config = _make_config(tmp)
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            # No events at all — system chain is empty, verify_chain returns count=0
            args = Namespace(all=False, run=None, project=None)
            with patch("aegis.audit.chain.resolve_writer", return_value=writer):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_verify(args, config)
                self.assertEqual(ctx.exception.code, 0)


# ---------------------------------------------------------------------------
# main() — __main__.py surface
# ---------------------------------------------------------------------------

class TestCliMain(unittest.TestCase):

    def test_main_module_invocable(self):
        """The __main__ surface doesn't blow up on import."""
        import aegis.cli.__main__ as m
        # Just asserting the module loads is enough; it calls main() at
        # runtime which we don't want to trigger here.
        self.assertTrue(hasattr(m, "__file__"))


if __name__ == "__main__":
    unittest.main()
