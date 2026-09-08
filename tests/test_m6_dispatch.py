"""M6 multi-scanner dispatch (offline-safe).

Covers the seams finished in M6:

  (a) ``start_scan`` with a non-Strix scanner routes through the registry
      ``dispatch`` and maps the returned ``ScanResult`` into a ``ScanOutcome``;
  (b) ``start_scan`` with ``scanner="strix"`` still delegates to ``run_strix``
      with its original ``detail`` shape (no regression);
  (c) ``POST /v1/scans`` with an unregistered scanner is rejected with HTTP 400
      before any Run/Job row is created;
  (d) ``run_cli_scan`` falls back to an adapter's ``default_timeout`` when the
      caller leaves ``ScanOptions.timeout`` at its sentinel default.

No scanner binary, broker, or DB is touched: ``dispatch`` / ``run_strix`` /
``subprocess.run`` are mocked at their boundaries.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from aegis.config import AegisConfig
from aegis.scanners.registry import ScanOptions, ScanResult, run_cli_scan
from aegis.services.scans import ScanOutcome, start_scan


def _run_state() -> MagicMock:
    rs = MagicMock()
    rs.run_path = "/tmp/run"
    rs.run_id = "test-run-001"
    return rs


def _completed(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="{}", stderr="")


class TestStartScanDispatch(unittest.TestCase):
    def setUp(self):
        self.config = AegisConfig(target_allowlist=["localhost"])

    def test_non_strix_scanner_dispatches_and_maps_result(self):
        state = _run_state()
        result = ScanResult(
            findings=[], adapter_name="semgrep", adapter_version="1.2.3",
            command_str="semgrep --json /repo", exit_code=0,
            duration_s=4.2, error=None,
        )
        with patch("aegis.scanners.dispatch", return_value=result) as dispatch, \
             patch("aegis.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                instruction="focus on injection", timeout=600,
                actor="cli:scan", config=self.config,
            )
        # dispatch received the scanner name + a ScanOptions carrying our inputs.
        self.assertEqual(dispatch.call_args[0][0], "semgrep")
        opts = dispatch.call_args[0][2]
        self.assertIsInstance(opts, ScanOptions)
        self.assertEqual(opts.target, "localhost")
        self.assertEqual(opts.instruction, "focus on injection")
        self.assertEqual(opts.timeout, 600)
        # ScanResult -> ScanOutcome mapping.
        self.assertIsInstance(outcome, ScanOutcome)
        self.assertTrue(outcome.success)
        self.assertFalse(outcome.partial_success)
        self.assertEqual(outcome.scanner, "semgrep")
        self.assertEqual(outcome.return_code, 0)
        self.assertIsNone(outcome.error)
        self.assertEqual(outcome.detail["command"], "semgrep --json /repo")
        self.assertEqual(outcome.detail["adapter_version"], "1.2.3")
        self.assertEqual(outcome.detail["duration_s"], 4.2)
        state.save_findings.assert_called_once_with(result.findings)

    def test_non_strix_partial_success_when_findings_with_nonzero_exit(self):
        state = _run_state()
        finding = MagicMock()
        result = ScanResult(
            findings=[finding], adapter_name="semgrep", adapter_version="1",
            command_str="semgrep", exit_code=1, duration_s=1.0, error=None,
        )
        with patch("aegis.scanners.dispatch", return_value=result), \
             patch("aegis.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                actor="cli:scan", config=self.config,
            )
        self.assertFalse(outcome.success)
        self.assertTrue(outcome.partial_success)
        self.assertEqual(outcome.return_code, 1)

    def test_non_strix_error_marks_failure(self):
        state = _run_state()
        result = ScanResult(
            findings=[], adapter_name="semgrep", adapter_version="1",
            command_str="semgrep", exit_code=0, duration_s=0.0,
            error="boom",
        )
        with patch("aegis.scanners.dispatch", return_value=result), \
             patch("aegis.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                actor="cli:scan", config=self.config,
            )
        self.assertFalse(outcome.success)
        self.assertFalse(outcome.partial_success)
        self.assertEqual(outcome.error, "boom")

    def test_strix_scanner_still_uses_run_strix(self):
        from aegis.runners.strix_runner import StrixRunResult
        state = _run_state()
        strix_result = StrixRunResult(
            success=True, partial_success=False, return_code=0,
            findings=[], command=["strix", "--target", "localhost"],
            log_path="/tmp/run/strix/log", events_path="/tmp/run/events.jsonl",
            error=None,
        )
        with patch("aegis.runners.strix_runner.run_strix",
                   return_value=strix_result) as run_strix, \
             patch("aegis.scanners.dispatch") as dispatch, \
             patch("aegis.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="strix",
                actor="cli:scan", config=self.config,
            )
        run_strix.assert_called_once()
        dispatch.assert_not_called()
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.scanner, "strix")
        # Strix-specific detail shape is unchanged.
        self.assertEqual(outcome.detail["command"], strix_result.command)
        self.assertEqual(outcome.detail["log_path"], "/tmp/run/strix/log")
        self.assertEqual(outcome.detail["events_path"], "/tmp/run/events.jsonl")
        state.save_findings.assert_called_once_with([])

    def test_events_only_bypass_skips_dispatch_and_strix(self):
        state = _run_state()
        with patch("aegis.runners.strix_runner.run_strix") as run_strix, \
             patch("aegis.scanners.dispatch") as dispatch, \
             patch("aegis.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                actor="cli:scan", config=self.config, use_strix=False,
            )
        run_strix.assert_not_called()
        dispatch.assert_not_called()
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.detail, {"mode": "events-only"})


class TestRunCliScanTimeout(unittest.TestCase):
    """run_cli_scan honours the adapter's default_timeout when unset."""

    def _adapter(self, default_timeout: int):
        adapter = MagicMock()
        adapter.name = "fake"
        adapter.default_timeout = default_timeout
        adapter.adapter_version.return_value = "0.0.0"
        return adapter

    def _call(self, options: ScanOptions, default_timeout: int):
        adapter = self._adapter(default_timeout)
        rs = _run_state()
        with patch("subprocess.run", return_value=_completed()) as run:
            run_cli_scan(
                adapter, options, rs,
                argv=["fake", "scan"], command_str="fake scan",
                parse=lambda proc, run_id: [],
            )
        return run

    def test_uses_adapter_default_timeout_when_options_unset(self):
        run = self._call(ScanOptions(target="/repo"), default_timeout=3600)
        self.assertEqual(run.call_args.kwargs["timeout"], 3600)

    def test_caller_override_wins_over_adapter_default(self):
        run = self._call(ScanOptions(target="/repo", timeout=42), default_timeout=3600)
        self.assertEqual(run.call_args.kwargs["timeout"], 42)


class TestUnknownScannerRejected(unittest.TestCase):
    def setUp(self):
        import pytest
        pytest.importorskip("fastapi")
        # The rate-limit bucket store is a module global shared across tests;
        # reset it so an earlier suite's writes don't drain it into a 429 here.
        import aegis.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()
        self.addCleanup(rl._BUCKETS.clear)

    def _client(self):
        from fastapi.testclient import TestClient

        from aegis.api.app import create_app
        from aegis.api.auth import CurrentUser, get_current_user
        from aegis.api.settings import APISettings
        app = create_app(APISettings(env="dev", auth_mode="dev",
                                     cors_origins=["http://localhost:3000"]))
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships={"proj-1": "scanner"})
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_unknown_scanner_returns_400(self):
        client = self._client()
        r = client.post("/v1/scans",
                        json={"project_id": "proj-1", "target": "localhost",
                              "scanner": "no-such-scanner"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("no-such-scanner", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
