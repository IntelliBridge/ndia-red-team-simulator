"""M6 multi-scanner dispatch (offline-safe).

Covers the seams finished in M6:

  (a) ``start_scan`` routes every scanner through the registry ``dispatch``
      and maps the returned ``ScanResult`` into a ``ScanOutcome``;
  (b) an unregistered scanner surfaces a ``KeyError`` whose message names the
      missing adapter and points at ``redsim.ml.attacks`` (the pentest engines
      were removed; the ML attack adapters register in the same registry);
  (c) ``POST /v1/scans`` is unmounted (M0): the path answers 404 and no
      Run/Job row is created;
  (d) ``run_cli_scan`` falls back to an adapter's ``default_timeout`` when the
      caller leaves ``ScanOptions.timeout`` at its sentinel default.

No scanner binary, broker, or DB is touched: ``dispatch`` /
``subprocess.run`` are mocked at their boundaries.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from redsim.config import RedsimConfig
from redsim.scanners.registry import ScanOptions, ScanResult, run_cli_scan
from redsim.services.scans import ScanOutcome, start_scan


def _run_state() -> MagicMock:
    rs = MagicMock()
    rs.run_path = "/tmp/run"
    rs.run_id = "test-run-001"
    return rs


def _completed(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="{}", stderr="")


class TestStartScanDispatch(unittest.TestCase):
    def setUp(self):
        self.config = RedsimConfig(target_allowlist=["localhost"])

    def test_scanner_dispatches_and_maps_result(self):
        state = _run_state()
        result = ScanResult(
            findings=[], adapter_name="semgrep", adapter_version="1.2.3",
            command_str="semgrep --json /repo", exit_code=0,
            duration_s=4.2, error=None,
        )
        with patch("redsim.scanners.dispatch", return_value=result) as dispatch, \
             patch("redsim.safety.authorize"):
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

    def test_partial_success_when_findings_with_nonzero_exit(self):
        state = _run_state()
        finding = MagicMock()
        result = ScanResult(
            findings=[finding], adapter_name="semgrep", adapter_version="1",
            command_str="semgrep", exit_code=1, duration_s=1.0, error=None,
        )
        with patch("redsim.scanners.dispatch", return_value=result), \
             patch("redsim.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                actor="cli:scan", config=self.config,
            )
        self.assertFalse(outcome.success)
        self.assertTrue(outcome.partial_success)
        self.assertEqual(outcome.return_code, 1)

    def test_error_marks_failure(self):
        state = _run_state()
        result = ScanResult(
            findings=[], adapter_name="semgrep", adapter_version="1",
            command_str="semgrep", exit_code=0, duration_s=0.0,
            error="boom",
        )
        with patch("redsim.scanners.dispatch", return_value=result), \
             patch("redsim.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="semgrep",
                actor="cli:scan", config=self.config,
            )
        self.assertFalse(outcome.success)
        self.assertFalse(outcome.partial_success)
        self.assertEqual(outcome.error, "boom")

    def test_explicit_scanner_name_routes_through_registry(self):
        # There is no default scanner: every caller names the adapter and the
        # name is handed to the registry verbatim.
        state = _run_state()
        result = ScanResult(
            findings=[], adapter_name="fake-evasion", adapter_version="1",
            command_str="fake-evasion", exit_code=0, duration_s=0.0, error=None,
        )
        with patch("redsim.scanners.dispatch", return_value=result) as dispatch, \
             patch("redsim.safety.authorize"):
            outcome = start_scan(
                run_state=state, target="localhost", scanner="fake-evasion",
                actor="cli:scan", config=self.config,
            )
        self.assertEqual(dispatch.call_args[0][0], "fake-evasion")
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.scanner, "fake-evasion")

    def test_start_scan_has_no_default_scanner(self):
        import inspect
        param = inspect.signature(start_scan).parameters["scanner"]
        self.assertIs(param.default, inspect.Parameter.empty)
        self.assertNotIn("use_strix", inspect.signature(start_scan).parameters)

    def test_unregistered_scanner_raises_keyerror_naming_the_adapter(self):
        # With no adapter registered, the live registry raises KeyError — an
        # explicit failure, never a silent success or a faked result — and the
        # message names the missing adapter and where the ML adapters register.
        state = _run_state()
        with patch("redsim.safety.authorize"), self.assertRaises(KeyError) as cm:
            start_scan(
                run_state=state, target="localhost",
                scanner="no-such-adapter-m6",
                actor="cli:scan", config=self.config,
            )
        message = str(cm.exception)
        self.assertIn("no-such-adapter-m6", message)
        self.assertIn("redsim.ml.attacks", message)
        self.assertIn("available", message)


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
        import redsim.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()
        self.addCleanup(rl._BUCKETS.clear)

    def _client(self):
        from fastapi.testclient import TestClient

        from redsim.api.app import create_app
        from redsim.api.auth import CurrentUser, get_current_user
        from redsim.api.settings import APISettings
        app = create_app(APISettings(env="dev", auth_mode="dev",
                                     cors_origins=["http://localhost:3000"]))
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships={"proj-1": "scanner"})
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_scans_route_is_unmounted(self):
        client = self._client()
        r = client.post("/v1/scans",
                        json={"project_id": "proj-1", "target": "localhost",
                              "scanner": "no-such-scanner"})
        self.assertEqual(r.status_code, 404)
        paths = set(client.app.openapi()["paths"])
        self.assertNotIn("/v1/scans", paths)
        self.assertIn("/v1/scanners", paths)


if __name__ == "__main__":
    unittest.main()
