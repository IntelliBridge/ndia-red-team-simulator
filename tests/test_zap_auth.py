"""Authenticated DAST through the ZAP adapter.

The resolved auth dict arrives in ``ScanOptions.extra["auth"]``; the adapter
turns it into a single replayable header and hands it to zap-cli via the
``ZAP_AUTH_HEADER`` / ``ZAP_AUTH_HEADER_VALUE`` env vars on the subprocess.

Invariants under test:
  - each auth kind yields the right env-var pair;
  - the form kind performs a pre-flight login POST and folds the returned
    cookies into the header (HTTP mocked);
  - the recorded ``command_str``, error strings, and persisted artifacts
    never contain the secret (only the redacted ``***`` marker);
  - the no-auth path is byte-for-byte unchanged.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.scanners.registry import ScanOptions, get
from aegis.state import RunState

SECRET = "s3cr3t-value-do-not-log"

ZAP_EMPTY = '{"site": []}'


def _make_run_state(tmp: str) -> RunState:
    return RunState(tmp, run_id="test-run-001")


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr="")


def _assert_scan_never_ran(mock_run) -> None:
    """The scan argv must never reach subprocess.run.

    The error envelope still probes ``zap-cli --version`` (also via the
    mocked subprocess.run), so filter to calls carrying the scan command.
    """
    scan_calls = [c for c in mock_run.call_args_list if "report" in c.args[0]]
    assert scan_calls == []


def _scan(auth: dict | None, mock_run):
    adapter = get("zap")
    with tempfile.TemporaryDirectory() as tmp:
        rs = _make_run_state(tmp)
        extra = {"auth": auth} if auth is not None else {}
        result = adapter.scan(rs, ScanOptions(target="http://localhost:3000",
                                              extra=extra))
        raw = Path(tmp) / "runs" / "test-run-001" / "zap" / "report.json"
        raw_text = raw.read_text() if raw.exists() else ""
    return result, raw_text


class TestZapAuthInjection(unittest.TestCase):
    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_bearer_sets_authorization_env(self, _w, mock_run):
        result, _ = _scan({"kind": "bearer", "config": {}, "secret": SECRET},
                          mock_run)
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(env["ZAP_AUTH_HEADER"], "Authorization")
        self.assertEqual(env["ZAP_AUTH_HEADER_VALUE"], f"Bearer {SECRET}")
        # env is merged over os.environ so the subprocess keeps PATH etc.
        self.assertIn("PATH", env)
        self.assertIsNone(result.error)

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_header_kind_uses_configured_name(self, _w, mock_run):
        _scan({"kind": "header", "config": {"header_name": "X-Api-Key"},
               "secret": SECRET}, mock_run)
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(env["ZAP_AUTH_HEADER"], "X-Api-Key")
        self.assertEqual(env["ZAP_AUTH_HEADER_VALUE"], SECRET)

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_cookie_kind_builds_cookie_header(self, _w, mock_run):
        _scan({"kind": "cookie", "config": {"cookie_name": "sid"},
               "secret": SECRET}, mock_run)
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(env["ZAP_AUTH_HEADER"], "Cookie")
        self.assertEqual(env["ZAP_AUTH_HEADER_VALUE"], f"sid={SECRET}")

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_form_login_preflight_captures_cookies(self, _w, mock_run):
        pytest.importorskip("httpx")
        resp = MagicMock()
        resp.status_code = 302
        resp.cookies = {"JSESSIONID": "abc123", "csrft": "xyz"}
        with patch("httpx.post", return_value=resp) as mock_post:
            _scan({"kind": "form",
                   "config": {"login_url": "http://localhost:3000/login",
                              "username_field": "user",
                              "password_field": "pass",
                              "username": "alice"},
                   "secret": SECRET}, mock_run)
        # Pre-flight POST carried the credentials as form data.
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args.args[0],
                         "http://localhost:3000/login")
        self.assertEqual(mock_post.call_args.kwargs["data"],
                         {"user": "alice", "pass": SECRET})
        # Captured Set-Cookie values became the replayed Cookie header.
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(env["ZAP_AUTH_HEADER"], "Cookie")
        self.assertEqual(env["ZAP_AUTH_HEADER_VALUE"],
                         "JSESSIONID=abc123; csrft=xyz")

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_form_login_rejection_fails_without_running_scan(self, _w, mock_run):
        pytest.importorskip("httpx")
        resp = MagicMock()
        resp.status_code = 401
        resp.cookies = {}
        with patch("httpx.post", return_value=resp):
            result, _ = _scan({"kind": "form",
                               "config": {"login_url": "http://localhost/login",
                                          "username_field": "user",
                                          "password_field": "pass",
                                          "username": "alice"},
                               "secret": SECRET}, mock_run)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("401", result.error)
        self.assertNotIn(SECRET, result.error)
        _assert_scan_never_ran(mock_run)

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_form_login_connection_error_is_secret_free(self, _w, mock_run):
        httpx = pytest.importorskip("httpx")
        with patch("httpx.post",
                   side_effect=httpx.ConnectError("refused")):
            result, _ = _scan({"kind": "form",
                               "config": {"login_url": "http://localhost/login",
                                          "username_field": "user",
                                          "password_field": "pass",
                                          "username": "alice"},
                               "secret": SECRET}, mock_run)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("ConnectError", result.error)
        self.assertNotIn(SECRET, result.error)
        _assert_scan_never_ran(mock_run)

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_unsupported_kind_errors_cleanly(self, _w, mock_run):
        result, _ = _scan({"kind": "magic", "config": {}, "secret": SECRET},
                          mock_run)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("magic", result.error)
        self.assertNotIn(SECRET, result.error)
        _assert_scan_never_ran(mock_run)


class TestZapAuthRedaction(unittest.TestCase):
    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_command_and_artifacts_never_contain_secret(self, _w, mock_run):
        result, raw_text = _scan(
            {"kind": "bearer", "config": {}, "secret": SECRET}, mock_run)
        # Recorded command carries the redaction marker, never the value.
        self.assertIn("ZAP_AUTH_HEADER_VALUE=***", result.command_str)
        self.assertNotIn(SECRET, result.command_str)
        self.assertNotIn(SECRET, raw_text)
        # Only env *names* are recorded on the result.
        self.assertEqual(result.env_keys,
                         ["ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE"])
        self.assertNotIn(SECRET, str(result.env_keys))

    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_argv_never_contains_secret(self, _w, mock_run):
        _scan({"kind": "bearer", "config": {}, "secret": SECRET}, mock_run)
        argv = mock_run.call_args.args[0]
        self.assertNotIn(SECRET, " ".join(argv))


class TestZapNoAuthPathUnchanged(unittest.TestCase):
    @patch("subprocess.run", return_value=_completed(ZAP_EMPTY))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_no_auth_keeps_legacy_command_and_no_env(self, _w, mock_run):
        result, _ = _scan(None, mock_run)
        self.assertEqual(result.command_str,
                         "zap-cli report -o - -f json http://localhost:3000")
        self.assertIsNone(mock_run.call_args.kwargs["env"])
        self.assertEqual(result.env_keys, [])


if __name__ == "__main__":
    unittest.main()
