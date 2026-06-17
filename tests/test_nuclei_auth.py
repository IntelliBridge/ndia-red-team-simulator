"""Authenticated DAST through the Nuclei adapter.

Nuclei replays a custom header natively via ``-H "Name: value"``: the
secret rides in the argv handed to ``subprocess.run`` only, while the
recorded ``command_str`` carries a redacted (``***``) copy.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

from aegis.scanners.registry import ScanOptions, get
from aegis.state import RunState

SECRET = "s3cr3t-value-do-not-log"


def _make_run_state(tmp: str) -> RunState:
    return RunState(tmp, run_id="test-run-001")


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr="")


def _assert_scan_never_ran(mock_run) -> None:
    """The scan argv must never reach subprocess.run.

    The error envelope still probes ``nuclei -version`` (also via the
    mocked subprocess.run), so filter to calls carrying the scan command.
    """
    scan_calls = [c for c in mock_run.call_args_list if "-target" in c.args[0]]
    assert scan_calls == []


def _scan(auth: dict | None, mock_run):
    adapter = get("nuclei")
    with tempfile.TemporaryDirectory() as tmp:
        rs = _make_run_state(tmp)
        extra = {"auth": auth} if auth is not None else {}
        return adapter.scan(rs, ScanOptions(target="http://localhost:3000",
                                            extra=extra))


def _argv(mock_run) -> list[str]:
    return mock_run.call_args.args[0]


class TestNucleiAuthInjection(unittest.TestCase):
    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_bearer_adds_authorization_header_flag(self, _w, mock_run):
        _scan({"kind": "bearer", "config": {}, "secret": SECRET}, mock_run)
        argv = _argv(mock_run)
        idx = argv.index("-H")
        self.assertEqual(argv[idx + 1], f"Authorization: Bearer {SECRET}")

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_header_kind_uses_configured_name(self, _w, mock_run):
        _scan({"kind": "header", "config": {"header_name": "X-Api-Key"},
               "secret": SECRET}, mock_run)
        argv = _argv(mock_run)
        idx = argv.index("-H")
        self.assertEqual(argv[idx + 1], f"X-Api-Key: {SECRET}")

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_cookie_kind_builds_cookie_header(self, _w, mock_run):
        _scan({"kind": "cookie", "config": {"cookie_name": "sid"},
               "secret": SECRET}, mock_run)
        argv = _argv(mock_run)
        idx = argv.index("-H")
        self.assertEqual(argv[idx + 1], f"Cookie: sid={SECRET}")

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_form_login_preflight_cookie_header(self, _w, mock_run):
        pytest.importorskip("httpx")
        resp = MagicMock()
        resp.status_code = 200
        resp.cookies = {"session": "abc123"}
        with patch("httpx.post", return_value=resp) as mock_post:
            _scan({"kind": "form",
                   "config": {"login_url": "http://localhost:3000/login",
                              "username_field": "email",
                              "password_field": "password",
                              "username": "a@b.c"},
                   "secret": SECRET}, mock_run)
        self.assertEqual(mock_post.call_args.kwargs["data"],
                         {"email": "a@b.c", "password": SECRET})
        argv = _argv(mock_run)
        idx = argv.index("-H")
        self.assertEqual(argv[idx + 1], "Cookie: session=abc123")

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_form_login_failure_errors_without_running_scan(self, _w, mock_run):
        pytest.importorskip("httpx")
        resp = MagicMock()
        resp.status_code = 403
        resp.cookies = {}
        with patch("httpx.post", return_value=resp):
            result = _scan({"kind": "form",
                            "config": {"login_url": "http://localhost/login",
                                       "username_field": "u",
                                       "password_field": "p",
                                       "username": "alice"},
                            "secret": SECRET}, mock_run)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("403", result.error)
        self.assertNotIn(SECRET, result.error)
        _assert_scan_never_ran(mock_run)

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_missing_header_name_errors_cleanly(self, _w, mock_run):
        result = _scan({"kind": "header", "config": {}, "secret": SECRET},
                       mock_run)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("header_name", result.error)
        self.assertNotIn(SECRET, result.error)
        _assert_scan_never_ran(mock_run)


class TestNucleiCommandRedaction(unittest.TestCase):
    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_command_str_is_redacted(self, _w, mock_run):
        result = _scan({"kind": "bearer", "config": {}, "secret": SECRET},
                       mock_run)
        self.assertIn('-H "Authorization: ***"', result.command_str)
        self.assertNotIn(SECRET, result.command_str)

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_header_kind_command_redacted(self, _w, mock_run):
        result = _scan({"kind": "header",
                        "config": {"header_name": "X-Api-Key"},
                        "secret": SECRET}, mock_run)
        self.assertIn('-H "X-Api-Key: ***"', result.command_str)
        self.assertNotIn(SECRET, result.command_str)

    @patch("subprocess.run", return_value=_completed(""))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_no_auth_command_unchanged(self, _w, mock_run):
        result = _scan(None, mock_run)
        self.assertEqual(
            result.command_str,
            "nuclei -target http://localhost:3000 -t cves,vulnerabilities")
        self.assertNotIn("-H", _argv(mock_run))


if __name__ == "__main__":
    unittest.main()
