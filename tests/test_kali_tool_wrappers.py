"""Coverage for the thin Kali tool wrappers added to the CAI toolbelt.

Mirrors the wrapper-test pattern in test_integrations_tools_coverage.py:
patch _maybe_import_function_tool with a passthrough decorator so the
wrappers are plain functions, build the toolbelt, find each by __name__,
and verify it routes through the audited KaliClient.run_tool plus
re-validates the target against the allowlist.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError
from aegis.tools.cai_tools import build_kali_toolbelt
from aegis.tools.kali_client import ToolResult


def _passthrough(fn):
    return fn


def _fake_cai_modules():
    """A sys.modules overlay that makes the optional CAI import succeed.

    ``_maybe_import_function_tool`` does ``from cai.sdk.agents import
    function_tool``; injecting these parent packages plus an ``agents``
    module exposing ``function_tool`` lets the real import resolve to our
    passthrough decorator, so the wrappers build as plain functions.
    """
    agents = types.ModuleType("cai.sdk.agents")
    agents.function_tool = _passthrough
    return {
        "cai": types.ModuleType("cai"),
        "cai.sdk": types.ModuleType("cai.sdk"),
        "cai.sdk.agents": agents,
    }


class TestKaliToolWrappers(unittest.TestCase):
    def _config(self):
        return AegisConfig(target_allowlist=["127.0.0.1", "localhost"])

    def _belt(self):
        with patch.dict(sys.modules, _fake_cai_modules()):
            return build_kali_toolbelt(self._config())

    def _tool(self, belt, name):
        return next(t for t in belt.tools if t.__name__ == name)

    def _ok(self):
        return ToolResult(success=True, stdout="ok", stderr="", return_code=0)

    # --- each new wrapper routes through run_tool and returns its dict ---

    def test_gobuster_scan_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "gobuster_scan")("127.0.0.1")
        self.assertIs(result["success"], True)

    def test_dirb_scan_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "dirb_scan")("127.0.0.1")
        self.assertIs(result["success"], True)

    def test_hydra_attack_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "hydra_attack")(target="127.0.0.1", service="ssh")
        self.assertIs(result["success"], True)

    def test_wpscan_scan_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "wpscan_scan")(url="http://localhost/")
        self.assertIs(result["success"], True)

    def test_enum4linux_scan_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "enum4linux_scan")("127.0.0.1")
        self.assertIs(result["success"], True)

    def test_metasploit_run_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "metasploit_run")(module="auxiliary/scanner/ssh/ssh_version")
        self.assertIs(result["success"], True)

    def test_john_crack_calls_run_tool(self):
        belt = self._belt()
        with patch.object(belt.client, "run_tool", return_value=self._ok()):
            result = self._tool(belt, "john_crack")(hash_file="/tmp/hashes.txt")
        self.assertIs(result["success"], True)

    # --- corrected param mappings sent to run_tool ---

    def _capture(self, belt, name, *args, **kwargs):
        mock = MagicMock(return_value=self._ok())
        with patch.object(belt.client, "run_tool", mock):
            self._tool(belt, name)(*args, **kwargs)
        return mock

    def test_gobuster_sends_url_and_default_mode(self):
        belt = self._belt()
        mock = self._capture(belt, "gobuster_scan", "127.0.0.1", wordlist="/w.txt")
        mock.assert_called_once_with(
            "gobuster", {"url": "127.0.0.1", "mode": "dir", "wordlist": "/w.txt"})

    def test_gobuster_invalid_mode_coerced_to_dir(self):
        belt = self._belt()
        mock = self._capture(belt, "gobuster_scan", "127.0.0.1", mode="../etc")
        self.assertEqual(mock.call_args.args[1]["mode"], "dir")
        self.assertEqual(mock.call_args.args[1]["url"], "127.0.0.1")
        self.assertNotIn("target", mock.call_args.args[1])

    def test_gobuster_valid_modes_pass_through(self):
        for mode in ("dns", "vhost", "fuzz"):
            belt = self._belt()
            mock = self._capture(belt, "gobuster_scan", "127.0.0.1", mode=mode)
            self.assertEqual(mock.call_args.args[1]["mode"], mode)

    def test_dirb_sends_url_not_target(self):
        belt = self._belt()
        mock = self._capture(belt, "dirb_scan", "127.0.0.1", wordlist="/w.txt")
        mock.assert_called_once_with(
            "dirb", {"url": "127.0.0.1", "wordlist": "/w.txt"})
        self.assertNotIn("target", mock.call_args.args[1])

    def test_hydra_sends_real_credential_keys(self):
        belt = self._belt()
        mock = self._capture(
            belt, "hydra_attack", target="127.0.0.1", service="ssh",
            username="root", username_file="/u.txt",
            password="pw", password_file="/p.txt")
        mock.assert_called_once_with("hydra", {
            "target": "127.0.0.1", "service": "ssh",
            "username": "root", "username_file": "/u.txt",
            "password": "pw", "password_file": "/p.txt"})
        params = mock.call_args.args[1]
        self.assertNotIn("userlist", params)
        self.assertNotIn("passlist", params)

    def test_hydra_omits_unset_credential_keys(self):
        belt = self._belt()
        mock = self._capture(
            belt, "hydra_attack", target="127.0.0.1", service="ssh",
            password_file="/p.txt")
        mock.assert_called_once_with("hydra", {
            "target": "127.0.0.1", "service": "ssh", "password_file": "/p.txt"})

    def test_metasploit_folds_rhosts_into_options(self):
        belt = self._belt()
        mock = self._capture(
            belt, "metasploit_run",
            module="auxiliary/scanner/ssh/ssh_version",
            rhosts="127.0.0.1", options={"THREADS": 4})
        mock.assert_called_once_with("metasploit", {
            "module": "auxiliary/scanner/ssh/ssh_version",
            "options": {"THREADS": 4, "RHOSTS": "127.0.0.1"}})
        params = mock.call_args.args[1]
        self.assertNotIn("rhosts", params)

    def test_metasploit_without_rhosts_sends_empty_options(self):
        belt = self._belt()
        mock = self._capture(
            belt, "metasploit_run", module="exploit/multi/handler")
        mock.assert_called_once_with(
            "metasploit", {"module": "exploit/multi/handler", "options": {}})

    def test_metasploit_checks_rhosts_against_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "metasploit_run")(
                module="auxiliary/scanner/ssh/ssh_version", rhosts="192.168.99.1")

    def test_john_sends_format_when_given(self):
        belt = self._belt()
        mock = self._capture(
            belt, "john_crack", hash_file="/tmp/h.txt", format_type="md5crypt")
        mock.assert_called_once_with(
            "john", {"hash_file": "/tmp/h.txt", "format": "md5crypt"})

    def test_john_omits_format_when_absent(self):
        belt = self._belt()
        mock = self._capture(belt, "john_crack", hash_file="/tmp/h.txt")
        self.assertNotIn("format", mock.call_args.args[1])

    # --- allowlist enforcement on target-bearing wrappers ---

    def test_gobuster_scan_enforces_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "gobuster_scan")("192.168.99.1")

    def test_dirb_scan_enforces_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "dirb_scan")("192.168.99.1")

    def test_hydra_attack_enforces_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "hydra_attack")(target="192.168.99.1", service="ssh")

    def test_wpscan_scan_enforces_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "wpscan_scan")(url="http://192.168.99.1/")

    def test_enum4linux_scan_enforces_allowlist(self):
        belt = self._belt()
        with self.assertRaises(AuthorizationError):
            self._tool(belt, "enum4linux_scan")("192.168.99.1")

    # --- toolbelt now exposes all 10 wrappers ---

    def test_toolbelt_has_ten_tools(self):
        belt = self._belt()
        self.assertEqual(len(belt.tools), 10)
        names = {t.__name__ for t in belt.tools}
        expected = {
            "nmap_scan", "nikto_scan", "sqlmap_test", "gobuster_scan", "dirb_scan",
            "hydra_attack", "wpscan_scan", "enum4linux_scan", "metasploit_run",
            "john_crack",
        }
        self.assertEqual(names, expected)


if __name__ == "__main__":
    unittest.main()
