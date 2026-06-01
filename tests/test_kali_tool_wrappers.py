"""Coverage for the thin Kali tool wrappers added to the CAI toolbelt.

Mirrors the wrapper-test pattern in test_integrations_tools_coverage.py:
patch _maybe_import_function_tool with a passthrough decorator so the
wrappers are plain functions, build the toolbelt, find each by __name__,
and verify it routes through the audited KaliClient.run_tool plus
re-validates the target against the allowlist.
"""

import unittest
from unittest.mock import patch

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError
from aegis.tools.cai_tools import build_kali_toolbelt
from aegis.tools.kali_client import ToolResult


def _passthrough(fn):
    return fn


class TestKaliToolWrappers(unittest.TestCase):
    def _config(self):
        return AegisConfig(target_allowlist=["127.0.0.1", "localhost"])

    def _belt(self):
        with patch("aegis.tools.cai_tools._maybe_import_function_tool",
                   return_value=_passthrough):
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
