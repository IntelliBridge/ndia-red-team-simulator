import unittest

from aegis.safety import AuthorizationError
from aegis.tools.kali_client import KaliClient


class TestKaliClientAllowlist(unittest.TestCase):
    def test_allows_exact_hostname(self):
        client = KaliClient(target_allowlist=["localhost"])
        client._check_target_allowed("http://localhost:3000")

    def test_rejects_substring_hostname_bypass(self):
        client = KaliClient(target_allowlist=["localhost"])
        with self.assertRaises(AuthorizationError):
            client._check_target_allowed("http://localhost.evil.example")

    def test_allows_cidr_match(self):
        client = KaliClient(target_allowlist=["127.0.0.0/8"])
        client._check_target_allowed("http://127.0.0.1:3000")


class TestKaliClientRunToolContract(unittest.TestCase):
    """Pin run_tool's asymmetric failure contract: an unknown tool
    returns a failed ToolResult (no raise); a disallowed target raises.
    Both short-circuit before _post, so neither touches the network.
    """

    def test_unknown_tool_returns_failed_result_without_raising(self):
        client = KaliClient(target_allowlist=["localhost"])
        result = client.run_tool("not-a-real-tool", {"target": "http://localhost"})
        self.assertFalse(result.success)
        self.assertEqual(result.return_code, -1)
        self.assertIn("allowed tools list", result.stderr)

    def test_disallowed_target_raises(self):
        client = KaliClient(target_allowlist=["localhost"])
        with self.assertRaises(AuthorizationError):
            client.run_tool("nmap", {"target": "http://evil.example"})


if __name__ == "__main__":
    unittest.main()