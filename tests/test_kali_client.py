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


if __name__ == "__main__":
    unittest.main()