import json
import tempfile
import unittest
from pathlib import Path

from redsim.safety import (
    AuthorizationError,
    authorize,
    is_loopback,
    is_target_allowed,
)


class TestTargetAllowlist(unittest.TestCase):
    def test_exact_host(self):
        self.assertTrue(is_target_allowed("http://localhost:3000", ["localhost"]))

    def test_substring_does_not_match(self):
        self.assertFalse(is_target_allowed("http://localhost.evil.example", ["localhost"]))

    def test_cidr(self):
        self.assertTrue(is_target_allowed("http://127.0.0.1:3000", ["127.0.0.0/8"]))
        self.assertFalse(is_target_allowed("http://10.0.0.1", ["127.0.0.0/8"]))

    def test_bare_host(self):
        self.assertTrue(is_target_allowed("localhost:5000", ["localhost"]))


class TestLoopback(unittest.TestCase):
    def test_loopback_names(self):
        self.assertTrue(is_loopback("http://localhost"))
        self.assertTrue(is_loopback("http://host.docker.internal:3000"))
        self.assertTrue(is_loopback("127.0.0.1"))

    def test_non_loopback(self):
        self.assertFalse(is_loopback("http://8.8.8.8"))
        self.assertFalse(is_loopback("http://example.com"))


class TestAuthorize(unittest.TestCase):
    def test_target_none_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            authorize("patch.apply", None, allowlist=["localhost"], run_path=run_path)
            lines = (run_path / "audit.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["action"], "patch.apply")
            self.assertEqual(record["target"], None)
            self.assertEqual(record["allowlist_check"], "n/a")
            self.assertTrue(record["success"])

    def test_allowed_target_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            authorize("strix.run", "http://localhost:3000",
                     allowlist=["localhost"], run_path=run_path)
            record = json.loads((run_path / "audit.jsonl").read_text().strip())
            self.assertEqual(record["allowlist_check"], "pass")
            self.assertTrue(record["success"])

    def test_blocked_target_raises_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            with self.assertRaises(AuthorizationError):
                authorize("strix.run", "http://8.8.8.8",
                         allowlist=["localhost"], run_path=run_path)
            record = json.loads((run_path / "audit.jsonl").read_text().strip())
            self.assertEqual(record["allowlist_check"], "fail")
            self.assertFalse(record["success"])

    def test_override_authorizes_non_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            authorize("strix.run", "http://example.com",
                     allowlist=["localhost"], run_path=run_path,
                     override_authorized=True)
            record = json.loads((run_path / "audit.jsonl").read_text().strip())
            self.assertEqual(record["allowlist_check"], "override")
            self.assertTrue(record["override"])
            self.assertTrue(record["success"])

    def test_appends_multiple_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            authorize("a", "localhost", allowlist=["localhost"], run_path=run_path)
            authorize("b", "localhost", allowlist=["localhost"], run_path=run_path)
            lines = (run_path / "audit.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
