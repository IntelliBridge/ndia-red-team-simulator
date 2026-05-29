import json
import unittest
from pathlib import Path

from aegis.scanners.bandit_adapter import _convert
from aegis.schema import AegisFinding, CodeLocation

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestBanditAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "bandit_raw.json") as f:
            self.payload = json.load(f)
        self.results = self.payload.get("results", [])

    def test_convert_single_finding(self):
        result = _convert(self.results[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "bandit:B105:app/auth.py:42")
        self.assertEqual(result.title, "hardcoded_password_string")
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.finding_type, "sast")
        self.assertEqual(result.source_tool, "bandit")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "app/auth.py")
        self.assertEqual(result.confidence, "medium")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)

    def test_cwe_passthrough(self):
        result = _convert(self.results[0], "run-123")
        self.assertEqual(result.cwe, "CWE-259")

    def test_code_locations(self):
        result = _convert(self.results[0], "run-123")
        self.assertIsNotNone(result.code_locations)
        self.assertEqual(len(result.code_locations), 1)
        loc = result.code_locations[0]
        self.assertIsInstance(loc, CodeLocation)
        self.assertEqual(loc.file, "app/auth.py")
        self.assertEqual(loc.start_line, 42)
        self.assertEqual(loc.end_line, 42)
        self.assertIn("admin123", loc.snippet)

    def test_severity_confidence_mapping(self):
        low = _convert(self.results[1], "run-123")
        self.assertEqual(low.severity, "low")
        self.assertEqual(low.confidence, "high")

    def test_convert_all(self):
        findings = [_convert(r, "run-123") for r in self.results]
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(isinstance(f, AegisFinding) for f in findings))


if __name__ == "__main__":
    unittest.main()
