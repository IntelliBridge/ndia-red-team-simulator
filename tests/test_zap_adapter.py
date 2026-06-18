import json
import unittest
from pathlib import Path

from aegis.scanners.zap_adapter import _convert, _extract_alerts
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestZapAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "zap_raw.json") as f:
            self.payload = json.load(f)
        self.alerts = _extract_alerts(self.payload)

    def test_extract_alerts(self):
        self.assertEqual(len(self.alerts), 2)

    def test_convert_required_fields(self):
        result = _convert(self.alerts[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "zap:40018:https://juice-shop.example.com/rest/user/login")
        self.assertEqual(result.title, "SQL Injection")
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.finding_type, "dast")
        self.assertEqual(result.source_tool, "zap")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component,
                         "https://juice-shop.example.com/rest/user/login")
        self.assertEqual(result.status, "open")

    def test_tool_specific_fields(self):
        result = _convert(self.alerts[0], "run-123")
        self.assertEqual(result.endpoint,
                         "https://juice-shop.example.com/rest/user/login")
        self.assertEqual(result.method, "POST")
        self.assertEqual(result.cwe, "89")

    def test_severity_mapping(self):
        high = _convert(self.alerts[0], "run-123")
        low = _convert(self.alerts[1], "run-123")
        self.assertEqual(high.severity, "high")
        self.assertEqual(low.severity, "low")

    def test_convert_all(self):
        results = [_convert(a, "run-123") for a in self.alerts]
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, AegisFinding) for r in results))


if __name__ == "__main__":
    unittest.main()
