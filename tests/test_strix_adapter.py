import json
import tempfile
import unittest
from pathlib import Path

from aegis.adapters.strix_adapter import convert_strix_finding, convert_strix_findings, load_strix_events
from aegis.schema import AegisFinding, CodeLocation

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrixAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "strix_finding.json") as f:
            self.raw = json.load(f)
        with open(FIXTURES / "aegis_finding_expected.json") as f:
            self.expected = json.load(f)

    def test_convert_single_finding(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "vuln-0001")
        self.assertEqual(result.title, "SQL Injection in Login Form")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.finding_type, "dast")
        self.assertEqual(result.source_tool, "strix")
        self.assertEqual(result.source_run_id, "test-run-001")
        self.assertEqual(result.affected_component, "/rest/user/login")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.status, "open")
        self.assertEqual(result.cvss, 9.8)
        self.assertEqual(result.cwe, "CWE-89")

    def test_code_locations_converted(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertIsNotNone(result.code_locations)
        self.assertEqual(len(result.code_locations), 1)
        loc = result.code_locations[0]
        self.assertIsInstance(loc, CodeLocation)
        self.assertEqual(loc.file, "routes/login.js")
        self.assertEqual(loc.start_line, 42)
        self.assertIsNotNone(loc.fix_after)

    def test_not_dependency_finding(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertFalse(result.is_dependency_finding)

    def test_convert_multiple(self):
        results = convert_strix_findings([self.raw, self.raw], "test-run-001")
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], AegisFinding)

    def test_roundtrip_matches_expected(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        d = result.to_dict()
        # Check key fields match expected fixture
        self.assertEqual(d["id"], self.expected["id"])
        self.assertEqual(d["finding_type"], self.expected["finding_type"])
        self.assertEqual(d["source_tool"], self.expected["source_tool"])
        self.assertEqual(d["affected_component"], self.expected["affected_component"])

    def test_load_strix_events_actual_payload_report_shape(self):
        event = {
            "event_type": "finding.created",
            "run_id": "strix-run",
            "payload": {"report": self.raw},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")

            results = load_strix_events(str(events_path), "test-run-001")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "vuln-0001")
        self.assertEqual(results[0].source_run_id, "test-run-001")

    def test_load_strix_events_legacy_data_shape(self):
        event = {"event_type": "finding.created", "data": self.raw}
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")

            results = load_strix_events(str(events_path), "test-run-001")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "vuln-0001")


if __name__ == "__main__":
    unittest.main()
