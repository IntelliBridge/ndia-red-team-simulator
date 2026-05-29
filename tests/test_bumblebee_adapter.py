import json
import unittest
from pathlib import Path
from unittest import mock

from aegis.scanners.bumblebee_adapter import BumblebeeAdapter, _convert
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestBumblebeeAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "bumblebee_raw.ndjson") as f:
            records = [json.loads(ln) for ln in f if ln.strip()]
        self.records = records
        self.findings = [r for r in records if r.get("type") == "finding"]
        self.packages = [r for r in records if r.get("type") == "package"]
        self.summaries = [r for r in records if r.get("type") == "scan_summary"]

    def test_convert_required_fields(self):
        record = self.findings[0]
        result = _convert(record, "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.finding_type, "supply_chain")
        self.assertEqual(result.source_tool, "bumblebee")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)
        self.assertEqual(result.affected_component, record["package"])
        self.assertEqual(result.id, record["id"])

    def test_severity_mapping(self):
        high = _convert(self.findings[0], "run-123")
        critical = _convert(self.findings[1], "run-123")
        self.assertEqual(self.findings[0]["severity"], "high")
        self.assertEqual(self.findings[1]["severity"], "critical")
        self.assertEqual(high.severity, "high")
        self.assertEqual(critical.severity, "critical")
        # Unknown severities must map to "low".
        bogus = _convert({"id": "BUMBLEBEE-9999", "severity": "bogus",
                          "package": "x"}, "run-123")
        self.assertEqual(bogus.severity, "low")

    def test_credential_not_leaked(self):
        record = next(r for r in self.findings if "redacted_credential" in r)
        self.assertEqual(record["redacted_credential"], "SENTINEL-DO-NOT-EMIT")
        result = _convert(record, "run-123")
        # The credential sentinel must not appear anywhere in the serialized finding.
        self.assertNotIn("SENTINEL-DO-NOT-EMIT", json.dumps(result.to_dict()))

    def test_package_and_summary_records_present(self):
        self.assertTrue(self.packages, "fixture is missing a 'package' record")
        self.assertTrue(self.summaries, "fixture is missing a 'scan_summary' record")

    def test_health_check_false_when_binary_absent(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertFalse(BumblebeeAdapter().health_check())


if __name__ == "__main__":
    unittest.main()
