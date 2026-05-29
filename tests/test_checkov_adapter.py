import json
import unittest
from pathlib import Path

from aegis.scanners.checkov_adapter import _convert
from aegis.schema import AegisFinding, CodeLocation

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestCheckovAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "checkov_raw.json") as f:
            payload = json.load(f)
        self.checks = payload["results"]["failed_checks"]

    def test_convert_single_finding(self):
        result = _convert(self.checks[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "checkov:CKV_AWS_18:/terraform/s3.tf:aws_s3_bucket.data")
        self.assertEqual(result.title, "Ensure the S3 bucket has access logging enabled")
        self.assertEqual(result.finding_type, "config")
        self.assertEqual(result.source_tool, "checkov")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "/terraform/s3.tf")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)

    def test_affected_component_is_file_path(self):
        result = _convert(self.checks[0], "run-123")
        self.assertEqual(result.affected_component, self.checks[0]["file_path"])

    def test_severity_defaults_medium_when_null(self):
        result = _convert(self.checks[0], "run-123")
        self.assertEqual(result.severity, "medium")

    def test_severity_mapping(self):
        result = _convert(self.checks[1], "run-123")
        self.assertEqual(result.severity, "high")

    def test_code_locations_from_line_range(self):
        result = _convert(self.checks[0], "run-123")
        self.assertIsNotNone(result.code_locations)
        self.assertEqual(len(result.code_locations), 1)
        loc = result.code_locations[0]
        self.assertIsInstance(loc, CodeLocation)
        self.assertEqual(loc.file, "/terraform/s3.tf")
        self.assertEqual(loc.start_line, 1)
        self.assertEqual(loc.end_line, 4)

    def test_references_from_guideline(self):
        result = _convert(self.checks[0], "run-123")
        self.assertEqual(
            result.references,
            ["https://docs.bridgecrew.io/docs/s3_13-enable-logging"],
        )


if __name__ == "__main__":
    unittest.main()
