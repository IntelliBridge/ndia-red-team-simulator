import json
import unittest
from pathlib import Path

from aegis.scanners.trufflehog_adapter import _convert
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestTrufflehogAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "trufflehog_raw.jsonl") as f:
            self.records = [json.loads(ln) for ln in f if ln.strip()]

    def test_convert_single_finding(self):
        result = _convert(self.records[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "trufflehog:AWS:/app/config/secrets.env:12")
        self.assertEqual(result.title, "AWS secret")
        self.assertEqual(result.finding_type, "runtime")
        self.assertEqual(result.source_tool, "trufflehog")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "/app/config/secrets.env")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)

    def test_verified_secret_is_high(self):
        result = _convert(self.records[0], "run-123")
        self.assertTrue(self.records[0]["Verified"])
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.confidence, "high")

    def test_unverified_secret_is_medium(self):
        result = _convert(self.records[1], "run-123")
        self.assertFalse(self.records[1]["Verified"])
        self.assertEqual(result.severity, "medium")
        self.assertEqual(result.confidence, "medium")

    def test_git_source_metadata_file(self):
        result = _convert(self.records[1], "run-123")
        self.assertEqual(result.affected_component, "/app/.git/config")
        self.assertEqual(result.id, "trufflehog:Github:/app/.git/config:3")

    def test_raw_secret_not_leaked(self):
        result = _convert(self.records[0], "run-123")
        self.assertEqual(result.evidence, "<redacted>")
        raw = self.records[0]["Raw"]
        self.assertNotIn(raw, result.evidence)
        # The raw secret must not appear anywhere in the serialized finding.
        self.assertNotIn(raw, json.dumps(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
