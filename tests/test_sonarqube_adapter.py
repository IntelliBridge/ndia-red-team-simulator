import json
import tempfile
import unittest
from pathlib import Path

from aegis.scanners.registry import ScanOptions
from aegis.scanners.sonarqube_adapter import SonarQubeAdapter, _convert
from aegis.schema import AegisFinding
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestSonarQubeAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "sonarqube_raw.json") as f:
            self.payload = json.load(f)
        self.issues = self.payload["issues"]

    def test_convert_required_fields(self):
        result = _convert(self.issues[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "sonarqube:AY1a2b3c4d5e6f7g8h9i")
        self.assertEqual(result.title,
                         "Make sure that executing this OS command is safe here.")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.finding_type, "sast")
        self.assertEqual(result.source_tool, "sonarqube")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "demo-proj:src/app.py")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)

    def test_severity_mapping(self):
        blocker = _convert(self.issues[0], "run-123")
        minor = _convert(self.issues[1], "run-123")
        self.assertEqual(blocker.severity, "critical")
        self.assertEqual(minor.severity, "low")
        self.assertEqual(_convert({"key": "k", "severity": "CRITICAL"},
                                  "r").severity, "high")
        self.assertEqual(_convert({"key": "k", "severity": "MAJOR"},
                                  "r").severity, "medium")
        self.assertEqual(_convert({"key": "k", "severity": "INFO"},
                                  "r").severity, "low")

    def test_convert_all(self):
        results = [_convert(i, "run-123") for i in self.issues]
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, AegisFinding) for r in results))

    def test_scan_no_host_returns_error(self, ):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            rs = RunState(tmp, run_id="run-123")
            saved = os.environ.pop("SONAR_HOST_URL", None)
            try:
                result = SonarQubeAdapter().scan(rs, ScanOptions(target="x"))
            finally:
                if saved is not None:
                    os.environ["SONAR_HOST_URL"] = saved
            self.assertEqual(result.findings, [])
            self.assertIsNotNone(result.error)
            self.assertIn("SONAR_HOST_URL", result.error)


if __name__ == "__main__":
    unittest.main()
