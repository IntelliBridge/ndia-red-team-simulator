import json
import unittest
from pathlib import Path

from aegis.scanners.grype_adapter import _convert
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestGrypeAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "grype_raw.json") as f:
            self.payload = json.load(f)
        self.matches = self.payload.get("matches", [])

    def test_convert_single_finding(self):
        result = _convert(self.matches[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "grype:CVE-2021-44228:log4j-core:2.14.1")
        self.assertEqual(result.title, "CVE-2021-44228 in log4j-core")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.finding_type, "dependency")
        self.assertEqual(result.source_tool, "grype")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "log4j-core")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.status, "open")
        self.assertIsNotNone(result.created_at)
        self.assertIsNotNone(result.updated_at)

    def test_dependency_fields(self):
        result = _convert(self.matches[0], "run-123")
        self.assertEqual(result.package_name, "log4j-core")
        self.assertEqual(result.installed_version, "2.14.1")
        self.assertEqual(result.fixed_version, "2.15.0")
        self.assertTrue(result.is_dependency_finding)

    def test_cve_passthrough(self):
        result = _convert(self.matches[0], "run-123")
        self.assertEqual(result.cve, "CVE-2021-44228")
        self.assertEqual(
            result.references,
            ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )

    def test_non_cve_id_and_severity_mapping(self):
        result = _convert(self.matches[1], "run-123")
        self.assertIsNone(result.cve)
        self.assertEqual(result.severity, "low")
        self.assertIsNone(result.fixed_version)

    def test_convert_all(self):
        findings = [_convert(m, "run-123") for m in self.matches]
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(isinstance(f, AegisFinding) for f in findings))


if __name__ == "__main__":
    unittest.main()
