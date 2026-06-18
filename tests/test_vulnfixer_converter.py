import json
import tempfile
import unittest
from pathlib import Path

from aegis.runners.vulnfixer_converter import export_findings, to_vulnfixer_vulnerability
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures"


class TestVulnfixerAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "aegis_finding_expected.json") as f:
            self.dast_finding = AegisFinding.from_dict(json.load(f))

        # Create a dependency finding for testing the routable path
        self.dep_finding = AegisFinding(
            id="vuln-dep-001",
            title="CVE-2024-1234 in lodash",
            severity="high",
            finding_type="dependency",
            description="Prototype pollution in lodash < 4.17.21",
            source_tool="strix",
            source_run_id="test-run-001",
            affected_component="lodash",
            confidence="high",
            status="open",
            created_at="2026-05-27T10:30:00Z",
            updated_at="2026-05-27T10:30:00Z",
            cve="CVE-2024-1234",
            cvss=7.5,
            package_name="lodash",
            installed_version="4.17.20",
            fixed_version="4.17.21",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        )

    def test_dast_finding_not_routable(self):
        """DAST/appsec findings should NOT be routable to vulnerability-fixer."""
        result = to_vulnfixer_vulnerability(self.dast_finding)
        self.assertFalse(result.routable_to_vulnfixer)
        self.assertTrue(result.requires_code_fix)
        self.assertIsNone(result.payload)
        self.assertIn("Appsec finding", result.reason)

    def test_dependency_finding_routable(self):
        """Dependency findings with package info should be routable."""
        result = to_vulnfixer_vulnerability(self.dep_finding)
        self.assertTrue(result.routable_to_vulnfixer)
        self.assertFalse(result.requires_code_fix)
        self.assertIsNotNone(result.payload)

        payload = result.payload
        self.assertEqual(payload["cveId"], "CVE-2024-1234")
        self.assertEqual(payload["packageName"], "lodash")
        self.assertEqual(payload["installedVersion"], "4.17.20")
        self.assertEqual(payload["fixedVersion"], "4.17.21")
        self.assertEqual(payload["severity"], "HIGH")
        self.assertTrue(payload["vulnerable"])
        self.assertFalse(payload["fixed"])

    def test_export_mixed_findings(self):
        """Export should separate routable and code-fix findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "export.json"
            summary = export_findings([self.dast_finding, self.dep_finding], out)

            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["routable_to_vulnfixer"], 1)
            self.assertEqual(summary["requires_code_fix"], 1)

            with open(out) as f:
                data = json.load(f)
            self.assertEqual(len(data["vulnerabilities"]), 1)
            self.assertEqual(len(data["code_fix_required"]), 1)
            self.assertEqual(data["vulnerabilities"][0]["packageName"], "lodash")

    def test_fixture_matches_expected(self):
        """Verify DAST finding result matches the expected fixture."""
        with open(FIXTURES / "vulnfixer_payload_expected.json") as f:
            expected = json.load(f)
        result = to_vulnfixer_vulnerability(self.dast_finding)
        self.assertEqual(result.routable_to_vulnfixer, expected["routable_to_vulnfixer"])
        self.assertEqual(result.requires_code_fix, expected["requires_code_fix"])
        self.assertIn(expected["reason"], result.reason)


if __name__ == "__main__":
    unittest.main()
