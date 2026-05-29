import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.adapters.trivy_runner import parse_trivy_json, run_trivy

_TRIVY_SAMPLE = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "package-lock.json",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1111",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Title": "Prototype pollution",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "Description": "lodash before 4.17.21 has prototype pollution.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"],
                    "CweIDs": ["CWE-1321"],
                },
                {
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "express",
                    "InstalledVersion": "4.17.1",
                    "FixedVersion": "4.18.2",
                    "Title": "Open redirect",
                    "Severity": "MEDIUM",
                    "CVSS": {},
                    "Description": "",
                },
            ],
        }
    ],
}


class TestParseTrivyJson(unittest.TestCase):
    def test_converts_vulnerabilities(self):
        findings = parse_trivy_json(_TRIVY_SAMPLE, "run-1")
        self.assertEqual(len(findings), 2)
        ids = {f.id for f in findings}
        self.assertIn("CVE-2024-1111@lodash", ids)
        self.assertIn("CVE-2023-9999@express", ids)
        sev = {f.id: f.severity for f in findings}
        self.assertEqual(sev["CVE-2024-1111@lodash"], "high")
        self.assertEqual(sev["CVE-2023-9999@express"], "medium")

    def test_dependency_findings_have_package_info(self):
        findings = parse_trivy_json(_TRIVY_SAMPLE, "run-1")
        lodash = next(f for f in findings if "lodash" in f.id)
        self.assertEqual(lodash.package_name, "lodash")
        self.assertEqual(lodash.installed_version, "4.17.20")
        self.assertEqual(lodash.fixed_version, "4.17.21")
        self.assertTrue(lodash.is_dependency_finding)
        self.assertEqual(lodash.cvss, 7.5)

    def test_routable_to_vulnfixer(self):
        from aegis.adapters.vulnfixer_adapter import to_vulnfixer_vulnerability
        findings = parse_trivy_json(_TRIVY_SAMPLE, "run-1")
        lodash = next(f for f in findings if "lodash" in f.id)
        export = to_vulnfixer_vulnerability(lodash)
        self.assertTrue(export.routable_to_vulnfixer)
        self.assertEqual(export.payload["packageName"], "lodash")
        self.assertEqual(export.payload["installedVersion"], "4.17.20")
        self.assertEqual(export.payload["fixedVersion"], "4.17.21")


class TestRunTrivy(unittest.TestCase):
    def test_returns_error_when_repo_missing(self):
        result = run_trivy("/nonexistent/path/12345", run_id="r1")
        self.assertFalse(result.success)
        self.assertIn("repo not found", result.error)

    def test_parses_subprocess_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            output_dir = Path(tmp) / "out"
            with patch("aegis.adapters.trivy_runner.shutil.which", return_value="/fake/trivy"), \
                 patch("aegis.adapters.trivy_runner.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    ["trivy"], 0, stdout=json.dumps(_TRIVY_SAMPLE), stderr="",
                )
                result = run_trivy(repo, run_id="r1", output_dir=output_dir)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 2)
            self.assertTrue((output_dir / "trivy.json").exists())

    def test_handles_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            with patch("aegis.adapters.trivy_runner.shutil.which", return_value="/fake/trivy"), \
                 patch("aegis.adapters.trivy_runner.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    ["trivy"], 0, stdout="not json", stderr="",
                )
                result = run_trivy(repo, run_id="r1")
        self.assertFalse(result.success)
        self.assertIn("parse", result.error.lower())


if __name__ == "__main__":
    unittest.main()
