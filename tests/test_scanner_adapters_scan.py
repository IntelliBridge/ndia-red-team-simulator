"""Behavioral tests for all scanner adapter scan() / health_check() methods.

Covers:
  - Happy-path scan(): subprocess.run returning schema-accurate JSON / JSONL
  - TimeoutExpired -> ScanResult(exit_code=-1, error set), no exception raised
  - FileNotFoundError -> ScanResult(exit_code=-1, error set), no exception raised
  - Malformed JSON -> ScanResult(exit_code=..., error set), no exception raised
  - health_check() True when which() returns a path, False when which() returns None
  - SonarQube: no SONAR_HOST_URL -> error returned immediately
  - SonarQube: /api/issues/search parse path via requests.get mock
  - Syft: findings=[] and sbom artifact written to run_path
  - Trivy: delegates to trivy_runner.run_trivy; mocked at that boundary
  - Strix: delegates to strix_runner.run_strix; mocked at that boundary
  - TruffleHog: evidence field is always "<redacted>", never raw secret content
  - registry: get(), list_scanners(), dispatch() by capability, unknown-name error
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    dispatch,
    get,
    list_scanners,
    register,
)
from aegis.schema import AegisFinding
from aegis.state import RunState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = "2025-01-01T00:00:00+00:00"


def _make_run_state(tmp: str) -> RunState:
    return RunState(tmp, run_id="test-run-001")


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# Minimal but schema-accurate sample payloads
# ---------------------------------------------------------------------------

BANDIT_PAYLOAD = json.dumps({
    "results": [{
        "filename": "app/auth.py",
        "line_number": 42,
        "test_id": "B105",
        "test_name": "hardcoded_password_string",
        "issue_severity": "HIGH",
        "issue_confidence": "MEDIUM",
        "issue_text": "Possible hardcoded password: 'admin123'",
        "issue_cwe": {"id": "CWE-259"},
        "code": "password = 'admin123'",
    }],
    "errors": [],
})

CHECKOV_PAYLOAD = json.dumps({
    "results": {
        "failed_checks": [{
            "check_id": "CKV_AWS_8",
            "check_name": "Ensure AWS Lightsail instance uses SSH key pair",
            "severity": "HIGH",
            "file_path": "main.tf",
            "resource": "aws_lightsail_instance.example",
            "file_line_range": [10, 20],
            "guideline": "https://docs.aws.amazon.com/lightsail/",
        }],
        "passed_checks": [],
    },
})

CODEQL_PAYLOAD = json.dumps({
    "runs": [{
        "results": [{
            "ruleId": "python/sql-injection",
            "level": "error",
            "message": {"text": "SQL injection vulnerability detected"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/db.py"},
                    "region": {"startLine": 55, "endLine": 57},
                }
            }],
        }],
    }],
})

GRYPE_PAYLOAD = json.dumps({
    "matches": [{
        "vulnerability": {
            "id": "CVE-2023-1234",
            "severity": "HIGH",
            "description": "Remote code execution",
            "fix": {"versions": ["2.0.1"]},
            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
        },
        "artifact": {
            "name": "requests",
            "version": "2.0.0",
        },
    }],
})

NUCLEI_LINE = json.dumps({
    "template-id": "cves/2023/CVE-2023-9999",
    "info": {
        "name": "Test CVE",
        "severity": "high",
        "description": "Test description",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"],
    },
    "matched-at": "http://localhost/vuln",
    "host": "http://localhost",
})

SEMGREP_PAYLOAD = json.dumps({
    "results": [{
        "check_id": "python.flask.security.injection.tainted-sql-string",
        "path": "app/views.py",
        "start": {"line": 10, "col": 5},
        "end": {"line": 10, "col": 30},
        "extra": {
            "severity": "ERROR",
            "message": "SQL injection risk in Flask view",
            "lines": "    db.execute(query)",
            "metadata": {
                "title": "SQL Injection",
                "cwe": ["CWE-89"],
                "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            },
        },
    }],
    "errors": [],
})

ZAP_PAYLOAD = json.dumps({
    "site": [{
        "alerts": [{
            "pluginid": "40018",
            "name": "SQL Injection",
            "riskcode": "3",
            "desc": "SQL injection vulnerability found",
            "cweid": "89",
            "solution": "Use parameterized queries",
            "instances": [{
                "uri": "http://localhost/login",
                "method": "POST",
            }],
        }],
    }],
})

# TruffleHog: note "Raw" key is present but the adapter must NOT store it
TRUFFLEHOG_LINE = json.dumps({
    "DetectorName": "AWS",
    "Verified": True,
    "Raw": "FAKE_AWS_KEY_PLACEHOLDER_NOT_REAL",
    "SourceMetadata": {
        "Data": {
            "Filesystem": {
                "file": "/repo/config.env",
                "line": 7,
            },
        },
    },
})

SONARQUBE_ISSUES_RESPONSE = {
    "issues": [{
        "key": "AY1abc",
        "rule": "python:S2078",
        "severity": "BLOCKER",
        "message": "Fix this LDAP injection.",
        "component": "myproject:src/ldap.py",
    }],
    "total": 1,
    "paging": {"total": 1, "pageIndex": 1, "pageSize": 100},
}

TRIVY_RAW = {
    "Results": [{
        "Target": "go.sum",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2022-0001",
            "PkgName": "golang.org/x/net",
            "InstalledVersion": "0.0.0-20220101",
            "FixedVersion": "0.7.0",
            "Severity": "HIGH",
            "Title": "Buffer overflow in net/http",
            "Description": "An attacker can overflow a buffer in the HTTP library.",
            "CweIDs": ["CWE-120"],
            "References": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0001"],
        }],
    }],
}

SYFT_SBOM = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [{"type": "library", "name": "requests", "version": "2.28.0"}],
})


# ===========================================================================
# Bandit
# ===========================================================================

class TestBanditAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("bandit")

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(BANDIT_PAYLOAD, returncode=1))
    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "bandit" / "results.json"
            self.assertTrue(raw_file.exists())
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertIsInstance(f, AegisFinding)
        self.assertEqual(f.source_tool, "bandit")
        self.assertEqual(f.finding_type, "sast")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, "medium")
        self.assertIn("bandit", result.command_str)
        self.assertEqual(result.exit_code, 1)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="bandit", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", side_effect=FileNotFoundError("bandit not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed("NOT JSON", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertIsNotNone(result.error)
        self.assertIn("parse", result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed("{}", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_scan_empty_results(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.findings, [])
        self.assertIsNone(result.error)


# ===========================================================================
# Checkov
# ===========================================================================

class TestCheckovAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("checkov")

    @patch("shutil.which", return_value="/usr/bin/checkov")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(CHECKOV_PAYLOAD, returncode=1))
    @patch("shutil.which", return_value="/usr/bin/checkov")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "checkov" / "results.json"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "checkov")
        self.assertEqual(f.finding_type, "config")
        self.assertEqual(f.severity, "high")
        self.assertIn("checkov", result.command_str)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="checkov", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/checkov")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("checkov not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("{BAD", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/checkov")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed("{}", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/checkov")
    def test_scan_empty_results(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# CodeQL
# ===========================================================================

class TestCodeqlAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("codeql")

    @patch("shutil.which", return_value="/usr/bin/codeql")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(CODEQL_PAYLOAD, returncode=0))
    @patch("shutil.which", return_value="/usr/bin/codeql")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/db"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "codeql" / "results.sarif"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "codeql")
        self.assertEqual(f.finding_type, "sast")
        self.assertEqual(f.severity, "high")  # "error" -> "high"
        self.assertIn("codeql", result.command_str)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="codeql", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/codeql")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/db"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("codeql not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/db"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("GARBAGE", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/codeql")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/db"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed('{"runs":[{"results":[]}]}', returncode=0))
    @patch("shutil.which", return_value="/usr/bin/codeql")
    def test_scan_empty_results(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/db"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# Grype
# ===========================================================================

class TestGrypeAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("grype")

    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(GRYPE_PAYLOAD, returncode=0))
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "grype" / "results.json"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "grype")
        self.assertEqual(f.finding_type, "dependency")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.cve, "CVE-2023-1234")
        self.assertEqual(f.package_name, "requests")
        self.assertEqual(f.fixed_version, "2.0.1")
        self.assertIn("grype", result.command_str)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="grype", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("grype not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("NOTJSON", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed('{"matches":[]}', returncode=0))
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_empty_matches(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# Nuclei
# ===========================================================================

class TestNucleiAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("nuclei")

    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(NUCLEI_LINE + "\n", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(
                target="http://localhost",
                extra={"templates": "cves"},
            ))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "nuclei" / "results.jsonl"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "nuclei")
        self.assertEqual(f.finding_type, "dast")
        self.assertEqual(f.severity, "high")
        self.assertIn("nuclei", result.command_str)

    @patch("subprocess.run", return_value=_completed(
        NUCLEI_LINE + "\n" + "BADLINE\n" + NUCLEI_LINE + "\n", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_scan_skips_invalid_lines(self, _w, _r):
        """Bad JSON lines in JSONL output are silently skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        # Two valid lines, one bad line -> 2 findings
        self.assertEqual(len(result.findings), 2)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("nuclei not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/nuclei")
    def test_scan_empty_output(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# Semgrep
# ===========================================================================

class TestSemgrepAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("semgrep")

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(SEMGREP_PAYLOAD, returncode=1))
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "semgrep" / "results.json"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "semgrep")
        self.assertEqual(f.finding_type, "sast")
        self.assertEqual(f.severity, "critical")  # ERROR -> critical
        self.assertIn("semgrep", result.command_str)

    @patch("subprocess.run", return_value=_completed(SEMGREP_PAYLOAD, returncode=1))
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_scan_custom_rules(self, _w, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            self.adapter.scan(rs, ScanOptions(
                target="/repo", extra={"rules": "p/python"}))
        # Find the call that ran semgrep with the custom config
        found = False
        for call in mock_run.call_args_list:
            args = call[0][0] if call[0] else []
            if any("--config=p/python" in str(a) for a in args):
                found = True
                break
        self.assertTrue(found, "--config=p/python not found in any subprocess.run call")

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("semgrep not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("{{BAD_JSON}}", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])


# ===========================================================================
# SonarQube
# ===========================================================================

class TestSonarQubeAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("sonarqube")
        # Make sure env var is absent unless set explicitly in test
        self._saved_host = os.environ.pop("SONAR_HOST_URL", None)
        self._saved_token = os.environ.pop("SONAR_TOKEN", None)

    def tearDown(self):
        if self._saved_host is not None:
            os.environ["SONAR_HOST_URL"] = self._saved_host
        else:
            os.environ.pop("SONAR_HOST_URL", None)
        if self._saved_token is not None:
            os.environ["SONAR_TOKEN"] = self._saved_token
        else:
            os.environ.pop("SONAR_TOKEN", None)

    @patch("shutil.which", return_value="/usr/bin/sonar-scanner")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    def test_scan_no_host_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.findings, [])
        self.assertIsNotNone(result.error)
        self.assertIn("SONAR_HOST_URL", result.error)

    @patch("subprocess.run", return_value=_completed("", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/sonar-scanner")
    def test_scan_with_host_env_var(self, _w, _r):
        os.environ["SONAR_HOST_URL"] = "http://sonar.example.com"
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        # SonarQube adapter does not parse findings from CLI output (API fetch later)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.findings, [])
        self.assertIsNone(result.error)

    @patch("subprocess.run", return_value=_completed("", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/sonar-scanner")
    def test_scan_with_host_in_extra(self, _w, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(
                target="/repo",
                extra={"sonar_host_url": "http://sonar.example.com",
                       "sonar_token": "fake-token"},
            ))
        self.assertEqual(result.exit_code, 0)
        # subprocess.run may be called multiple times (adapter_version + scan)
        # Find the call that contains sonar.token in its args
        all_calls = mock_run.call_args_list
        found_token = False
        for call in all_calls:
            args = call[0][0] if call[0] else []
            if any("sonar.token" in str(a) for a in args):
                found_token = True
                break
        self.assertTrue(found_token, "sonar.token was not passed to any subprocess.run call")

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="sonar-scanner", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/sonar-scanner")
    def test_scan_timeout(self, _w, _r):
        os.environ["SONAR_HOST_URL"] = "http://sonar.example.com"
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("sonar-scanner not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        os.environ["SONAR_HOST_URL"] = "http://sonar.example.com"
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    def test_convert_issues_via_helper(self):
        """Directly exercise the _convert helper for API parse path coverage."""
        from aegis.scanners.sonarqube_adapter import _convert
        for issue in SONARQUBE_ISSUES_RESPONSE["issues"]:
            f = _convert(issue, "run-test")
            self.assertIsInstance(f, AegisFinding)
            self.assertEqual(f.source_tool, "sonarqube")
            self.assertEqual(f.finding_type, "sast")
            # BLOCKER -> critical
            self.assertEqual(f.severity, "critical")


# ===========================================================================
# Syft
# ===========================================================================

class TestSyftAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("syft")

    @patch("shutil.which", return_value="/usr/bin/syft")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(SYFT_SBOM, returncode=0))
    @patch("shutil.which", return_value="/usr/bin/syft")
    def test_scan_produces_sbom_artifact_and_empty_findings(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
            sbom_path = Path(tmp) / "runs" / "test-run-001" / "syft" / "sbom.cyclonedx.json"
            self.assertTrue(sbom_path.exists())
            written = json.loads(sbom_path.read_text())
            self.assertEqual(written["bomFormat"], "CycloneDX")
        # Syft adapter always returns empty findings (SBOM only)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.adapter_name, "syft")
        self.assertEqual(result.exit_code, 0)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="syft", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/syft")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", side_effect=FileNotFoundError("syft not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="myimage:latest"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])


# ===========================================================================
# Trivy (via trivy_runner)
# ===========================================================================

class TestTrivyAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("trivy")

    @patch("shutil.which", return_value="/usr/bin/trivy")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("aegis.runners.trivy_runner.run_trivy")
    @patch("shutil.which", return_value="/usr/bin/trivy")
    def test_scan_happy_path(self, _w, mock_run_trivy):
        """TrivyAdapter delegates to trivy_runner.run_trivy; mock at that boundary."""
        from aegis.runners.trivy_runner import TrivyRunResult, parse_trivy_json
        findings = parse_trivy_json(TRIVY_RAW, "test-run-001")
        mock_run_trivy.return_value = TrivyRunResult(
            success=True, return_code=0, findings=findings,
            raw_json_path=None, error=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target=tmp))
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "trivy")
        self.assertEqual(f.finding_type, "dependency")
        self.assertEqual(f.severity, "high")
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.error)

    @patch("aegis.runners.trivy_runner.run_trivy")
    @patch("shutil.which", return_value=None)
    def test_scan_error_propagated(self, _w, mock_run_trivy):
        from aegis.runners.trivy_runner import TrivyRunResult
        mock_run_trivy.return_value = TrivyRunResult(
            success=False, return_code=-1, findings=[],
            raw_json_path=None, error="trivy CLI not found",
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target=tmp))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])


# ===========================================================================
# TruffleHog
# ===========================================================================

class TestTrufflehogAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("trufflehog")

    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(TRUFFLEHOG_LINE + "\n", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "trufflehog" / "results.jsonl"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "trufflehog")
        self.assertEqual(f.finding_type, "runtime")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, "high")
        self.assertIn("trufflehog", result.command_str)

    @patch("subprocess.run", return_value=_completed(TRUFFLEHOG_LINE + "\n", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_secret_redaction(self, _w, _r):
        """Raw secret value from 'Raw' key must NEVER appear in the finding."""
        fake_secret = "FAKE_AWS_KEY_PLACEHOLDER_NOT_REAL"
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        f = result.findings[0]
        # evidence must be "<redacted>", not the raw key
        self.assertEqual(f.evidence, "<redacted>")
        serialised = json.dumps(f.to_dict())
        self.assertNotIn(fake_secret, serialised)

    @patch("subprocess.run", return_value=_completed(
        TRUFFLEHOG_LINE + "\n" + "NOT_JSON\n" + TRUFFLEHOG_LINE + "\n", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_scan_skips_invalid_lines(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(len(result.findings), 2)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trufflehog", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("trufflehog not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_scan_empty_output(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="/repo"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# ZAP
# ===========================================================================

class TestZapAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("zap")

    @patch("shutil.which", side_effect=lambda x: "/usr/bin/zap-cli" if x == "zap-cli" else None)
    def test_health_check_true_via_zap_cli(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", side_effect=lambda x: None if x == "zap-cli" else "/usr/bin/zap.sh")
    def test_health_check_true_via_zap_sh(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("subprocess.run", return_value=_completed(ZAP_PAYLOAD, returncode=0))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_scan_happy_path(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
            raw_file = Path(tmp) / "runs" / "test-run-001" / "zap" / "report.json"
            self.assertTrue(raw_file.exists())
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.source_tool, "zap")
        self.assertEqual(f.finding_type, "dast")
        self.assertEqual(f.severity, "high")
        self.assertIn("zap-cli", result.command_str)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="zap-cli", timeout=1))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_scan_timeout(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("zap-cli not found"))
    @patch("shutil.which", return_value=None)
    def test_scan_file_not_found(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("subprocess.run", return_value=_completed("BAD_JSON", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_scan_bad_json(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch("subprocess.run", return_value=_completed('{"site":[]}', returncode=0))
    @patch("shutil.which", return_value="/usr/bin/zap-cli")
    def test_scan_empty_sites(self, _w, _r):
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.findings, [])


# ===========================================================================
# Strix (delegates to strix_runner.run_strix)
# ===========================================================================

class TestStrixAdapterScan(unittest.TestCase):
    def setUp(self):
        self.adapter = get("strix")

    @patch("shutil.which", return_value="/usr/bin/strix")
    def test_health_check_true(self, _w):
        self.assertTrue(self.adapter.health_check())

    @patch("shutil.which", return_value=None)
    def test_health_check_false(self, _w):
        self.assertFalse(self.adapter.health_check())

    @patch("aegis.runners.strix_runner.run_strix")
    @patch("shutil.which", return_value="/usr/bin/strix")
    def test_scan_happy_path(self, _w, mock_run_strix):
        from aegis.runners.strix_runner import StrixRunResult
        from aegis.schema import AegisFinding
        mock_finding = AegisFinding(
            id="strix-001",
            title="SQL Injection",
            severity="critical",
            finding_type="dast",
            description="SQL injection",
            source_tool="strix",
            source_run_id="test-run-001",
            affected_component="/login",
            confidence="high",
            status="open",
            created_at=_NOW,
            updated_at=_NOW,
        )
        mock_run_strix.return_value = StrixRunResult(
            success=True, partial_success=False, return_code=0,
            findings=[mock_finding],
            command=["strix", "--target", "http://localhost"],
            error=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source_tool, "strix")
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.error)

    @patch("aegis.runners.strix_runner.run_strix")
    @patch("shutil.which", return_value=None)
    def test_scan_error_propagated(self, _w, mock_run_strix):
        from aegis.runners.strix_runner import StrixRunResult
        mock_run_strix.return_value = StrixRunResult(
            success=False, partial_success=False, return_code=-1,
            findings=[], command=[],
            error="strix CLI not found",
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            result = self.adapter.scan(rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)

    @patch("aegis.runners.strix_runner.run_strix")
    @patch("shutil.which", return_value="/usr/bin/strix")
    def test_scan_passes_instruction(self, _w, mock_run_strix):
        from aegis.runners.strix_runner import StrixRunResult
        mock_run_strix.return_value = StrixRunResult(
            success=True, partial_success=False, return_code=0,
            findings=[], command=[],
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            self.adapter.scan(rs, ScanOptions(
                target="http://localhost",
                instruction="focus on authentication",
            ))
        call_kwargs = mock_run_strix.call_args[1]
        self.assertEqual(call_kwargs["instruction"], "focus on authentication")


# ===========================================================================
# Registry
# ===========================================================================

class TestRegistryExtra(unittest.TestCase):
    def setUp(self):
        # These tests register throwaway adapters into the module-level
        # _REGISTRY; snapshot/restore so they don't leak into the roster
        # tests (test_scanners.py / test_scanner_registry.py) that assert
        # an exact set and sort the keys.
        from aegis.scanners import registry as _reg
        self._saved_registry = dict(_reg._REGISTRY)

    def tearDown(self):
        from aegis.scanners import registry as _reg
        _reg._REGISTRY.clear()
        _reg._REGISTRY.update(self._saved_registry)

    def test_list_scanners_includes_all_adapters(self):
        names = set(list_scanners())
        expected = {"bandit", "checkov", "codeql", "grype", "nuclei",
                    "semgrep", "sonarqube", "strix", "syft", "trivy",
                    "trufflehog", "zap"}
        self.assertTrue(expected.issubset(names))

    def test_get_unknown_raises_key_error(self):
        with self.assertRaises(KeyError):
            get("no_such_scanner_xyz")

    def test_get_returns_same_adapter(self):
        a = get("bandit")
        b = get("bandit")
        self.assertIs(a, b)

    def test_dispatch_by_name(self):
        class _FakeScanResult:
            pass

        class _FakeAdapter:
            name = "_test_dispatch_name_42"
            capabilities = {"sast"}
            default_timeout = 60

            def adapter_version(self):
                return "0"

            def health_check(self):
                return True

            def scan(self, run_state, options):
                return ScanResult(
                    findings=[], adapter_name=self.name,
                    adapter_version="0", command_str="fake",
                )

        register(_FakeAdapter())
        result = dispatch("_test_dispatch_name_42", run_state=None,
                          options=ScanOptions(target="."))
        self.assertEqual(result.adapter_name, "_test_dispatch_name_42")

    def test_dispatch_by_capability(self):
        """dispatch() falls through to first adapter matching a capability."""
        class _FakeCapAdapter:
            name = "_test_dispatch_cap_secret_99"
            capabilities = {"secret"}
            default_timeout = 60

            def adapter_version(self):
                return "0"

            def health_check(self):
                return True

            def scan(self, run_state, options):
                return ScanResult(
                    findings=[], adapter_name=self.name,
                    adapter_version="0", command_str="fake",
                )

        register(_FakeCapAdapter())
        # dispatch by capability (not by name)
        result = dispatch("secret", run_state=None, options=ScanOptions(target="."))
        self.assertIsInstance(result, ScanResult)

    def test_dispatch_unknown_raises(self):
        with self.assertRaises(KeyError):
            dispatch("__no_such_cap_or_name__", run_state=None,
                     options=ScanOptions(target="."))

    def test_scan_result_defaults(self):
        r = ScanResult(findings=[], adapter_name="x", adapter_version="1",
                       command_str="cmd")
        self.assertEqual(r.exit_code, 0)
        self.assertIsNone(r.error)
        self.assertEqual(r.env_keys, [])

    def test_scan_options_defaults(self):
        opts = ScanOptions(target="/repo")
        self.assertIsNone(opts.instruction)
        self.assertEqual(opts.timeout, 1800)
        self.assertEqual(opts.extra, {})

    def test_maybe_load_entry_points_with_plugin_flag(self):
        """maybe_load_entry_points executes the entry-point discovery loop."""
        from aegis.scanners.registry import maybe_load_entry_points
        fake_ep = MagicMock()
        fake_ep.load.return_value = lambda: MagicMock(
            name="_test_ep_adapter_xyz",
            capabilities={"sast"},
            default_timeout=60,
        )
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}):
            with patch("importlib.metadata.entry_points", return_value=[fake_ep]):
                # Should run without raising
                maybe_load_entry_points()

    def test_maybe_load_entry_points_without_flag(self):
        """maybe_load_entry_points is a no-op unless AEGIS_PLUGINS=1."""
        from aegis.scanners.registry import maybe_load_entry_points
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_PLUGINS"}
        with patch.dict(os.environ, env, clear=True):
            # Should return immediately; no exception
            maybe_load_entry_points()


# ===========================================================================
# Extra coverage for adapter_version() and helper edge-cases
# ===========================================================================

class TestAdapterVersionEdgeCases(unittest.TestCase):
    """Cover the adapter_version() success path and minor helper branches."""

    @patch("subprocess.run", return_value=_completed("strix 1.2.3", returncode=0))
    def test_strix_adapter_version_success(self, _r):
        from aegis.scanners.strix_adapter import StrixAdapter
        v = StrixAdapter().adapter_version()
        self.assertEqual(v, "strix 1.2.3")

    @patch("subprocess.run", side_effect=Exception("no strix"))
    def test_strix_adapter_version_exception(self, _r):
        from aegis.scanners.strix_adapter import StrixAdapter
        v = StrixAdapter().adapter_version()
        self.assertEqual(v, "unknown")

    @patch("subprocess.run", return_value=_completed("trivy Version: 0.46.0", returncode=0))
    def test_trivy_adapter_version_success(self, _r):
        from aegis.scanners.trivy_adapter import TrivyAdapter
        v = TrivyAdapter().adapter_version()
        self.assertEqual(v, "trivy Version: 0.46.0")

    @patch("subprocess.run", side_effect=Exception("no trivy"))
    def test_trivy_adapter_version_exception(self, _r):
        from aegis.scanners.trivy_adapter import TrivyAdapter
        v = TrivyAdapter().adapter_version()
        self.assertEqual(v, "unknown")

    def test_syft_summarize_sbom(self):
        from aegis.scanners.syft_adapter import _summarize_sbom
        self.assertEqual(_summarize_sbom({"components": ["a", "b", "c"]}), 3)
        self.assertEqual(_summarize_sbom({}), 0)

    def test_trufflehog_source_location_unknown_fallback(self):
        """_source_location returns ('unknown', 0) when SourceMetadata is absent."""
        from aegis.scanners.trufflehog_adapter import _source_location
        file, line = _source_location({})
        self.assertEqual(file, "unknown")
        self.assertEqual(line, 0)

    def test_trufflehog_scan_blank_line_skipped(self):
        """Blank lines in trufflehog JSONL output don't become findings."""
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            # Output is only blank lines
            blank_output = "\n\n\n"
            with patch("subprocess.run",
                       return_value=_completed(blank_output, returncode=0)):
                with patch("shutil.which", return_value="/usr/bin/trufflehog"):
                    result = get("trufflehog").scan(
                        rs, ScanOptions(target="/repo"))
        self.assertEqual(result.findings, [])

    def test_nuclei_scan_blank_line_skipped(self):
        """Blank lines in nuclei JSONL output don't become findings."""
        with tempfile.TemporaryDirectory() as tmp:
            rs = _make_run_state(tmp)
            blank_output = "\n\n\n"
            with patch("subprocess.run",
                       return_value=_completed(blank_output, returncode=0)):
                with patch("shutil.which", return_value="/usr/bin/nuclei"):
                    result = get("nuclei").scan(
                        rs, ScanOptions(target="http://localhost"))
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
