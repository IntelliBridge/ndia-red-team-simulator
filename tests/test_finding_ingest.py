import json
import unittest
from pathlib import Path

from aegis.integrations.finding_ingest import (
    detect_format,
    ingest_report,
    ingest_sarif,
    ingest_snyk,
    ingest_trivy,
    ingest_veracode,
)
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures" / "ingest"

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FINDING_TYPES = {"dependency", "sast", "dast", "runtime", "config"}


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestSnykIngest(unittest.TestCase):
    def setUp(self):
        self.data = _load("snyk.json")
        self.findings = ingest_snyk(self.data)

    def test_roundtrip_to_findings(self):
        # 3 dict vulns + 1 non-dict entry that must be skipped.
        self.assertEqual(len(self.findings), 3)
        for f in self.findings:
            self.assertIsInstance(f, AegisFinding)
            self.assertEqual(f.finding_type, "dependency")
            self.assertEqual(f.source_tool, "snyk")
            self.assertEqual(f.status, "open")
            self.assertIn(f.severity, _VALID_SEVERITIES)
            self.assertIsNotNone(f.created_at)
            self.assertIsNotNone(f.updated_at)

    def test_first_finding_fields(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.package_name, "example-pkg")
        self.assertEqual(f.installed_version, "1.2.3")
        self.assertEqual(f.fixed_version, "1.2.4")
        self.assertEqual(f.cve, "CVE-0000-00001")
        self.assertEqual(f.cwe, "CWE-1321")
        self.assertEqual(f.title, "Prototype Pollution")

    def test_empty_identifiers_leave_cve_none(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "medium")
        self.assertIsNone(f.cve)
        self.assertEqual(f.cwe, "CWE-400")
        self.assertEqual(f.fixed_version, "0.9.1")

    def test_unknown_severity_defaults_low(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "low")
        self.assertIsNone(f.cve)
        self.assertIsNone(f.fixed_version)

    def test_source_run_id_threaded(self):
        findings = ingest_report(self.data, "snyk", source_run_id="run-snyk")
        self.assertTrue(findings)
        self.assertTrue(all(f.source_run_id == "run-snyk" for f in findings))

    def test_serializable_no_crash(self):
        for f in self.findings:
            json.dumps(f.to_dict())


class TestVeracodeIngest(unittest.TestCase):
    def setUp(self):
        self.data = _load("veracode.json")
        self.findings = ingest_veracode(self.data)

    def test_roundtrip_to_findings(self):
        # 3 dict findings + 1 non-dict (42) skipped.
        self.assertEqual(len(self.findings), 3)
        for f in self.findings:
            self.assertEqual(f.finding_type, "sast")
            self.assertEqual(f.source_tool, "veracode")
            self.assertEqual(f.status, "open")
            self.assertIn(f.severity, _VALID_SEVERITIES)

    def test_first_finding_fields(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "high")  # numeric 4 -> high
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.title, "SQL Injection")
        self.assertEqual(f.id, "veracode:1001")
        self.assertIsNotNone(f.code_locations)
        loc = f.code_locations[0]
        self.assertEqual(loc.file, "src/main/java/com/example/test/Login.java")
        self.assertEqual(loc.start_line, 88)

    def test_second_finding_severity_medium(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "medium")  # numeric 3 -> medium
        self.assertEqual(f.cwe, "CWE-80")

    def test_out_of_range_severity_defaults_low_and_no_location(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "low")  # 99 not in map
        self.assertIsNone(f.code_locations)  # no file_path/line

    def test_no_leak(self):
        blob = json.dumps([f.to_dict() for f in self.findings])
        # evidence is never populated.
        self.assertNotIn('"evidence": "', blob.replace('"evidence": null', ""))
        for f in self.findings:
            self.assertIsNone(f.evidence)


class TestTrivyIngest(unittest.TestCase):
    def setUp(self):
        self.data = _load("trivy.json")
        self.findings = ingest_trivy(self.data)

    def test_roundtrip_to_findings(self):
        # 2 + 1 vulns across 3 results (third result has no Vulnerabilities).
        self.assertEqual(len(self.findings), 3)
        for f in self.findings:
            self.assertEqual(f.finding_type, "dependency")
            self.assertEqual(f.source_tool, "trivy")
            self.assertEqual(f.status, "open")

    def test_first_finding_fields(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.cve, "CVE-0000-10001")
        self.assertEqual(f.cwe, "CWE-787")
        self.assertEqual(f.package_name, "libplaceholder")
        self.assertEqual(f.installed_version, "1.0.0-1")
        self.assertEqual(f.fixed_version, "1.0.0-2")
        self.assertIn("debian", f.affected_component)
        self.assertEqual(f.references, ["https://example.test/advisory/CVE-0000-10001"])

    def test_empty_fixed_version_is_none(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "medium")
        self.assertIsNone(f.fixed_version)  # "" -> None

    def test_non_cve_id_leaves_cve_none_and_unknown_severity(self):
        f = self.findings[2]
        self.assertIsNone(f.cve)  # GHSA-* is not a CVE
        self.assertEqual(f.severity, "low")  # UNKNOWN -> low
        self.assertEqual(f.package_name, "example-node-pkg")

    def test_serializable(self):
        for f in self.findings:
            json.dumps(f.to_dict())


class TestSarifIngest(unittest.TestCase):
    def setUp(self):
        self.data = _load("example.sarif")
        self.findings = ingest_sarif(self.data)

    def test_roundtrip_to_findings(self):
        self.assertEqual(len(self.findings), 4)
        for f in self.findings:
            self.assertEqual(f.finding_type, "sast")
            self.assertEqual(f.source_tool, "sarif")
            self.assertEqual(f.status, "open")

    def test_error_level_maps_high_with_location(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "high")  # level error
        self.assertEqual(f.title, "example/sql-injection")
        self.assertIsNotNone(f.code_locations)
        loc = f.code_locations[0]
        self.assertEqual(loc.file, "app/db.py")
        self.assertEqual(loc.start_line, 42)
        self.assertEqual(loc.end_line, 45)

    def test_warning_level_maps_medium_no_endline(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "medium")
        loc = f.code_locations[0]
        self.assertEqual(loc.start_line, 18)
        self.assertEqual(loc.end_line, 18)  # endLine absent -> startLine

    def test_note_level_maps_low_no_location(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "low")
        self.assertIsNone(f.code_locations)  # no locations

    def test_missing_level_defaults_low_and_empty_locations(self):
        f = self.findings[3]
        self.assertEqual(f.severity, "low")  # no level field
        self.assertIsNone(f.code_locations)  # locations == []


class TestAutoDetection(unittest.TestCase):
    def test_detect_each_fixture(self):
        self.assertEqual(detect_format(_load("snyk.json")), "snyk")
        self.assertEqual(detect_format(_load("veracode.json")), "veracode")
        self.assertEqual(detect_format(_load("trivy.json")), "trivy")
        self.assertEqual(detect_format(_load("example.sarif")), "sarif")

    def test_ingest_report_routes_each_fixture(self):
        snyk = ingest_report(_load("snyk.json"))
        veracode = ingest_report(_load("veracode.json"))
        trivy = ingest_report(_load("trivy.json"))
        sarif = ingest_report(_load("example.sarif"))
        self.assertTrue(all(f.source_tool == "snyk" for f in snyk))
        self.assertTrue(all(f.source_tool == "veracode" for f in veracode))
        self.assertTrue(all(f.source_tool == "trivy" for f in trivy))
        self.assertTrue(all(f.source_tool == "sarif" for f in sarif))
        self.assertEqual((len(snyk), len(veracode), len(trivy), len(sarif)), (3, 3, 3, 4))

    def test_explicit_fmt_overrides_and_is_case_insensitive(self):
        findings = ingest_report(_load("snyk.json"), fmt="SNYK")
        self.assertTrue(findings)
        self.assertTrue(all(f.source_tool == "snyk" for f in findings))

    def test_ingest_report_accepts_json_string(self):
        raw = (FIXTURES / "trivy.json").read_text()
        findings = ingest_report(raw)
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f.source_tool == "trivy" for f in findings))

    def test_detect_format_top_level_findings_array(self):
        # Veracode export with a flat top-level findings array (no _embedded).
        doc = {"findings": [{"issue_id": 7, "finding_details": {"severity": 2}}]}
        self.assertEqual(detect_format(doc), "veracode")
        findings = ingest_report(doc)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_detect_format_unknown_returns_none(self):
        self.assertIsNone(detect_format({"something": "else"}))
        self.assertIsNone(detect_format({}))
        self.assertIsNone(detect_format("not a dict"))

    def test_sarif_detected_by_runs_without_schema(self):
        doc = {"version": "2.1.0", "runs": [{"results": []}]}
        self.assertEqual(detect_format(doc), "sarif")

    def test_trivy_detected_by_results_without_schemaversion(self):
        doc = {"Results": [{"Target": "x", "Vulnerabilities": []}]}
        self.assertEqual(detect_format(doc), "trivy")


class TestDefensive(unittest.TestCase):
    def test_malformed_inputs_return_empty_without_raising(self):
        self.assertEqual(ingest_report({}), [])
        self.assertEqual(ingest_report("not json"), [])
        self.assertEqual(ingest_report(None), [])
        self.assertEqual(ingest_report([{"x": 1}]), [])  # list, not a dict
        self.assertEqual(ingest_report("[1, 2, 3]"), [])  # JSON list string
        self.assertEqual(ingest_report("123"), [])  # JSON scalar string

    def test_unknown_or_unmatched_format_returns_empty(self):
        self.assertEqual(ingest_report({"something": "else"}), [])
        self.assertEqual(ingest_report(_load("snyk.json"), fmt="bogus"), [])

    def test_each_parser_handles_garbage(self):
        for parser in (ingest_snyk, ingest_veracode, ingest_trivy, ingest_sarif):
            self.assertEqual(parser({}), [])
            self.assertEqual(parser(None), [])
            self.assertEqual(parser("not json"), [])
            self.assertEqual(parser([1, 2]), [])

    def test_non_dict_array_members_skipped(self):
        self.assertEqual(ingest_snyk({"vulnerabilities": ["x", 1, None]}), [])
        self.assertEqual(ingest_trivy({"Results": ["x", {"Vulnerabilities": [1, "y"]}]}), [])
        self.assertEqual(ingest_sarif({"runs": ["x", {"results": [1, None]}]}), [])
        self.assertEqual(ingest_veracode({"findings": [1, "x", None]}), [])

    def test_caller_dict_not_mutated(self):
        data = _load("snyk.json")
        ingest_report(data, source_run_id="run-x")
        self.assertNotIn("_source_run_id", data)


if __name__ == "__main__":
    unittest.main()
