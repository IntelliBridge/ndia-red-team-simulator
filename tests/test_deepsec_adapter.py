import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aegis.config import AegisConfig
from aegis.scanners import ScanOptions
from aegis.scanners.deepsec_adapter import (
    DeepsecAdapter,
    _convert,
    _extract_json_array,
    _has_ai_key,
    _normalize_severity,
)
from aegis.schema import AegisFinding
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
FIXTURE_TEXT = (FIXTURES / "deepsec_raw.json").read_text()

# Every owner/identity value in the fixture carries this marker so a single
# substring check proves none of it survives into a finding.
_PII_MARKER = "pii-leak"
_OWNER_NAMES = ("Dave Owner", "Erin Boss", "Jane Owner", "Carol Coder")


def _fake_run(cmd, **kwargs):
    """Stand-in for subprocess.run keyed on the deepsec subcommand."""
    if "--version" in cmd:
        out = "deepsec 9e3832d"
    elif "export" in cmd:
        out = FIXTURE_TEXT
    else:  # scan / process stages write to disk, print nothing to stdout
        out = ""
    return SimpleNamespace(stdout=out, stderr="", returncode=0)


class TestDeepsecConvert(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(FIXTURE_TEXT)
        self.converted = [_convert(f, "run-1") for f in self.raw]
        self.surviving = [f for f in self.converted if f is not None]

    def test_verdict_filter_drops_non_actionable(self):
        # false-positive, duplicate, fixed → dropped; the rest survive.
        self.assertEqual(len(self.surviving), 6)
        self.assertEqual(len(self.raw), 9)
        verdicts_dropped = {
            (f["metadata"]["revalidation"]["verdict"])
            for f, c in zip(self.raw, self.converted)
            if c is None
        }
        self.assertEqual(verdicts_dropped, {"false-positive", "duplicate", "fixed"})

    def test_finding_type_and_provenance(self):
        for f in self.surviving:
            self.assertIsInstance(f, AegisFinding)
            self.assertEqual(f.finding_type, "code_audit")
            self.assertEqual(f.source_tool, "deepsec")
            self.assertEqual(f.source_run_id, "run-1")
            self.assertEqual(f.status, "open")
            self.assertIsNotNone(f.created_at)
            self.assertIsNotNone(f.updated_at)

    def test_severity_mapping_each_class(self):
        # Keyed by file/component to make the mapping assertions explicit.
        sev = {
            (f.code_locations[0].file if f.code_locations else f.affected_component): f.severity
            for f in self.surviving
        }
        self.assertEqual(sev["scripts/deploy.sh"], "critical")   # CRITICAL
        self.assertEqual(sev["src/db/users.ts"], "high")         # HIGH
        self.assertEqual(sev["src/api/handler.ts"], "high")      # HIGH_BUG → high
        self.assertEqual(sev["src/web/webhook.ts"], "medium")    # MEDIUM
        self.assertEqual(sev["src/util/paginate.ts"], "low")     # BUG → low
        self.assertEqual(sev["weak-hash"], "low")                # LOW

    def test_file_line_extraction(self):
        sqli = next(f for f in self.surviving if f.code_locations
                    and f.code_locations[0].file == "src/db/users.ts")
        loc = sqli.code_locations[0]
        self.assertEqual(loc.start_line, 42)
        self.assertEqual(loc.end_line, 44)
        self.assertEqual(sqli.affected_component, "src/db/users.ts")

    def test_finding_without_file_has_no_code_location(self):
        weak = next(f for f in self.surviving if f.affected_component == "weak-hash")
        self.assertIsNone(weak.code_locations)
        self.assertEqual(weak.affected_component, "weak-hash")
        self.assertTrue(weak.id.startswith("deepsec:weak-hash:"))

    def test_title_prefix_stripped(self):
        for f in self.surviving:
            self.assertFalse(f.title.startswith("["),
                             f"severity prefix not stripped: {f.title!r}")
        sqli = next(f for f in self.surviving if f.code_locations
                    and f.code_locations[0].file == "src/db/users.ts")
        self.assertEqual(sqli.title, "SQL injection in user lookup")

    def test_description_is_synthesized_not_copied(self):
        sqli = next(f for f in self.surviving if f.code_locations
                    and f.code_locations[0].file == "src/db/users.ts")
        self.assertIn("sql-injection", sqli.description)
        self.assertIn("src/db/users.ts", sqli.description)
        self.assertIn("line 42", sqli.description)

    def test_no_owner_pii_in_any_finding(self):
        """The load-bearing guarantee: owner identities never reach a finding."""
        blob = json.dumps([f.to_dict() for f in self.surviving])
        # Catch-all: every structured PII value in the fixture carries the marker.
        self.assertNotIn(_PII_MARKER, blob)
        # Owner display names (leaked via deepsec's prebuilt description) stripped.
        for name in _OWNER_NAMES:
            self.assertNotIn(name, blob)
        # deepsec's own PII-laden description is never reused verbatim.
        for raw in self.raw:
            desc = raw.get("description")
            if desc:
                self.assertNotIn(desc, blob)
        # The PII-bearing keys themselves never appear in serialized findings.
        for key in ("owners", "assignee", "labels", "githubUrl"):
            self.assertNotIn(key, blob)

    def test_evidence_and_references_never_populated(self):
        for f in self.surviving:
            self.assertIsNone(f.evidence)
            self.assertEqual(f.references, [])
            self.assertIsNone(f.remediation_steps)

    def test_unknown_severity_and_confidence_default(self):
        # Inline records exercise the default branches without touching fixtures.
        f = _convert({"severity": "WAT", "metadata": {
            "vulnSlug": "x", "confidence": "bogus",
            "revalidation": {"verdict": "confirmed"}}}, "run-1")
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.confidence, "medium")

    def test_confidence_passthrough(self):
        ssrf = next(f for f in self.surviving if f.affected_component == "src/web/webhook.ts")
        self.assertEqual(ssrf.confidence, "medium")
        handler = next(f for f in self.surviving if f.affected_component == "src/api/handler.ts")
        self.assertEqual(handler.confidence, "low")


class TestExtractJsonArray(unittest.TestCase):
    def test_empty_and_garbage(self):
        self.assertEqual(_extract_json_array(""), [])
        self.assertEqual(_extract_json_array("   "), [])
        self.assertEqual(_extract_json_array("not json"), [])

    def test_bare_array(self):
        self.assertEqual(_extract_json_array("[]"), [])
        self.assertEqual(_extract_json_array('[{"a": 1}]'), [{"a": 1}])

    def test_object_is_not_an_array(self):
        self.assertEqual(_extract_json_array('{"a": 1}'), [])

    def test_array_sliced_from_noise(self):
        noisy = 'INFO starting export\n[{"x": 2}]\nINFO done'
        self.assertEqual(_extract_json_array(noisy), [{"x": 2}])

    def test_broken_brackets(self):
        self.assertEqual(_extract_json_array("[oops"), [])
        self.assertEqual(_extract_json_array("INFO no array here"), [])

    def test_sliced_region_still_invalid(self):
        # Both brackets present but the region between them is not valid JSON.
        self.assertEqual(_extract_json_array("[not, valid, json]"), [])


class TestHelpers(unittest.TestCase):
    def test_normalize_severity(self):
        self.assertEqual(_normalize_severity("CRITICAL"), "critical")
        self.assertEqual(_normalize_severity("high_bug"), "high")
        self.assertEqual(_normalize_severity("HIGH_BUG"), "high")
        self.assertEqual(_normalize_severity("Bug"), "low")
        self.assertEqual(_normalize_severity("???"), "low")
        self.assertEqual(_normalize_severity(""), "low")

    def test_has_ai_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_has_ai_key())
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "x"}, clear=True):
            self.assertTrue(_has_ai_key())
        with mock.patch.dict(os.environ, {"AI_GATEWAY_API_KEY": "x"}, clear=True):
            self.assertTrue(_has_ai_key())


class TestDeepsecAdapter(unittest.TestCase):
    def test_capabilities_and_name(self):
        a = DeepsecAdapter()
        self.assertEqual(a.name, "deepsec")
        self.assertEqual(a.capabilities, {"code_audit"})

    def test_health_check_false_when_pnpm_absent(self):
        with mock.patch("aegis.scanners.deepsec_adapter.shutil.which", return_value=None):
            self.assertFalse(DeepsecAdapter().health_check())

    def test_health_check_false_when_path_absent(self):
        cfg = AegisConfig(deepsec_path="/nonexistent/deepsec/path")
        with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=cfg), \
             mock.patch("aegis.scanners.deepsec_adapter.shutil.which", return_value="/usr/bin/pnpm"):
            self.assertFalse(DeepsecAdapter().health_check())

    def test_health_check_true_when_pnpm_and_path_present(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = AegisConfig(deepsec_path=td)
            with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=cfg), \
                 mock.patch("aegis.scanners.deepsec_adapter.shutil.which", return_value="/usr/bin/pnpm"):
                self.assertTrue(DeepsecAdapter().health_check())

    def test_adapter_version_reads_cli(self):
        with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=AegisConfig()), \
             mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=_fake_run):
            self.assertEqual(DeepsecAdapter().adapter_version(), "deepsec 9e3832d")

    def test_adapter_version_unknown_on_error(self):
        with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=AegisConfig()), \
             mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=OSError):
            self.assertEqual(DeepsecAdapter().adapter_version(), "unknown")

    def test_scan_happy_path_parses_export(self):
        with tempfile.TemporaryDirectory() as td:
            rs = RunState(output_dir=td)
            opts = ScanOptions(target=td, timeout=5)
            with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=AegisConfig()), \
                 mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=_fake_run):
                result = DeepsecAdapter().scan(rs, opts)
            self.assertEqual(result.adapter_name, "deepsec")
            self.assertEqual(result.exit_code, 0)
            self.assertIsNone(result.error)
            self.assertEqual(len(result.findings), 6)
            self.assertTrue(all(f.finding_type == "code_audit" for f in result.findings))
            # AI process stage is OFF by default — never invoked.
            self.assertNotIn("process", result.command_str)
            # Raw export is persisted under the run dir.
            self.assertTrue((Path(rs.run_path) / "deepsec" / "export.json").exists())
            # Owner PII never reaches the persisted findings either.
            self.assertNotIn(_PII_MARKER, json.dumps([f.to_dict() for f in result.findings]))

    def test_scan_runs_ai_process_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            rs = RunState(output_dir=td)
            opts = ScanOptions(target=td, timeout=5)
            calls = []

            def rec(cmd, **kw):
                calls.append(cmd)
                return _fake_run(cmd, **kw)

            cfg = AegisConfig(deepsec_ai_process=True, deepsec_budget_usd=5.0)
            with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=cfg), \
                 mock.patch.dict(os.environ, {"AI_GATEWAY_API_KEY": "test-key"}, clear=False), \
                 mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=rec):
                result = DeepsecAdapter().scan(rs, opts)
            self.assertIn("process", result.command_str)
            self.assertTrue(any("process" in c for c in calls),
                            "AI process stage should run when enabled + key present")

    def test_scan_no_ai_process_without_key_even_if_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            rs = RunState(output_dir=td)
            opts = ScanOptions(target=td, timeout=5)
            cfg = AegisConfig(deepsec_ai_process=True, deepsec_budget_usd=5.0)
            with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=cfg), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=_fake_run):
                result = DeepsecAdapter().scan(rs, opts)
            self.assertNotIn("process", result.command_str)

    def test_scan_skips_non_dict_items(self):
        mixed = json.dumps([
            {"title": "[LOW] ok", "severity": "LOW",
             "metadata": {"vulnSlug": "x", "filePath": "a.ts", "lineNumbers": [1],
                          "revalidation": {"verdict": "confirmed"}}},
            "stray-log-line", 42, None,
        ])

        def run(cmd, **kw):
            if "--version" in cmd:
                return SimpleNamespace(stdout="deepsec 9e3832d", stderr="", returncode=0)
            if "export" in cmd:
                return SimpleNamespace(stdout=mixed, stderr="", returncode=0)
            return SimpleNamespace(stdout="", stderr="", returncode=0)

        with tempfile.TemporaryDirectory() as td:
            rs = RunState(output_dir=td)
            opts = ScanOptions(target=td, timeout=5)
            with mock.patch("aegis.scanners.deepsec_adapter.load_config", return_value=AegisConfig()), \
                 mock.patch("aegis.scanners.deepsec_adapter.subprocess.run", side_effect=run):
                result = DeepsecAdapter().scan(rs, opts)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "low")

    def test_scan_soft_degrades(self):
        for exc in (FileNotFoundError("pnpm"),
                    subprocess.TimeoutExpired(cmd=["pnpm"], timeout=5),
                    OSError("boom")):
            with self.subTest(exc=type(exc).__name__):
                with tempfile.TemporaryDirectory() as td:
                    rs = RunState(output_dir=td)
                    opts = ScanOptions(target=td, timeout=5)
                    with mock.patch("aegis.scanners.deepsec_adapter.load_config",
                                    return_value=AegisConfig()), \
                         mock.patch("aegis.scanners.deepsec_adapter.subprocess.run",
                                    side_effect=exc):
                        result = DeepsecAdapter().scan(rs, opts)
                    self.assertEqual(result.findings, [])
                    self.assertEqual(result.exit_code, -1)
                    self.assertIsNotNone(result.error)
                    self.assertEqual(result.adapter_name, "deepsec")


if __name__ == "__main__":
    unittest.main()
