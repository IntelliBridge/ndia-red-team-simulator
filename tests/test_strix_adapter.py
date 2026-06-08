import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.runners.strix_converter import convert_strix_finding, convert_strix_findings, load_strix_events
from aegis.runners.strix_runner import StrixRunResult
from aegis.scanners.registry import ScanOptions
from aegis.scanners.strix_adapter import StrixAdapter
from aegis.schema import AegisFinding, CodeLocation
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrixAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "strix_finding.json") as f:
            self.raw = json.load(f)
        with open(FIXTURES / "aegis_finding_expected.json") as f:
            self.expected = json.load(f)

    def test_convert_single_finding(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "vuln-0001")
        self.assertEqual(result.title, "SQL Injection in Login Form")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.finding_type, "dast")
        self.assertEqual(result.source_tool, "strix")
        self.assertEqual(result.source_run_id, "test-run-001")
        self.assertEqual(result.affected_component, "/rest/user/login")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.status, "open")
        self.assertEqual(result.cvss, 9.8)
        self.assertEqual(result.cwe, "CWE-89")

    def test_code_locations_converted(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertIsNotNone(result.code_locations)
        self.assertEqual(len(result.code_locations), 1)
        loc = result.code_locations[0]
        self.assertIsInstance(loc, CodeLocation)
        self.assertEqual(loc.file, "routes/login.js")
        self.assertEqual(loc.start_line, 42)
        self.assertIsNotNone(loc.fix_after)

    def test_not_dependency_finding(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        self.assertFalse(result.is_dependency_finding)

    def test_convert_multiple(self):
        results = convert_strix_findings([self.raw, self.raw], "test-run-001")
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], AegisFinding)

    def test_roundtrip_matches_expected(self):
        result = convert_strix_finding(self.raw, "test-run-001")
        d = result.to_dict()
        # Check key fields match expected fixture
        self.assertEqual(d["id"], self.expected["id"])
        self.assertEqual(d["finding_type"], self.expected["finding_type"])
        self.assertEqual(d["source_tool"], self.expected["source_tool"])
        self.assertEqual(d["affected_component"], self.expected["affected_component"])

    def test_load_strix_events_actual_payload_report_shape(self):
        event = {
            "event_type": "finding.created",
            "run_id": "strix-run",
            "payload": {"report": self.raw},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")

            results = load_strix_events(str(events_path), "test-run-001")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "vuln-0001")
        self.assertEqual(results[0].source_run_id, "test-run-001")

    def test_load_strix_events_legacy_data_shape(self):
        event = {"event_type": "finding.created", "data": self.raw}
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")

            results = load_strix_events(str(events_path), "test-run-001")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "vuln-0001")


class TestStrixAdapterPassesDepthOptions(unittest.TestCase):
    def test_scan_forwards_new_depth_options_to_run_strix(self):
        adapter = StrixAdapter()
        captured = {}

        def fake_run_strix(target, run_state, **kwargs):
            captured["target"] = target
            captured.update(kwargs)
            return StrixRunResult(
                success=True, partial_success=False, return_code=0,
                findings=[], command=["strix"], log_path=None, events_path=None,
            )

        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "adapter-depth")
            options = ScanOptions(
                target="http://localhost:3000",
                instruction="inline",
                targets=["./repo", "https://staging.example.com"],
                instruction_file="/tmp/instr.md",
                scope_mode="diff",
                diff_base="origin/main",
            )
            with patch("aegis.runners.strix_runner.run_strix", side_effect=fake_run_strix):
                adapter.scan(state, options)

        self.assertEqual(captured["target"], "http://localhost:3000")
        self.assertEqual(captured["targets"], ["./repo", "https://staging.example.com"])
        self.assertEqual(captured["instruction_file"], "/tmp/instr.md")
        self.assertEqual(captured["scope_mode"], "diff")
        self.assertEqual(captured["diff_base"], "origin/main")
        # instruction is still forwarded; the runner decides exclusivity.
        self.assertEqual(captured["instruction"], "inline")

    def test_scan_defaults_for_depth_options(self):
        adapter = StrixAdapter()
        captured = {}

        def fake_run_strix(target, run_state, **kwargs):
            captured.update(kwargs)
            return StrixRunResult(
                success=True, partial_success=False, return_code=0,
                findings=[], command=["strix"], log_path=None, events_path=None,
            )

        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "adapter-depth-default")
            options = ScanOptions(target="http://localhost:3000")
            with patch("aegis.runners.strix_runner.run_strix", side_effect=fake_run_strix):
                adapter.scan(state, options)

        self.assertIsNone(captured["targets"])
        self.assertIsNone(captured["instruction_file"])
        self.assertEqual(captured["scope_mode"], "auto")
        self.assertIsNone(captured["diff_base"])


if __name__ == "__main__":
    unittest.main()
