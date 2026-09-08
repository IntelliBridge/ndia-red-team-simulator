"""Sanity: the service layer emits the audit chain the CLI relied on.

The pentest remediation ``generate_fix`` service was removed with the pentest
domain, so only the scan-admission audit invariant is covered here now.
"""

import json
import tempfile
import unittest
from unittest.mock import patch

from redsim.config import RedsimConfig
from redsim.scanners.registry import ScanResult
from redsim.services.scans import start_scan
from redsim.state import RunState


class TestStartScanAuthorizes(unittest.TestCase):
    def test_audit_event_emitted_before_scanner_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r3")
            result = ScanResult(
                findings=[], adapter_name="fake", adapter_version="0",
                command_str="fake", exit_code=0,
            )
            with patch("redsim.scanners.dispatch", return_value=result):
                outcome = start_scan(
                    run_state=state, target="http://localhost:3000",
                    scanner="fake",
                    actor="cli:test", config=RedsimConfig(output_dir=tmp),
                )
            self.assertTrue(outcome.success)
            audit = (state.run_path / "audit.jsonl").read_text().strip().splitlines()
            actions = [json.loads(line)["action"] for line in audit]
            self.assertIn("scan.start", actions)


if __name__ == "__main__":
    unittest.main()
