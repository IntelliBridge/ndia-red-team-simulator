import json
import tempfile
import unittest
from pathlib import Path

from aegis.scanners.registry import ScanOptions
from aegis.scanners.syft_adapter import SyftAdapter, _summarize_sbom
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestSyftAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "syft_raw.json") as f:
            self.doc = json.load(f)

    def test_summarize_sbom(self):
        self.assertEqual(_summarize_sbom(self.doc), len(self.doc["components"]))
        self.assertEqual(_summarize_sbom(self.doc), 1)
        self.assertEqual(_summarize_sbom({}), 0)

    def test_capabilities(self):
        self.assertEqual(SyftAdapter().capabilities, {"sbom"})

    def test_scan_missing_binary_returns_empty_findings(self):
        # No syft binary on PATH -> FileNotFoundError path -> findings == [].
        with tempfile.TemporaryDirectory() as tmp:
            rs = RunState(tmp, run_id="run-123")
            result = SyftAdapter().scan(rs, ScanOptions(target="x"))
            self.assertEqual(result.findings, [])
            self.assertEqual(result.adapter_name, "syft")


if __name__ == "__main__":
    unittest.main()
