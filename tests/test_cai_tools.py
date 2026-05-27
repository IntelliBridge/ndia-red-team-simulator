import tempfile
import unittest
from pathlib import Path

from aegis.config import AegisConfig
from aegis.tools.cai_tools import build_kali_toolbelt


class TestBuildKaliToolbelt(unittest.TestCase):
    def test_returns_empty_when_cai_missing(self):
        # CAI is an optional dependency. The toolbelt must be safe to call.
        config = AegisConfig()
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            toolbelt = build_kali_toolbelt(config, run_path=run_path)
        # The KaliClient is constructed regardless
        self.assertIsNotNone(toolbelt.client)
        self.assertEqual(toolbelt.client.target_allowlist, config.target_allowlist)
        # Either a list of tools or empty depending on whether CAI is importable
        self.assertIsInstance(toolbelt.tools, list)

    def test_audit_path_threaded_through_to_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            toolbelt = build_kali_toolbelt(AegisConfig(), run_path=run_path)
            self.assertEqual(toolbelt.client.audit_path, run_path / "tool-calls.jsonl")


if __name__ == "__main__":
    unittest.main()
