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

    def test_audit_writer_threaded_through_to_client(self):
        # Phase 4 v0.3.1 F8: tool-calls.jsonl is retired. The KaliClient now
        # routes per-call audit events through the canonical chain. When the
        # caller passes only ``run_path`` (no explicit writer), the toolbelt
        # constructs the offline-mode ``JsonlAuditWriter`` in single-file
        # mode at ``<run_path>/audit.jsonl`` (matching the safety layer).
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            toolbelt = build_kali_toolbelt(AegisConfig(), run_path=run_path)
            self.assertIsNotNone(toolbelt.client.audit_writer)
            self.assertIsInstance(toolbelt.client.audit_writer, JsonlAuditWriter)
            # And there is no audit_path attribute on the client any more.
            self.assertFalse(hasattr(toolbelt.client, "audit_path"))


if __name__ == "__main__":
    unittest.main()
