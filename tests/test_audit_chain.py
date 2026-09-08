"""Hash-chain integrity tests (filesystem backend; Postgres parity is
exercised when REDSIM_TEST_DB_URL is set)."""

import json
import tempfile
import unittest
from pathlib import Path

from redsim.audit.chain import (
    JsonlAuditWriter,
    verify_chain,
)


class TestHappyPath(unittest.TestCase):
    def test_n_events_verify_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            for i in range(5):
                writer.append(
                    action="scan.start", actor="cli:alice",
                    target="http://localhost:3000",
                    allowlist_check="pass", override=False, success=True,
                    detail={"seq": i}, run_id="run-1", project_id="proj-1",
                )
            events = list(writer.read_chain("run:run-1"))
            self.assertEqual(len(events), 5)
            result = verify_chain(events)
            self.assertTrue(result.verified, msg=result.reason)
            self.assertEqual(result.count, 5)


class TestTamperDetection(unittest.TestCase):
    def _writer(self, tmp: str) -> JsonlAuditWriter:
        return JsonlAuditWriter(Path(tmp))

    def test_mutation_breaks_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            for i in range(3):
                writer.append(
                    action="a", actor="cli", target="localhost",
                    allowlist_check="pass", override=False, success=True,
                    detail={"i": i}, run_id="r", project_id="p",
                )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            tampered = json.loads(lines[1])
            tampered["detail"]["i"] = 999
            lines[1] = json.dumps(tampered)
            chain_path.write_text("\n".join(lines) + "\n")
            events = list(writer.read_chain("run:r"))
            result = verify_chain(events)
            self.assertFalse(result.verified)
            self.assertEqual(result.broken_at, 2)
            self.assertIn("hash mismatch", result.reason)

    def test_deletion_breaks_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            for i in range(4):
                writer.append(
                    action="a", actor="cli", target="localhost",
                    allowlist_check="pass", override=False, success=True,
                    detail={"i": i}, run_id="r", project_id="p",
                )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            del lines[1]            # drop seq=2
            chain_path.write_text("\n".join(lines) + "\n")
            events = list(writer.read_chain("run:r"))
            result = verify_chain(events)
            self.assertFalse(result.verified)
            self.assertEqual(result.broken_at, 3)
            self.assertIn("seq gap", result.reason)

    def test_unknown_schema_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            writer.append(
                action="a", actor="cli", target="localhost",
                allowlist_check="pass", override=False, success=True,
                detail={"i": 0}, run_id="r", project_id="p",
            )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            rec = json.loads(chain_path.read_text().strip())
            rec["schema_version"] = 999
            chain_path.write_text(json.dumps(rec) + "\n")
            result = verify_chain(list(writer.read_chain("run:r")))
            self.assertFalse(result.verified)
            self.assertIn("schema_version", result.reason)


class TestRedaction(unittest.TestCase):
    def test_authorization_header_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(
                action="x", actor="cli", target=None,
                allowlist_check="n/a", override=False, success=True,
                detail={
                    "headers": {"Authorization": "Bearer ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "password": "hunter2",
                },
                run_id=None, project_id="p",
            )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            rec = json.loads(chain_path.read_text().strip())
            self.assertEqual(rec["detail"]["headers"]["Authorization"], "<REDACTED>")
            self.assertEqual(rec["detail"]["password"], "<REDACTED>")


if __name__ == "__main__":
    unittest.main()
