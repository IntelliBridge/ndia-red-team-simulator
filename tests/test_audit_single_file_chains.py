"""Single-file ``JsonlAuditWriter`` keeps interleaved chains independent.

When every chain lands in one ``audit.jsonl`` (Phase 2/3 compat path),
``_last``/``read_chain`` must filter by ``chain_id`` so two chains in the
same file don't corrupt each other's seq/prev_hash continuity. Offline
(no DB)."""

import tempfile
import unittest
from pathlib import Path

from aegis.audit.chain import JsonlAuditWriter, verify_chain


def _append(writer, run_id, action):
    return writer.append(
        action=action, actor="cli", target=None,
        allowlist_check="pass", override=False, success=True,
        detail={"action": action}, run_id=run_id,
    )


class TestSingleFileChainsStayIndependent(unittest.TestCase):
    def test_two_chains_in_one_file_stay_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp), single_file="audit.jsonl")
            # Interleave writes across two chains in one file.
            _append(writer, "r1", "a1")
            _append(writer, "r2", "b1")
            _append(writer, "r1", "a2")
            _append(writer, "r2", "b2")
            _append(writer, "r1", "a3")

            chain1 = list(writer.read_chain("run:r1"))
            chain2 = list(writer.read_chain("run:r2"))

            # read_chain returns only the requested chain's events.
            self.assertEqual([e["seq"] for e in chain1], [1, 2, 3])
            self.assertEqual([e["seq"] for e in chain2], [1, 2])
            self.assertTrue(all(e["chain_id"] == "run:r1" for e in chain1))
            self.assertTrue(all(e["chain_id"] == "run:r2" for e in chain2))
            self.assertEqual([e["action"] for e in chain1], ["a1", "a2", "a3"])
            self.assertEqual([e["action"] for e in chain2], ["b1", "b2"])

            # Each chain verifies independently despite sharing a file.
            r1 = verify_chain(chain1)
            r2 = verify_chain(chain2)
            self.assertTrue(r1.verified, msg=r1.reason)
            self.assertTrue(r2.verified, msg=r2.reason)
            self.assertEqual(r1.count, 3)
            self.assertEqual(r2.count, 2)


if __name__ == "__main__":
    unittest.main()
