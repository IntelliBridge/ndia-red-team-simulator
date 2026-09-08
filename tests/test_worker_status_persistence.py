"""Phase 4 v0.3.1 F11 — workers persist Finding status / validation_state.

This is a unit-level check on the mapping logic; the full Celery
round-trip lives in the integration suite (which runs against the
live Postgres + worker stack).
"""

from __future__ import annotations

import unittest

import pytest

pytest.importorskip("sqlalchemy")


class TestVerifyStateMap(unittest.TestCase):
    def test_verify_status_to_validation_state_mapping(self):
        from redsim.workers.tasks.verify import _STATE_MAP
        self.assertEqual(_STATE_MAP["verified"], "poc_passed")
        self.assertEqual(_STATE_MAP["still_vulnerable"], "poc_failed")
        self.assertEqual(_STATE_MAP["inconclusive"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
