"""Unit tests for the ``jobs.status`` transition guard
(``aegis.workers.job_state``).

Fully offline and DB-free: ``set_job_status`` operates structurally on
anything carrying a ``status`` attribute, so a tiny ``SimpleNamespace`` stands
in for a real ``Job`` row. The tests pin the transition matrix against the
plan spec (``queued → {running, cancelled}``, ``running → {succeeded, failed,
cancelled, queued}``, terminal → ∅) so a future edit that widens or narrows
the lifecycle has to update them deliberately.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from aegis.workers.job_state import (
    ALLOWED,
    IllegalJobTransition,
    set_job_status,
)

# All statuses the lifecycle knows about.
ALL_STATES = ("queued", "running", "succeeded", "failed", "cancelled")
TERMINAL = ("succeeded", "failed", "cancelled")


def _job(status: str) -> SimpleNamespace:
    return SimpleNamespace(status=status)


class TestAllowedMap(unittest.TestCase):
    """The map itself is the contract; pin it to the spec."""

    def test_map_matches_spec_exactly(self):
        self.assertEqual(
            ALLOWED,
            {
                "queued": {"running", "cancelled"},
                "running": {"succeeded", "failed", "cancelled", "queued"},
                "succeeded": set(),
                "failed": set(),
                "cancelled": set(),
            },
        )

    def test_terminal_states_have_no_outgoing_edges(self):
        for state in TERMINAL:
            self.assertEqual(ALLOWED[state], set(), state)

    def test_every_state_is_a_key(self):
        # No state may be implicitly terminal-by-omission; each is explicit.
        self.assertEqual(set(ALLOWED), set(ALL_STATES))


class TestLegalTransitions(unittest.TestCase):
    def test_queued_to_running(self):
        job = _job("queued")
        set_job_status(job, "running")
        self.assertEqual(job.status, "running")

    def test_queued_to_cancelled(self):
        job = _job("queued")
        set_job_status(job, "cancelled")
        self.assertEqual(job.status, "cancelled")

    def test_running_to_succeeded(self):
        job = _job("running")
        set_job_status(job, "succeeded")
        self.assertEqual(job.status, "succeeded")

    def test_running_to_failed(self):
        job = _job("running")
        set_job_status(job, "failed")
        self.assertEqual(job.status, "failed")

    def test_running_to_cancelled(self):
        job = _job("running")
        set_job_status(job, "cancelled")
        self.assertEqual(job.status, "cancelled")

    def test_running_to_queued_is_the_transient_retry_requeue(self):
        # The one "backwards" edge: task_context resets a rolled-back body to
        # queued so the redelivery guard lets the retry run.
        job = _job("running")
        set_job_status(job, "queued")
        self.assertEqual(job.status, "queued")

    def test_every_allowed_edge_is_accepted(self):
        # Exhaustively walk the matrix: each declared edge must be accepted.
        for current, targets in ALLOWED.items():
            for new in targets:
                job = _job(current)
                set_job_status(job, new)
                self.assertEqual(job.status, new, f"{current} -> {new}")


class TestIllegalTransitions(unittest.TestCase):
    def test_terminal_states_reject_all_transitions(self):
        # A redelivered/late terminal job can never be resurrected — this is
        # what makes the redelivery guard fail-closed.
        for current in TERMINAL:
            for new in ALL_STATES:
                if new == current:
                    continue  # no-op self-write handled elsewhere
                job = _job(current)
                with self.assertRaises(IllegalJobTransition, msg=f"{current}->{new}"):
                    set_job_status(job, new)
                self.assertEqual(job.status, current)  # row untouched

    def test_queued_cannot_skip_straight_to_succeeded(self):
        job = _job("queued")
        with self.assertRaises(IllegalJobTransition):
            set_job_status(job, "succeeded")
        self.assertEqual(job.status, "queued")

    def test_queued_cannot_skip_straight_to_failed(self):
        job = _job("queued")
        with self.assertRaises(IllegalJobTransition):
            set_job_status(job, "failed")
        self.assertEqual(job.status, "queued")

    def test_unknown_current_status_is_terminal_and_rejects(self):
        # A status not in the map has no outgoing edges (defensive default).
        job = _job("bogus")
        with self.assertRaises(IllegalJobTransition):
            set_job_status(job, "running")
        self.assertEqual(job.status, "bogus")

    def test_every_disallowed_edge_is_rejected(self):
        # The complement of the allowed matrix must raise — except no-op
        # self-writes, which are intentionally permitted (tested separately).
        for current in ALL_STATES:
            allowed = ALLOWED.get(current, set())
            for new in ALL_STATES:
                if new == current or new in allowed:
                    continue
                job = _job(current)
                with self.assertRaises(IllegalJobTransition, msg=f"{current}->{new}"):
                    set_job_status(job, new)

    def test_exception_carries_context(self):
        job = _job("succeeded")
        with self.assertRaises(IllegalJobTransition) as cm:
            set_job_status(job, "running")
        self.assertEqual(cm.exception.current, "succeeded")
        self.assertEqual(cm.exception.new, "running")
        self.assertIsInstance(cm.exception, ValueError)  # back-compat base
        self.assertIn("succeeded", str(cm.exception))
        self.assertIn("running", str(cm.exception))


class TestIdempotentSelfTransition(unittest.TestCase):
    def test_same_status_is_a_noop_for_every_state(self):
        # Re-writing the current status (including terminal) must never raise;
        # the row is left as-is.
        for state in ALL_STATES:
            job = _job(state)
            set_job_status(job, state)
            self.assertEqual(job.status, state)


if __name__ == "__main__":
    unittest.main()
