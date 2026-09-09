"""Spec 6.2 run-status roll-up (``services.runs.rollup_run_status``), the
reaper's use of it, and the cancel-on-terminal refusal (``run_terminal``).

Offline: the shared sqlite harness (``tests/conftest.py``) hosts the schema
so real ``Run`` / ``Job`` rows drive the rules. Every rule in the 6.2 table
gets a case, plus the invariant the table exists to protect: a terminal run
is never reopened by a later job.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("sqlalchemy")

from redsim.db.models import Job, Organization, Project, Run
from redsim.services.runs import (
    TERMINAL_RUN_STATUSES,
    TerminalRunError,
    cancel_run,
    rollup_run_status,
)
from redsim.workers.tasks.reaper import REAPED_ERROR, reap_stale_jobs_in_session
from tests.conftest import make_sqlite_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)
TTL = 3600


def _seed(Session: Any, run_status: str = "running") -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.add(Run(id="run-1", project_id="proj-1", status=run_status))
        s.commit()


def _job(job_id: str, status: str, **extra: Any) -> Job:
    return Job(
        id=job_id, run_id="run-1", project_id="proj-1",
        type=extra.pop("type", "attack.run"), status=status, **extra,
    )


class _Recorder:
    """Minimal AuditWriter double: records every appended row."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **event: Any) -> Any:
        self.events.append(event)
        return SimpleNamespace(**event)


class TestRollupRules(unittest.TestCase):
    def setUp(self) -> None:
        self.session_cm, _, self.Session = make_sqlite_session_factory()
        _seed(self.Session)

    def _rollup(self, *job_statuses: str, run_status: str = "running") -> tuple[str, str, Any]:
        with self.Session() as s:
            run = s.get(Run, "run-1")
            run.status = run_status
            run.completed_at = None
            for i, status in enumerate(job_statuses):
                s.add(_job(f"job-{i}", status))
            s.commit()
        with self.session_cm() as s:
            returned = rollup_run_status(s, "run-1")
        with self.Session() as s:
            run = s.get(Run, "run-1")
            return returned, run.status, run.completed_at

    def test_all_queued_is_queued(self):
        returned, stored, completed = self._rollup("queued", "queued")
        self.assertEqual((returned, stored), ("queued", "queued"))
        self.assertIsNone(completed)

    def test_any_running_is_running(self):
        returned, stored, completed = self._rollup("succeeded", "running", "queued")
        self.assertEqual((returned, stored), ("running", "running"))
        self.assertIsNone(completed)

    def test_mix_of_queued_and_terminal_is_running(self):
        returned, stored, _ = self._rollup("succeeded", "queued")
        self.assertEqual((returned, stored), ("running", "running"))

    def test_all_terminal_with_success_and_no_failure_is_succeeded(self):
        returned, stored, completed = self._rollup("succeeded", "succeeded", "cancelled")
        self.assertEqual((returned, stored), ("succeeded", "succeeded"))
        self.assertIsNotNone(completed)  # completed_at set on the terminal edge

    def test_any_failed_among_terminal_is_failed(self):
        returned, stored, completed = self._rollup("succeeded", "failed")
        self.assertEqual((returned, stored), ("failed", "failed"))
        self.assertIsNotNone(completed)

    def test_all_cancelled_is_cancelled(self):
        returned, stored, _ = self._rollup("cancelled", "cancelled")
        self.assertEqual((returned, stored), ("cancelled", "cancelled"))

    def test_no_jobs_leaves_status_alone(self):
        returned, stored, _ = self._rollup(run_status="running")
        self.assertEqual((returned, stored), ("running", "running"))

    def test_running_rollup_clears_completed_at(self):
        with self.Session() as s:
            run = s.get(Run, "run-1")
            run.completed_at = NOW
            s.add(_job("job-0", "running"))
            s.commit()
        with self.session_cm() as s:
            self.assertEqual(rollup_run_status(s, "run-1"), "running")
        with self.Session() as s:
            self.assertIsNone(s.get(Run, "run-1").completed_at)

    def test_terminal_run_is_never_reopened(self):
        # Spec 6.2: follow-on jobs attach to the run but do not reopen it.
        for terminal in sorted(TERMINAL_RUN_STATUSES):
            with self.subTest(terminal=terminal):
                with self.Session() as s:
                    for job in s.query(Job).all():
                        s.delete(job)
                    s.commit()
                returned, stored, _ = self._rollup("queued", "running", run_status=terminal)
                self.assertEqual((returned, stored), (terminal, terminal))

    def test_cancelled_run_stays_cancelled_even_when_jobs_succeeded(self):
        returned, stored, _ = self._rollup("succeeded", run_status="cancelled")
        self.assertEqual((returned, stored), ("cancelled", "cancelled"))

    def test_missing_run_raises_lookup_error(self):
        with self.session_cm() as s:
            with self.assertRaises(LookupError):
                rollup_run_status(s, "run-does-not-exist")


class TestReaperRollsRunUp(unittest.TestCase):
    def setUp(self) -> None:
        self.session_cm, _, self.Session = make_sqlite_session_factory()
        _seed(self.Session)

    def test_reaped_last_job_makes_run_failed(self):
        with self.Session() as s:
            s.add(_job("job-stale", "running", started_at=NOW - timedelta(seconds=TTL + 5)))
            s.add(_job("job-done", "succeeded", started_at=NOW - timedelta(seconds=TTL + 50)))
            s.commit()
        with self.session_cm() as s:
            self.assertEqual(reap_stale_jobs_in_session(s, TTL, now=NOW), 1)
        with self.Session() as s:
            run = s.get(Run, "run-1")
            self.assertEqual(run.status, "failed")
            self.assertIsNotNone(run.completed_at)
            entry = run.stage_table["jobs"]["job-stale"]
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["error"], REAPED_ERROR)
            self.assertEqual(run.stage_table["error"], REAPED_ERROR)

    def test_run_with_live_job_stays_running(self):
        with self.Session() as s:
            s.add(_job("job-stale", "running", started_at=NOW - timedelta(seconds=TTL + 5)))
            s.add(_job("job-live", "running", started_at=NOW - timedelta(seconds=5)))
            s.commit()
        with self.session_cm() as s:
            self.assertEqual(reap_stale_jobs_in_session(s, TTL, now=NOW), 1)
        with self.Session() as s:
            run = s.get(Run, "run-1")
            self.assertEqual(run.status, "running")
            self.assertIsNone(run.completed_at)
            self.assertEqual(s.get(Job, "job-live").status, "running")

    def test_cancelled_run_is_left_alone(self):
        with self.Session() as s:
            s.get(Run, "run-1").status = "cancelled"
            s.add(_job("job-stale", "running", started_at=NOW - timedelta(seconds=TTL + 5)))
            s.commit()
        with self.session_cm() as s:
            self.assertEqual(reap_stale_jobs_in_session(s, TTL, now=NOW), 1)
        with self.Session() as s:
            self.assertEqual(s.get(Job, "job-stale").status, "failed")
            self.assertEqual(s.get(Run, "run-1").status, "cancelled")


class TestCancelTerminalRun(unittest.TestCase):
    """``cancel_run`` on a terminal run: ``TerminalRunError`` (HTTP 409
    ``run_terminal`` at the route) plus a ``success=False`` audit row."""

    def setUp(self) -> None:
        self.session_cm, _, self.Session = make_sqlite_session_factory()
        self.config = SimpleNamespace(target_allowlist=[])

    def _cancel(self, recorder: _Recorder) -> Any:
        with patch("redsim.db.session.get_session", self.session_cm):
            return cancel_run(
                run_id="run-1", actor="user:alice",
                config=self.config, audit_writer=recorder,  # type: ignore[arg-type]
            )

    def test_terminal_run_refused_with_audit_row(self):
        for terminal in sorted(TERMINAL_RUN_STATUSES):
            with self.subTest(terminal=terminal):
                self.session_cm, _, self.Session = make_sqlite_session_factory()
                _seed(self.Session, run_status=terminal)
                recorder = _Recorder()
                with self.assertRaises(TerminalRunError) as cm:
                    self._cancel(recorder)
                self.assertEqual(cm.exception.code, "run_terminal")
                self.assertEqual(cm.exception.run_status, terminal)
                self.assertEqual(len(recorder.events), 1)
                row = recorder.events[0]
                self.assertEqual(row["action"], "run.cancel")
                self.assertFalse(row["success"])
                self.assertEqual(row["detail"]["reason"], "run_terminal")
                self.assertEqual(row["detail"]["run_status"], terminal)
                with self.Session() as s:
                    self.assertEqual(s.get(Run, "run-1").status, terminal)

    def test_live_run_is_cancelled_after_audit(self):
        _seed(self.Session, run_status="running")
        with self.Session() as s:
            s.add(_job("job-q", "queued"))
            s.add(_job("job-r", "running", started_at=NOW))
            s.add(_job("job-done", "succeeded"))
            s.commit()
        recorder = _Recorder()
        outcome = self._cancel(recorder)
        self.assertEqual((outcome.status, outcome.jobs_cancelled), ("cancelled", 2))
        self.assertEqual([e["action"] for e in recorder.events], ["run.cancel"])
        self.assertTrue(recorder.events[0]["success"])
        with self.Session() as s:
            self.assertEqual(s.get(Run, "run-1").status, "cancelled")
            self.assertEqual(s.get(Job, "job-q").status, "cancelled")
            self.assertEqual(s.get(Job, "job-r").status, "cancelled")
            self.assertEqual(s.get(Job, "job-done").status, "succeeded")

    def test_missing_run_is_lookup_error_without_audit(self):
        recorder = _Recorder()
        with self.assertRaises(LookupError):
            self._cancel(recorder)
        self.assertEqual(recorder.events, [])


if __name__ == "__main__":
    unittest.main()
