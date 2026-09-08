"""Unit tests for the stale-job reaper (``redsim.workers.tasks.reaper``).

Offline + DB-free: the shared sqlite in-memory harness
(``make_sqlite_session_factory`` from ``tests/conftest.py``) hosts the
schema so we can seed real ``Job`` rows and exercise
``reap_stale_jobs_in_session`` directly. An explicit ``now`` keeps the TTL
boundary deterministic.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("sqlalchemy")

from redsim.db.models import Job, Organization, Project, Run
from redsim.workers.tasks.reaper import reap_stale_jobs_in_session
from tests.conftest import make_sqlite_session_factory as _make_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration

TTL_SECONDS = 3600
NOW = datetime(2026, 6, 8, 12, 0, 0, tzinfo=UTC)


def _seed_org_project_run(Session) -> None:
    """Seed the FK chain (Org → Project → Run) the Job rows reference."""
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.add(Run(id="run-1", project_id="proj-1"))
        s.commit()


def _make_job(job_id: str, status: str, started_at: datetime | None) -> Job:
    return Job(
        id=job_id, run_id="run-1", project_id="proj-1",
        type="scan.start", status=status, started_at=started_at,
    )


class TestReaper(unittest.TestCase):
    def setUp(self) -> None:
        self.session_cm, _, self.Session = _make_session_factory()
        _seed_org_project_run(self.Session)

    def test_stale_running_job_is_failed(self):
        # started before the TTL window → reaped.
        old = NOW - timedelta(seconds=TTL_SECONDS + 1)
        with self.Session() as s:
            s.add(_make_job("job-stale", "running", old))
            s.commit()

        with self.session_cm() as s:
            reaped = reap_stale_jobs_in_session(s, TTL_SECONDS, now=NOW)

        self.assertEqual(reaped, 1)
        with self.Session() as s:
            job = s.get(Job, "job-stale")
            self.assertEqual(job.status, "failed")
            # sqlite drops tzinfo on round-trip from a timezone=True column,
            # so compare the wall-clock value rather than the aware datetime.
            self.assertIsNotNone(job.completed_at)
            self.assertEqual(job.completed_at.replace(tzinfo=UTC), NOW)
            self.assertEqual(job.error, "reaped: exceeded max runtime TTL")

    def test_fresh_running_job_is_untouched(self):
        # started inside the TTL window (and exactly at the boundary) → kept.
        recent = NOW - timedelta(seconds=TTL_SECONDS - 1)
        boundary = NOW - timedelta(seconds=TTL_SECONDS)
        with self.Session() as s:
            s.add(_make_job("job-fresh", "running", recent))
            s.add(_make_job("job-boundary", "running", boundary))
            s.commit()

        with self.session_cm() as s:
            reaped = reap_stale_jobs_in_session(s, TTL_SECONDS, now=NOW)

        self.assertEqual(reaped, 0)
        with self.Session() as s:
            for jid in ("job-fresh", "job-boundary"):
                job = s.get(Job, jid)
                self.assertEqual(job.status, "running")
                self.assertIsNone(job.completed_at)
                self.assertIsNone(job.error)

    def test_non_running_jobs_are_untouched(self):
        # queued/succeeded/failed are never reaped, even if old.
        old = NOW - timedelta(seconds=TTL_SECONDS + 999)
        with self.Session() as s:
            s.add(_make_job("job-queued", "queued", None))
            s.add(_make_job("job-succeeded", "succeeded", old))
            s.add(_make_job("job-failed", "failed", old))
            s.commit()

        with self.session_cm() as s:
            reaped = reap_stale_jobs_in_session(s, TTL_SECONDS, now=NOW)

        self.assertEqual(reaped, 0)
        with self.Session() as s:
            self.assertEqual(s.get(Job, "job-queued").status, "queued")
            self.assertEqual(s.get(Job, "job-succeeded").status, "succeeded")
            self.assertEqual(s.get(Job, "job-failed").status, "failed")

    def test_returns_correct_reaped_count(self):
        # Two stale running jobs alongside fresh/non-running noise → count is 2.
        old = NOW - timedelta(seconds=TTL_SECONDS + 10)
        recent = NOW - timedelta(seconds=10)
        with self.Session() as s:
            s.add(_make_job("stale-1", "running", old))
            s.add(_make_job("stale-2", "running", old))
            s.add(_make_job("fresh-1", "running", recent))
            s.add(_make_job("queued-1", "queued", None))
            s.commit()

        with self.session_cm() as s:
            reaped = reap_stale_jobs_in_session(s, TTL_SECONDS, now=NOW)

        self.assertEqual(reaped, 2)
        with self.Session() as s:
            self.assertEqual(s.get(Job, "stale-1").status, "failed")
            self.assertEqual(s.get(Job, "stale-2").status, "failed")
            self.assertEqual(s.get(Job, "fresh-1").status, "running")
            self.assertEqual(s.get(Job, "queued-1").status, "queued")


if __name__ == "__main__":
    unittest.main()
