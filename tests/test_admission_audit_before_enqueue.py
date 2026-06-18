"""Phase 4 v0.3.1 F6 — admission service contract.

Verifies that every admission service:

1. Emits the chain audit row through the supplied writer.
2. Inserts the Run + Job rows after the audit row exists.
3. Only then enqueues the Celery task.

This is the load-bearing ordering invariant for the v0.3.1 release gate:
if the worker crashes between the audit row and the task pickup, the row
is still on the chain and the job is queued — never a half-state.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("sqlalchemy")

from aegis.audit.chain import InMemoryAuditWriter
from aegis.config import AegisConfig
from aegis.db.models import Finding, Organization, Project, Run
from aegis.services.fixes import create_fix_job
from aegis.services.runs import cancel_run
from aegis.services.scans import create_scan_job
from aegis.services.verify import create_verify_job
from tests.conftest import make_sqlite_session_factory as _make_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration


def _seed_project(Session) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.commit()


class TestAdmissionAuditBeforeEnqueue(unittest.TestCase):
    def test_scan_admission_emits_chain_row_before_celery(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()
        enqueue_calls: list[str] = []

        def fake_delay(job_id):
            # Audit row must already exist by the time Celery is touched.
            self.assertEqual(len(writer.events), 1,
                             "audit row must exist before enqueue")
            enqueue_calls.append(job_id)

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.workers.tasks.scan.scan_start") as scan_start:
            scan_start.delay = fake_delay
            handle = create_scan_job(
                target="http://localhost:3000",
                scanner="strix", project_id="proj-1",
                actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer,
            )

        # Audit row landed on the chain
        events = writer.events
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].action, "scan.start")
        self.assertEqual(events[0].success, True)
        self.assertEqual(events[0].allowlist_check, "pass")

        # Run + Job were persisted
        with Session() as s:
            run = s.get(Run, handle.run_id)
            self.assertIsNotNone(run)
            self.assertEqual(run.status, "queued")
            from aegis.db.models import Job
            job = s.get(Job, handle.job_id)
            self.assertIsNotNone(job)
            self.assertEqual(job.status, "queued")
            # celery_task_id is stamped by the worker on pickup, not at
            # admission time — so it remains NULL here.
            self.assertIsNone(job.celery_task_id)

        # Celery enqueue happened *after* the audit row (asserted in fake_delay)
        self.assertEqual(enqueue_calls, [handle.job_id])

    def test_scan_admission_refuses_unauthorised_target(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        from aegis.safety import AuthorizationError
        with patch("aegis.db.session.get_session", session_cm):
            with self.assertRaises(AuthorizationError):
                create_scan_job(
                    target="http://attacker.example.com",
                    scanner="strix", project_id="proj-1",
                    actor="user:test",
                    config=AegisConfig(target_allowlist=["localhost"]),
                    audit_writer=writer,
                )

        # The refusal still lands on the chain as a fail
        self.assertEqual(len(writer.events), 1)
        self.assertEqual(writer.events[0].action, "scan.start")
        self.assertEqual(writer.events[0].allowlist_check, "fail")
        self.assertFalse(writer.events[0].success)

        # And no Run/Job rows were inserted
        with Session() as s:
            self.assertEqual(s.query(Run).count(), 0)

    def test_fix_admission_emits_chain_row_before_celery(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        with Session() as s:
            s.add(Run(id="run-1", project_id="proj-1",
                      mode="api", status="queued", stage_table={}))
            s.add(Finding(
                id="f-uuid-1", scanner_finding_id="vuln-0001",
                run_id="run-1", project_id="proj-1",
                schema_blob={"id": "vuln-0001"},
                severity="high",
            ))
            s.commit()

        writer = InMemoryAuditWriter()
        enqueue_calls: list[str] = []

        def fake_delay(job_id):
            self.assertEqual(len(writer.events), 1)
            enqueue_calls.append(job_id)

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.workers.tasks.fix.fix_generate") as fix_generate:
            fix_generate.delay = fake_delay
            handle = create_fix_job(
                finding_id="f-uuid-1", strategy="patch", apply=False,
                project_id="proj-1", run_id="run-1",
                actor="user:test",
                config=AegisConfig(),
                audit_writer=writer,
            )

        self.assertEqual(len(writer.events), 1)
        self.assertEqual(writer.events[0].action, "fix.generate")
        self.assertEqual(enqueue_calls, [handle.job_id])

    def test_verify_admission_emits_chain_row_before_celery(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        with Session() as s:
            s.add(Run(id="run-1", project_id="proj-1",
                      mode="api", status="queued", stage_table={}))
            s.commit()

        writer = InMemoryAuditWriter()
        enqueue_calls: list[str] = []

        def fake_delay(job_id):
            self.assertEqual(len(writer.events), 1)
            enqueue_calls.append(job_id)

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.workers.tasks.verify.verify_replay") as verify_replay:
            verify_replay.delay = fake_delay
            handle = create_verify_job(
                finding_id="f-1", project_id="proj-1", run_id="run-1",
                actor="user:test", config=AegisConfig(),
                audit_writer=writer,
            )

        self.assertEqual(writer.events[0].action, "verify.replay")
        self.assertEqual(enqueue_calls, [handle.job_id])

    def test_cancel_emits_chain_row_then_marks_cancelled(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        from aegis.db.models import Job
        with Session() as s:
            s.add(Run(id="run-1", project_id="proj-1",
                      mode="api", status="running", stage_table={}))
            s.add(Job(id="job-1", run_id="run-1", project_id="proj-1",
                      type="scan.start", status="running"))
            s.commit()

        writer = InMemoryAuditWriter()
        with patch("aegis.db.session.get_session", session_cm):
            outcome = cancel_run(
                run_id="run-1", actor="user:test",
                config=AegisConfig(), audit_writer=writer,
            )

        self.assertEqual(outcome.status, "cancelled")
        self.assertEqual(outcome.jobs_cancelled, 1)
        self.assertEqual(writer.events[0].action, "run.cancel")
        with Session() as s:
            run = s.get(Run, "run-1")
            self.assertEqual(run.status, "cancelled")
            self.assertIsNotNone(run.completed_at)


if __name__ == "__main__":
    unittest.main()
