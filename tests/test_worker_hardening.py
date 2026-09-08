"""Phase 4 worker hardening: task_context status persistence + transient
retry, the Redis event publisher, and Celery queue routing.

These drive the *real* ``task_context`` (its DB/blob/audit deps are patched at
the boundary) — unlike test_worker_tasks_coverage.py, which mocks task_context
to exercise task bodies. Fully offline: no Redis, Postgres, or network.
"""

from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from redsim.workers import bootstrap, events


def _fake_job(status: str = "queued") -> SimpleNamespace:
    return SimpleNamespace(
        status=status, started_at="set", completed_at=None, error=None,
        run_id="run-1", project_id="proj-1", created_by="user:alice",
    )


@contextmanager
def _patched(job: SimpleNamespace):
    """Patch task_context's boundary deps; yield (session_mock, publish_mock)."""
    sess = MagicMock()
    sess.get.return_value = job

    @contextmanager
    def fake_get_session():
        yield sess

    with patch("redsim.db.session.get_session", fake_get_session), \
         patch("redsim.db.session.init_engine"), \
         patch("redsim.config.load_config",
               return_value=SimpleNamespace(output_dir="/tmp")), \
         patch("redsim.storage.open_blob_store", return_value=MagicMock()), \
         patch("redsim.state.PostgresRunState", return_value=MagicMock()), \
         patch("redsim.audit.chain.PostgresAuditWriter", return_value=MagicMock()), \
         patch("redsim.workers.events.publish_job_event") as pub:
        yield sess, pub


def _statuses(pub: MagicMock) -> list[str]:
    return [c.args[2] for c in pub.call_args_list]


class TestTaskContextLifecycle(unittest.TestCase):
    def test_success_marks_succeeded_and_publishes_after(self):
        job = _fake_job()
        with _patched(job) as (sess, pub):
            with bootstrap.task_context("job-1") as ctx:
                self.assertFalse(ctx.skip)
            self.assertEqual(job.status, "succeeded")
            self.assertIsNotNone(job.completed_at)
        self.assertEqual(_statuses(pub), ["running", "succeeded"])

    def test_terminal_failure_persists_failed_status(self):
        """Regression: get_session() rolls back on exception, so the 'failed'
        write must be committed by task_context itself or the job is stranded
        'running'."""
        job = _fake_job()
        with _patched(job) as (sess, pub):
            with self.assertRaises(ValueError):
                with bootstrap.task_context("job-1"):
                    raise ValueError("boom")
            self.assertEqual(job.status, "failed")
            self.assertIn("ValueError", job.error)
            self.assertTrue(sess.commit.called)  # committed, not left pending
        self.assertEqual(_statuses(pub), ["running", "failed"])

    def test_skip_path_publishes_nothing(self):
        job = _fake_job(status="cancelled")
        with _patched(job) as (sess, pub):
            with bootstrap.task_context("job-1") as ctx:
                self.assertTrue(ctx.skip)
        pub.assert_not_called()


class TestTransientRetry(unittest.TestCase):
    def _bound_task(self, retries: int, max_retries: int = 2) -> MagicMock:
        from celery.exceptions import Retry
        task = MagicMock()
        task.request.retries = retries
        task.max_retries = max_retries
        task.retry.side_effect = Retry()
        return task

    def _operational_error(self):
        from sqlalchemy.exc import OperationalError
        return OperationalError("SELECT 1", {}, Exception("db gone"))

    def test_transient_error_requeues_instead_of_failing(self):
        """A retried task must NOT be left 'failed' (the redelivery guard would
        skip it); it's reset to 'queued' so the retry can run."""
        from celery.exceptions import Retry
        job = _fake_job()
        task = self._bound_task(retries=0)
        with _patched(job) as (sess, pub):
            with self.assertRaises(Retry):
                with bootstrap.task_context("job-1", task=task):
                    raise self._operational_error()
            self.assertEqual(job.status, "queued")
            self.assertIsNone(job.started_at)
            task.retry.assert_called_once()
        self.assertNotIn("failed", _statuses(pub))

    def test_transient_error_marks_failed_when_retries_exhausted(self):
        from sqlalchemy.exc import OperationalError
        job = _fake_job()
        task = self._bound_task(retries=2)  # retries == max_retries
        with _patched(job) as (sess, pub):
            with self.assertRaises(OperationalError):
                with bootstrap.task_context("job-1", task=task):
                    raise self._operational_error()
            self.assertEqual(job.status, "failed")
            task.retry.assert_not_called()


class TestPublishJobEvent(unittest.TestCase):
    def test_publishes_to_run_channel_with_payload(self):
        client = MagicMock()
        with patch.object(events, "_redis_client", return_value=client):
            events.publish_job_event("run-9", "job-9", "running", extra_k="v")
        client.publish.assert_called_once()
        channel, data = client.publish.call_args.args
        self.assertEqual(channel, "run:run-9:events")
        self.assertEqual(
            json.loads(data),
            {"type": "job", "run_id": "run-9", "job_id": "job-9",
             "status": "running", "extra_k": "v"},
        )

    def test_swallows_redis_errors(self):
        client = MagicMock()
        client.publish.side_effect = RuntimeError("redis down")
        with patch.object(events, "_redis_client", return_value=client):
            events.publish_job_event("r", "j", "failed")  # must not raise

    def test_noop_when_redis_unavailable(self):
        with patch.object(events, "_redis_client", return_value=None):
            events.publish_job_event("r", "j", "running")  # must not raise


class TestQueueRouting(unittest.TestCase):
    def test_long_tasks_route_to_scans(self):
        from redsim.workers.celery_app import app
        routes = app.conf.task_routes
        for name in ("redsim.scan_start", "redsim.verify_replay"):
            self.assertEqual(routes[name]["queue"], "scans", name)

    def test_short_tasks_route_to_default(self):
        from redsim.workers.celery_app import app
        routes = app.conf.task_routes
        for name in ("redsim.report_render", "redsim.reap_stale_jobs",
                     "redsim.verify_tenant_integrity",
                     "redsim.export_chains_to_worm"):
            self.assertEqual(routes[name]["queue"], "default", name)
        self.assertEqual(app.conf.task_default_queue, "default")

    def test_removed_pentest_tasks_are_not_routed(self):
        # fix / agent / vuln-fixer / CI-gate / parallel_fix tasks were removed
        # with the pentest domain; no dead routes linger in the table.
        from redsim.workers.celery_app import app
        routes = app.conf.task_routes
        for name in ("redsim.fix_generate", "redsim.agent_run",
                     "redsim.vulnfixer_render", "redsim.ci_gate",
                     "redsim.parallel_fix"):
            self.assertNotIn(name, routes)
        # Every routed task name is one the app actually includes.
        self.assertEqual(
            set(routes),
            {"redsim.scan_start", "redsim.verify_replay", "redsim.report_render",
             "redsim.reap_stale_jobs", "redsim.verify_tenant_integrity",
             "redsim.export_chains_to_worm"},
        )


if __name__ == "__main__":
    unittest.main()
