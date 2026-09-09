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


def _fake_job(status: str = "queued", job_type: str = "scan.start") -> SimpleNamespace:
    return SimpleNamespace(
        status=status, started_at="set", completed_at=None, error=None,
        run_id="run-1", project_id="proj-1", created_by="user:alice",
        type=job_type, celery_task_id=None,
    )


class _AuditRecorder:
    """AuditWriter double standing in for PostgresAuditWriter."""

    def __init__(self, **_kwargs):
        self.events: list[dict] = []

    def append(self, **event):
        self.events.append(event)
        return SimpleNamespace(**event)


@contextmanager
def _patched(job: SimpleNamespace, audit: _AuditRecorder | None = None):
    """Patch task_context's boundary deps; yield (session_mock, publish_mock)."""
    sess = MagicMock()
    sess.get.return_value = job
    # Deterministic row counts for the job.complete detail (findings, artifacts).
    sess.execute.return_value.scalar.return_value = 3

    @contextmanager
    def fake_get_session():
        yield sess

    with patch("redsim.db.session.get_session", fake_get_session), \
         patch("redsim.db.session.init_engine"), \
         patch("redsim.config.load_config",
               return_value=SimpleNamespace(output_dir="/tmp")), \
         patch("redsim.storage.open_blob_store", return_value=MagicMock()), \
         patch("redsim.state.PostgresRunState", return_value=MagicMock()), \
         patch("redsim.audit.chain.PostgresAuditWriter",
               return_value=audit if audit is not None else MagicMock()), \
         patch("redsim.workers.events.publish_job_event") as pub:
        yield sess, pub


def _ml_task(name: str = "redsim.ml_campaign_run", request_id: str | None = "celery-abc",
             retries: int = 0, max_retries: int = 2) -> MagicMock:
    """A bound-task double carrying a real Celery task name and request id."""
    task = MagicMock()
    task.name = name
    task.request.id = request_id if request_id is not None else MagicMock()
    task.request.retries = retries
    task.max_retries = max_retries
    return task


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


class TestCeleryTaskIdStamp(unittest.TestCase):
    """Spec 10.7 item 2: the live request id is stamped on pickup."""

    def test_bound_task_request_id_is_stamped(self):
        job = _fake_job(job_type="attack.run")
        task = _ml_task(request_id="celery-abc")
        with _patched(job):
            with bootstrap.task_context("job-1", task=task) as ctx:
                self.assertEqual(job.celery_task_id, "celery-abc")
                self.assertEqual(ctx.celery_task_id, "celery-abc")
                self.assertEqual(ctx.task_name, "redsim.ml_campaign_run")
                self.assertEqual(ctx.worker_actor, "worker:attack.run")

    def test_no_stamp_without_a_real_request_id(self):
        job = _fake_job()
        with _patched(job):
            with bootstrap.task_context("job-1", task=MagicMock()) as ctx:
                self.assertIsNone(job.celery_task_id)
                self.assertIsNone(ctx.celery_task_id)
            with bootstrap.task_context("job-1") as ctx:
                pass
        self.assertIsNone(job.celery_task_id)

    def test_skip_path_does_not_stamp(self):
        job = _fake_job(status="cancelled")
        with _patched(job):
            with bootstrap.task_context("job-1", task=_ml_task()) as ctx:
                self.assertTrue(ctx.skip)
        self.assertIsNone(job.celery_task_id)


class TestJobCompleteAudit(unittest.TestCase):
    """Spec 5.11 / 10.5: ``task_context`` can close a job's chain with
    ``job.complete`` (``worker:<job type>`` actor). Opt-in: the ML task bodies
    write that row themselves today, so the default adds no audit rows."""

    def test_default_is_off_for_every_task(self):
        for task in (_ml_task(), _ml_task("redsim.ml_model_validate"),
                     _ml_task("redsim.scan_start"), None):
            with self.subTest(task=getattr(task, "name", None)):
                job = _fake_job(job_type="attack.run")
                audit = _AuditRecorder()
                with _patched(job, audit):
                    with bootstrap.task_context("job-1", task=task):
                        pass
                self.assertEqual(job.status, "succeeded")
                self.assertEqual(audit.events, [])

    def test_opt_in_success_emits_job_complete_via_authorize(self):
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        with _patched(job, audit) as (sess, pub):
            with bootstrap.task_context(
                "job-1", task=_ml_task(), emit_job_complete=True,
            ) as ctx:
                ctx.completion_detail["envelope_sha256"] = "e" * 64
                ctx.completion_detail["measurements"] = 12
        self.assertEqual(job.status, "succeeded")
        self.assertEqual([e["action"] for e in audit.events], ["job.complete"])
        row = audit.events[0]
        self.assertEqual(row["actor"], "worker:attack.run")
        self.assertTrue(row["success"])
        self.assertEqual(row["allowlist_check"], "n/a")  # target-less action
        self.assertIsNone(row["target"])
        self.assertEqual((row["run_id"], row["project_id"]), ("run-1", "proj-1"))
        detail = row["detail"]
        self.assertEqual(detail["job_type"], "attack.run")
        self.assertEqual(detail["status"], "succeeded")
        self.assertEqual(detail["job_id"], "job-1")
        self.assertEqual(detail["findings"], 3)
        self.assertEqual(detail["artifacts"], 3)
        self.assertEqual(detail["measurements"], 12)
        self.assertEqual(detail["envelope_sha256"], "e" * 64)
        self.assertEqual(detail["actor"], "worker:attack.run")
        self.assertEqual(_statuses(pub), ["running", "succeeded"])

    def test_actor_follows_job_type(self):
        job = _fake_job(job_type="model.validate")
        audit = _AuditRecorder()
        with _patched(job, audit):
            with bootstrap.task_context(
                "job-1", task=_ml_task("redsim.ml_model_validate"), emit_job_complete=True,
            ) as ctx:
                self.assertEqual(ctx.worker_actor, "worker:model.validate")
        self.assertEqual([e["action"] for e in audit.events], ["job.complete"])
        self.assertEqual(audit.events[0]["actor"], "worker:model.validate")

    def test_opt_in_without_bound_task(self):
        job = _fake_job(job_type="report.render")
        audit = _AuditRecorder()
        with _patched(job, audit):
            with bootstrap.task_context("job-1", emit_job_complete=True):
                pass
        self.assertEqual([e["action"] for e in audit.events], ["job.complete"])
        self.assertEqual(audit.events[0]["actor"], "worker:report.render")

    def test_opt_in_failure_emits_failed_row_then_reraises(self):
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        with _patched(job, audit) as (sess, pub):
            with self.assertRaises(ValueError):
                with bootstrap.task_context("job-1", task=_ml_task(), emit_job_complete=True):
                    raise ValueError("boom")
            self.assertEqual(job.status, "failed")
            self.assertTrue(sess.commit.called)
        self.assertEqual([e["action"] for e in audit.events], ["job.complete"])
        row = audit.events[0]
        self.assertFalse(row["success"])
        self.assertEqual(row["actor"], "worker:attack.run")
        self.assertEqual(row["detail"]["status"], "failed")
        self.assertEqual(row["detail"]["error_class"], "ValueError")
        self.assertNotIn("boom", str(row["detail"]))  # class only, no message
        self.assertEqual(_statuses(pub), ["running", "failed"])

    def test_failed_row_write_error_never_masks_body_error(self):
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        audit.append = MagicMock(side_effect=RuntimeError("chain down"))  # type: ignore[method-assign]
        with _patched(job, audit):
            with self.assertRaises(ValueError):
                with bootstrap.task_context("job-1", task=_ml_task(), emit_job_complete=True):
                    raise ValueError("boom")
        self.assertEqual(job.status, "failed")

    def test_transient_retry_emits_no_job_complete(self):
        from celery.exceptions import Retry
        from sqlalchemy.exc import OperationalError
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        task = _ml_task(retries=0)
        task.retry.side_effect = Retry()
        with _patched(job, audit):
            with self.assertRaises(Retry):
                with bootstrap.task_context("job-1", task=task, emit_job_complete=True):
                    raise OperationalError("SELECT 1", {}, Exception("db gone"))
        self.assertEqual(job.status, "queued")
        self.assertEqual(audit.events, [])


class TestTerminalRowHonoured(unittest.TestCase):
    """Spec 10.7 item 2: a row cancelled mid-body is never overwritten."""

    def test_success_suppressed_when_job_cancelled_mid_body(self):
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        with _patched(job, audit) as (sess, pub), \
             patch.object(bootstrap, "record_campaign_outcome") as outcome:
            with bootstrap.task_context("job-1", task=_ml_task(), emit_job_complete=True):
                # Another session's cancel_run commits while the body runs.
                job.status = "cancelled"
        self.assertEqual(job.status, "cancelled")
        self.assertIsNone(job.completed_at)
        self.assertTrue(sess.rollback.called)
        self.assertEqual(audit.events, [])  # no stale job.complete
        self.assertEqual(_statuses(pub), ["running"])  # no stale 'succeeded'
        outcome.assert_called_once_with("cancelled")

    def test_failure_leaves_cancelled_row_alone(self):
        job = _fake_job(job_type="attack.run")
        audit = _AuditRecorder()
        with _patched(job, audit) as (sess, pub):
            with self.assertRaises(ValueError):
                with bootstrap.task_context("job-1", task=_ml_task(), emit_job_complete=True):
                    job.status = "cancelled"
                    raise ValueError("boom")
        self.assertEqual(job.status, "cancelled")
        self.assertIsNone(job.error)
        self.assertEqual(audit.events, [])
        self.assertEqual(_statuses(pub), ["running"])


class TestCampaignOutcomeCounter(unittest.TestCase):
    def test_campaign_task_counts_terminal_outcomes(self):
        for body_raises, expected in ((False, "succeeded"), (True, "failed")):
            with self.subTest(expected=expected):
                job = _fake_job(job_type="attack.run")
                with _patched(job), \
                     patch.object(bootstrap, "record_campaign_outcome") as outcome:
                    if body_raises:
                        with self.assertRaises(ValueError):
                            with bootstrap.task_context("job-1", task=_ml_task()):
                                raise ValueError("boom")
                    else:
                        with bootstrap.task_context("job-1", task=_ml_task()):
                            pass
                outcome.assert_called_once_with(expected)

    def test_non_campaign_tasks_do_not_count(self):
        for name in ("redsim.ml_model_validate", "redsim.scan_start"):
            with self.subTest(name=name):
                job = _fake_job()
                with _patched(job), \
                     patch.object(bootstrap, "record_campaign_outcome") as outcome:
                    with bootstrap.task_context("job-1", task=_ml_task(name)):
                        pass
                outcome.assert_not_called()


class TestJobLogContext(unittest.TestCase):
    def test_run_job_project_ids_bound_for_body_only(self):
        from redsim.observability import current_job_context
        job = _fake_job()
        with _patched(job):
            with bootstrap.task_context("job-1"):
                self.assertEqual(
                    current_job_context(),
                    {"run_id": "run-1", "job_id": "job-1", "project_id": "proj-1"},
                )
        self.assertEqual(current_job_context(), {})


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
        for name in (
            "redsim.scan_start",
            "redsim.verify_replay",
            "redsim.ml_campaign_run",
            "redsim.ml_model_validate",
        ):
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
             "redsim.export_chains_to_worm", "redsim.ml_campaign_run",
             "redsim.ml_model_validate"},
        )


if __name__ == "__main__":
    unittest.main()
