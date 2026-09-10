"""Behavioral unit tests for Celery worker modules.

Covers:
  redsim/workers/bootstrap.py
  redsim/workers/tasks/scan.py
  redsim/workers/tasks/report.py

(The pentest fix / parallel_fix / exports / ci_gate task modules were removed
with the pentest domain, the verify task with the verify loop.)

All tests are fully offline: Celery runs in eager/apply() mode; no real
Redis, Postgres, or network connection is made.  The DB session, service
layer, and any subprocess are mocked at the boundary.
"""

from __future__ import annotations

import os
import sys
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

# celery ships in the [worker] extra and the worker task modules import it at
# load time. Skip this whole module when it's absent (e.g. the minimal-deps
# unit CI job) so the offline suite stays green without the worker extra.
pytest.importorskip("celery")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding_blob(**overrides) -> dict:
    """Minimal RedsimFinding-shaped dict suitable for RedsimFinding.from_dict."""
    base = {
        "id": "find-001",
        "title": "SQL Injection",
        "severity": "high",
        "finding_type": "sast",
        "description": "Unsanitised input used in query",
        "source_tool": "strix",
        "source_run_id": "run-001",
        "affected_component": "app/db.py",
        "confidence": "high",
        "status": "open",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "target": "localhost",
    }
    base.update(overrides)
    return base


def _ctx_factory(
    *,
    run_id: str = "run-001",
    project_id: str = "proj-001",
    actor: str = "user:alice",
    job_detail: dict | None = None,
    findings: list | None = None,
):
    """Return a mock TaskContext and a mock session wired to it."""
    ctx = MagicMock()
    ctx.skip = False
    ctx.run_id = run_id
    ctx.project_id = project_id
    ctx.actor = actor

    sess = MagicMock()
    ctx.session = sess
    ctx.run_state.load_findings.return_value = findings or []

    # By default, session.get returns a job whose detail is job_detail.
    job = MagicMock()
    job.detail = job_detail or {}
    sess.get.return_value = job

    return ctx, sess, job


@contextmanager
def _task_context_cm(ctx):
    """Yields *ctx* — replaces ``redsim.workers.bootstrap.task_context``."""
    @contextmanager
    def _inner(job_id, task=None):
        yield ctx
    return _inner


# ---------------------------------------------------------------------------
# bootstrap.py
# ---------------------------------------------------------------------------

class TestBootstrapTaskContext(unittest.TestCase):
    """Tests for ``redsim.workers.bootstrap.task_context``."""

    def _patch_all(self, job=None, db_url: str | None = "sqlite://"):
        """Return a list of context managers that stub every real dependency."""
        # Use real __enter__/__exit__ via patch.multiple approach
        patches = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        env = {"REDSIM_DB_URL": db_url} if db_url else {}
        return patches, env

    def _apply_patches(self, patches, db_url="sqlite://"):
        """Start all patches and return mocks + cleanup handle."""
        started = [p.start() for p in patches]
        return started

    def _setup_mocks(self, mocks, job_obj, output_dir="/tmp"):
        """Configure the mock return values from the started patches list."""
        # Order: PostgresAuditWriter, open_blob_store, load_config,
        #        get_session, init_engine, PostgresRunState
        _mock_aw, _mock_bs, mock_cfg, mock_sess_cm, _mock_init, _mock_state = mocks
        mock_cfg.return_value = MagicMock(output_dir=output_dir)

        sess = MagicMock()
        sess.get.return_value = job_obj

        @contextmanager
        def fake_session():
            yield sess

        mock_sess_cm.side_effect = fake_session
        return sess, _mock_init

    # -- success path ---------------------------------------------------------

    def test_success_marks_job_running_then_succeeded(self):
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-001"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _mock_bs, mock_cfg, mock_sess_cm, mock_init, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            with patch.dict(os.environ, {"REDSIM_DB_URL": "sqlite://"}):
                import importlib

                import redsim.workers.bootstrap as boot
                importlib.reload(boot)

                with boot.task_context("job-001"):
                    # Inside the context body, status should be 'running'
                    self.assertEqual(job.status, "running")
                    self.assertIsNotNone(job.started_at)
                    ctx_mid_status = job.status

            self.assertEqual(ctx_mid_status, "running")
            # After exiting normally, status becomes 'succeeded'
            self.assertEqual(job.status, "succeeded")
            self.assertIsNotNone(job.completed_at)
            # init_engine was called because REDSIM_DB_URL was set
            mock_init.assert_called_once_with("sqlite://")
        finally:
            for p in patches_list:
                p.stop()

    def test_non_queued_job_is_skipped_without_status_change(self):
        # H2: a cancelled/redelivered job must not re-run. task_context yields
        # skip=True, leaves the row status untouched, and never builds the
        # run-state backend (no side effects, no offensive work re-fired).
        job = MagicMock()
        job.status = "cancelled"
        job.run_id = "run-007"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, mock_state = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            with patch.dict(os.environ, {"REDSIM_DB_URL": "sqlite://"}):
                import importlib

                import redsim.workers.bootstrap as boot
                importlib.reload(boot)

                with boot.task_context("job-007") as ctx:
                    self.assertTrue(ctx.skip)

            # Status untouched and the DB-backed run-state was never built.
            self.assertEqual(job.status, "cancelled")
            mock_state.assert_not_called()
        finally:
            for p in patches_list:
                p.stop()

    def test_actor_comes_from_job_created_by(self):
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-002"
        job.project_id = "proj-001"
        job.created_by = "user:bob"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            import importlib

            import redsim.workers.bootstrap as boot
            importlib.reload(boot)

            with boot.task_context("job-002") as ctx:
                self.assertEqual(ctx.actor, "user:bob")
                self.assertEqual(ctx.run_id, "run-002")
                self.assertEqual(ctx.project_id, "proj-001")
        finally:
            for p in patches_list:
                p.stop()

    def test_actor_defaults_to_system_worker_when_created_by_is_none(self):
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-003"
        job.project_id = "proj-001"
        job.created_by = None  # trigger the default

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            import importlib

            import redsim.workers.bootstrap as boot
            importlib.reload(boot)

            with boot.task_context("job-003") as ctx:
                self.assertEqual(ctx.actor, "system:worker")
        finally:
            for p in patches_list:
                p.stop()

    def test_missing_job_raises_runtime_error(self):
        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = None  # job not found

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            import importlib

            import redsim.workers.bootstrap as boot
            importlib.reload(boot)

            with self.assertRaises(RuntimeError) as cm, boot.task_context("missing-job"):
                pass  # pragma: no cover
            self.assertIn("missing-job", str(cm.exception))
        finally:
            for p in patches_list:
                p.stop()

    def test_exception_inside_context_marks_job_failed_and_reraises(self):
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-004"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            import importlib

            import redsim.workers.bootstrap as boot
            importlib.reload(boot)

            with self.assertRaises(ValueError), boot.task_context("job-004"):
                raise ValueError("intentional task failure")

            self.assertEqual(job.status, "failed")
            self.assertIsNotNone(job.completed_at)
            self.assertIn("ValueError", job.error)
            self.assertIn("intentional task failure", job.error)
        finally:
            for p in patches_list:
                p.stop()

    def test_no_init_engine_when_db_url_not_set(self):
        """REDSIM_DB_URL absent → init_engine must NOT be called."""
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-005"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, mock_init, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            # Ensure REDSIM_DB_URL is absent
            env_without = {k: v for k, v in os.environ.items()
                           if k != "REDSIM_DB_URL"}
            with patch.dict(os.environ, env_without, clear=True):
                import importlib

                import redsim.workers.bootstrap as boot
                importlib.reload(boot)
                with boot.task_context("job-005") as ctx:
                    self.assertEqual(ctx.job_id, "job-005")

            mock_init.assert_not_called()
        finally:
            for p in patches_list:
                p.stop()

    def test_context_bundle_fields_are_populated(self):
        job = MagicMock()
        job.status = "queued"
        job.run_id = "run-006"
        job.project_id = "proj-006"
        job.created_by = "user:carol"

        patches_list = [
            patch("redsim.audit.chain.PostgresAuditWriter"),
            patch("redsim.storage.open_blob_store"),
            patch("redsim.config.load_config"),
            patch("redsim.db.session.get_session"),
            patch("redsim.db.session.init_engine"),
            patch("redsim.state.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, _, mock_cfg, mock_sess_cm, _, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            import importlib

            import redsim.workers.bootstrap as boot
            importlib.reload(boot)

            with boot.task_context("job-006") as ctx:
                self.assertEqual(ctx.job_id, "job-006")
                self.assertEqual(ctx.run_id, "run-006")
                self.assertEqual(ctx.project_id, "proj-006")
                self.assertEqual(ctx.actor, "user:carol")
                self.assertIsNotNone(ctx.run_state)
                self.assertIsNotNone(ctx.audit_writer)
                self.assertIsNotNone(ctx.blob_store)
        finally:
            for p in patches_list:
                p.stop()


# ---------------------------------------------------------------------------
# Helper: _make_task_ctx — builds the shared MagicMock TaskContext + session
# used by every task test below.
# ---------------------------------------------------------------------------

def _make_task_ctx(
    job_detail: dict | None = None,
    findings: list | None = None,
    run_id: str = "run-001",
    project_id: str = "proj-001",
    actor: str = "user:alice",
):
    ctx = MagicMock()
    ctx.skip = False
    ctx.run_id = run_id
    ctx.project_id = project_id
    ctx.actor = actor

    job = MagicMock()
    job.detail = job_detail or {}

    sess = MagicMock()
    sess.get.return_value = job
    ctx.session = sess
    ctx.run_state.load_findings.return_value = findings or []

    @contextmanager
    def fake_tc(job_id, task=None):
        yield ctx

    return ctx, sess, job, fake_tc


# ---------------------------------------------------------------------------
# scan.py
# ---------------------------------------------------------------------------

class TestScanStart(unittest.TestCase):

    def _scan_task(self):
        from redsim.workers.tasks.scan import scan_start
        return scan_start

    def test_happy_path_returns_expected_keys(self):
        _ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "10.0.0.1", "scanner": "strix",
                        "instruction": None},
        )

        disp_result = MagicMock()
        disp_result.findings = [MagicMock(), MagicMock(), MagicMock()]
        disp_result.exit_code = 0
        sess.get.return_value = job  # second get() inside task body

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.config.load_config") as mock_cfg, \
             patch("redsim.safety.authorize"), \
             patch("redsim.scanners.dispatch", return_value=disp_result), \
             patch("redsim.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])

            result = self._scan_task().apply(args=["job-scan-001"]).get()

        self.assertEqual(result["run_id"], "run-001")
        self.assertEqual(result["scanner"], "strix")
        self.assertEqual(result["findings"], 3)
        self.assertEqual(result["exit_code"], 0)

    def test_authorize_called_with_scanner_and_target(self):
        _ctx, _sess, _job, fake_tc = _make_task_ctx(
            job_detail={"target": "192.168.1.1", "scanner": "trivy",
                        "instruction": "scan everything"},
        )

        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.config.load_config") as mock_cfg, \
             patch("redsim.safety.authorize") as mock_auth, \
             patch("redsim.scanners.dispatch", return_value=disp_result), \
             patch("redsim.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=["192.168.1.1"])

            self._scan_task().apply(args=["job-scan-002"]).get()

        mock_auth.assert_called_once()
        auth_args = mock_auth.call_args
        self.assertIn("scan.execute.trivy", auth_args[0])
        self.assertEqual(auth_args[0][1], "192.168.1.1")
        # No override in detail -> worker re-check defaults to False.
        self.assertIs(auth_args.kwargs.get("override_authorized", False), False)

    def test_override_authorized_threaded_from_detail_to_worker_authorize(self):
        # M1: a target authorized at admission only via the explicit override
        # must stay authorized through the worker re-check (else the job fails
        # despite a valid admission decision).
        _ctx, _sess, _job, fake_tc = _make_task_ctx(
            job_detail={"target": "10.0.0.9", "scanner": "trivy",
                        "instruction": None, "override_authorized": True},
        )
        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.config.load_config") as mock_cfg, \
             patch("redsim.safety.authorize") as mock_auth, \
             patch("redsim.scanners.dispatch", return_value=disp_result), \
             patch("redsim.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])  # off-allowlist
            self._scan_task().apply(args=["job-scan-ovr"]).get()

        self.assertIs(mock_auth.call_args.kwargs["override_authorized"], True)

    def test_findings_saved_on_run_state(self):
        ctx, _sess, _job, fake_tc = _make_task_ctx(
            job_detail={"target": "host", "scanner": "strix",
                        "instruction": None},
        )

        disp_result = MagicMock()
        disp_result.findings = [MagicMock()]
        disp_result.exit_code = 0

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.config.load_config") as mock_cfg, \
             patch("redsim.safety.authorize"), \
             patch("redsim.scanners.dispatch", return_value=disp_result), \
             patch("redsim.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            self._scan_task().apply(args=["job-scan-003"]).get()

        ctx.run_state.save_findings.assert_called_once_with(disp_result.findings)

    def test_missing_scanner_in_detail_fails_explicitly(self):
        # Admission always records the scanner; there is no default engine to
        # fall back to (the pentest default "strix" was removed). A Job without
        # one must fail loudly before authorize / dispatch, never substitute an
        # adapter silently.
        ctx, _sess, _job, fake_tc = _make_task_ctx(
            # detail has no 'scanner' key
            job_detail={"target": "host"},
        )

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.config.load_config") as mock_cfg, \
             patch("redsim.safety.authorize") as mock_auth, \
             patch("redsim.scanners.dispatch") as mock_dispatch, \
             patch("redsim.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            with self.assertRaises(RuntimeError) as cm:
                self._scan_task().apply(args=["job-scan-004"]).get()

        self.assertIn("no scanner", str(cm.exception))
        self.assertIn("redsim.ml.attacks", str(cm.exception))
        mock_auth.assert_not_called()
        mock_dispatch.assert_not_called()
        ctx.run_state.save_findings.assert_not_called()


# ---------------------------------------------------------------------------
# report.py
# ---------------------------------------------------------------------------

class TestReportRender(unittest.TestCase):

    def _rep_task(self):
        from redsim.workers.tasks.report import report_render
        return report_render

    def test_happy_path_returns_paths(self):
        ctx, _sess, _job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = []

        from redsim.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/run/report.md",
            json_path="/run/findings.json",
            html_path="/run/report.html",
        )

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.services.reports.render_reports",
                   return_value=outcome):
            result = self._rep_task().apply(args=["job-rep-001"]).get()

        self.assertEqual(result["markdown_path"], "/run/report.md")
        self.assertEqual(result["json_path"], "/run/findings.json")
        self.assertEqual(result["html_path"], "/run/report.html")
        self.assertEqual(result["job_id"], "job-rep-001")

    def test_findings_converted_and_passed_to_render(self):
        raw = _make_finding_blob(id="find-rep-01")
        ctx, _sess, _job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = [raw]

        from redsim.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/run/report.md",
            json_path="/run/findings.json",
            html_path=None,
        )

        rendered_findings = []

        def _capture_render(*, run_state, findings, html):
            rendered_findings.extend(findings)
            return outcome

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.services.reports.render_reports",
                   side_effect=_capture_render):
            self._rep_task().apply(args=["job-rep-002"]).get()

        from redsim.schema import RedsimFinding
        self.assertEqual(len(rendered_findings), 1)
        self.assertIsInstance(rendered_findings[0], RedsimFinding)

    def test_render_called_with_html_true(self):
        ctx, _sess, _job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = []

        from redsim.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/r.md", json_path="/r.json", html_path="/r.html"
        )

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.services.reports.render_reports",
                   return_value=outcome) as mock_render:
            self._rep_task().apply(args=["job-rep-003"]).get()

        call_kwargs = mock_render.call_args[1]
        self.assertTrue(call_kwargs["html"])

    def test_multiple_findings_all_passed(self):
        raws = [_make_finding_blob(id=f"find-{i}") for i in range(5)]
        ctx, _sess, _job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = raws

        from redsim.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/r.md", json_path="/r.json", html_path="/r.html"
        )
        passed_count = []

        def _cap(*, run_state, findings, html):
            passed_count.append(len(findings))
            return outcome

        with patch("redsim.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("redsim.services.reports.render_reports",
                   side_effect=_cap):
            self._rep_task().apply(args=["job-rep-004"]).get()

        self.assertEqual(passed_count[0], 5)


# ---------------------------------------------------------------------------
# celery_app.py — bootstrap env-var reading
# ---------------------------------------------------------------------------

class TestCeleryAppBootstrap(unittest.TestCase):
    """Verify celery_app.py reads env vars at import time and applies them."""

    def _fresh_import(self, env_overrides: dict):
        """Reload celery_app with a patched environment, return the module."""
        # Remove cached module so the module-level code re-runs
        for key in list(sys.modules.keys()):
            if "celery_app" in key:
                del sys.modules[key]

        with patch.dict(os.environ, env_overrides, clear=False):
            import importlib

            import redsim.workers.celery_app as m
            importlib.reload(m)
            return m

    def test_broker_url_taken_from_env(self):
        m = self._fresh_import(
            {"REDSIM_BROKER_URL": "redis://broker-host:9999/3"}
        )
        self.assertEqual(m.app.conf.broker_url, "redis://broker-host:9999/3")

    def test_result_backend_taken_from_env(self):
        m = self._fresh_import(
            {"REDSIM_RESULT_BACKEND": "redis://result-host:8888/7"}
        )
        self.assertEqual(m.app.conf.result_backend, "redis://result-host:8888/7")

    def test_defaults_when_env_not_set(self):
        env_without = {k: v for k, v in os.environ.items()
                       if k not in ("REDSIM_BROKER_URL", "REDSIM_RESULT_BACKEND")}
        for key in list(sys.modules.keys()):
            if "celery_app" in key:
                del sys.modules[key]

        with patch.dict(os.environ, env_without, clear=True):
            import importlib

            import redsim.workers.celery_app as m
            importlib.reload(m)

        self.assertEqual(m.app.conf.broker_url, "redis://localhost:6379/0")
        self.assertEqual(m.app.conf.result_backend, "redis://localhost:6379/1")

    def test_task_acks_late_enabled(self):
        m = self._fresh_import({})
        self.assertTrue(m.app.conf.task_acks_late)

    def test_task_track_started_enabled(self):
        m = self._fresh_import({})
        self.assertTrue(m.app.conf.task_track_started)

    def test_prefetch_multiplier_is_one(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.conf.worker_prefetch_multiplier, 1)

    def test_soft_and_hard_time_limits(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.conf.task_soft_time_limit, 1800)
        self.assertEqual(m.app.conf.task_time_limit, 2100)

    def test_default_max_retries(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.conf.task_default_max_retries, 3)

    def test_default_retry_delay(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.conf.task_default_retry_delay, 10)

    def test_app_name_is_redsim(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.main, "redsim")

    def test_task_modules_registered(self):
        m = self._fresh_import({})
        # The pentest fix/parallel_fix/exports/ci_gate task modules were
        # removed with the pentest domain; the surviving task set is what
        # celery_app now includes.
        expected_tasks = [
            "redsim.workers.tasks.scan",
            "redsim.workers.tasks.report",
        ]
        registered = list(m.app.conf.include)
        for module in expected_tasks:
            self.assertIn(module, registered)
        self.assertNotIn("redsim.workers.tasks.verify", registered)


if __name__ == "__main__":
    unittest.main()
