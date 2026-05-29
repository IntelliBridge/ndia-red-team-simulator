"""Behavioral unit tests for Celery worker modules.

Covers:
  aegis/workers/bootstrap.py
  aegis/workers/tasks/scan.py
  aegis/workers/tasks/fix.py
  aegis/workers/tasks/verify.py
  aegis/workers/tasks/parallel_fix.py
  aegis/workers/tasks/exports.py
  aegis/workers/tasks/ci_gate.py
  aegis/workers/tasks/report.py

All tests are fully offline: Celery runs in eager/apply() mode; no real
Redis, Postgres, or network connection is made.  The DB session, service
layer, and any subprocess are mocked at the boundary.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
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
    """Minimal AegisFinding-shaped dict suitable for AegisFinding.from_dict."""
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
    ctx.run_id = run_id
    ctx.project_id = project_id
    ctx.actor = actor

    sess = MagicMock()
    ctx.run_state.session = sess
    ctx.run_state.load_findings.return_value = findings or []

    # By default, session.get returns a job whose detail is job_detail.
    job = MagicMock()
    job.detail = job_detail or {}
    sess.get.return_value = job

    return ctx, sess, job


@contextmanager
def _task_context_cm(ctx):
    """Yields *ctx* — replaces ``aegis.workers.bootstrap.task_context``."""
    @contextmanager
    def _inner(job_id):  # noqa: ARG001
        yield ctx
    return _inner


# ---------------------------------------------------------------------------
# bootstrap.py
# ---------------------------------------------------------------------------

class TestBootstrapTaskContext(unittest.TestCase):
    """Tests for ``aegis.workers.bootstrap.task_context``."""

    def _patch_all(self, job=None, db_url: str | None = "sqlite://"):
        """Return a list of context managers that stub every real dependency."""
        # Use real __enter__/__exit__ via patch.multiple approach
        patches = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
        ]
        env = {"AEGIS_DB_URL": db_url} if db_url else {}
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
        job.run_id = "run-001"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
        ]
        mocks = [p.start() for p in patches_list]
        try:
            _, mock_bs, mock_cfg, mock_sess_cm, mock_init, _ = mocks
            mock_cfg.return_value = MagicMock(output_dir="/tmp")
            sess = MagicMock()
            sess.get.return_value = job

            @contextmanager
            def fake_session():
                yield sess

            mock_sess_cm.side_effect = fake_session

            with patch.dict(os.environ, {"AEGIS_DB_URL": "sqlite://"}):
                import importlib

                import aegis.workers.bootstrap as boot
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
            # init_engine was called because AEGIS_DB_URL was set
            mock_init.assert_called_once_with("sqlite://")
        finally:
            for p in patches_list:
                p.stop()

    def test_actor_comes_from_job_created_by(self):
        job = MagicMock()
        job.run_id = "run-002"
        job.project_id = "proj-001"
        job.created_by = "user:bob"

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            import aegis.workers.bootstrap as boot
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
        job.run_id = "run-003"
        job.project_id = "proj-001"
        job.created_by = None  # trigger the default

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            import aegis.workers.bootstrap as boot
            importlib.reload(boot)

            with boot.task_context("job-003") as ctx:
                self.assertEqual(ctx.actor, "system:worker")
        finally:
            for p in patches_list:
                p.stop()

    def test_missing_job_raises_runtime_error(self):
        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            import aegis.workers.bootstrap as boot
            importlib.reload(boot)

            with self.assertRaises(RuntimeError) as cm:
                with boot.task_context("missing-job"):
                    pass  # pragma: no cover
            self.assertIn("missing-job", str(cm.exception))
        finally:
            for p in patches_list:
                p.stop()

    def test_exception_inside_context_marks_job_failed_and_reraises(self):
        job = MagicMock()
        job.run_id = "run-004"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            import aegis.workers.bootstrap as boot
            importlib.reload(boot)

            with self.assertRaises(ValueError):
                with boot.task_context("job-004"):
                    raise ValueError("intentional task failure")

            self.assertEqual(job.status, "failed")
            self.assertIsNotNone(job.completed_at)
            self.assertIn("ValueError", job.error)
            self.assertIn("intentional task failure", job.error)
        finally:
            for p in patches_list:
                p.stop()

    def test_no_init_engine_when_db_url_not_set(self):
        """AEGIS_DB_URL absent → init_engine must NOT be called."""
        job = MagicMock()
        job.run_id = "run-005"
        job.project_id = "proj-001"
        job.created_by = "user:alice"

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            # Ensure AEGIS_DB_URL is absent
            env_without = {k: v for k, v in os.environ.items()
                           if k != "AEGIS_DB_URL"}
            with patch.dict(os.environ, env_without, clear=True):
                import importlib

                import aegis.workers.bootstrap as boot
                importlib.reload(boot)
                with boot.task_context("job-005") as ctx:
                    self.assertEqual(ctx.job_id, "job-005")

            mock_init.assert_not_called()
        finally:
            for p in patches_list:
                p.stop()

    def test_context_bundle_fields_are_populated(self):
        job = MagicMock()
        job.run_id = "run-006"
        job.project_id = "proj-006"
        job.created_by = "user:carol"

        patches_list = [
            patch("aegis.audit.chain.PostgresAuditWriter"),
            patch("aegis.blobs.open_blob_store"),
            patch("aegis.config.load_config"),
            patch("aegis.db.session.get_session"),
            patch("aegis.db.session.init_engine"),
            patch("aegis.state_pg.PostgresRunState"),
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

            import aegis.workers.bootstrap as boot
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
    ctx.run_id = run_id
    ctx.project_id = project_id
    ctx.actor = actor

    job = MagicMock()
    job.detail = job_detail or {}

    sess = MagicMock()
    sess.get.return_value = job
    ctx.run_state.session = sess
    ctx.run_state.load_findings.return_value = findings or []

    @contextmanager
    def fake_tc(job_id):  # noqa: ARG001
        yield ctx

    return ctx, sess, job, fake_tc


# ---------------------------------------------------------------------------
# scan.py
# ---------------------------------------------------------------------------

class TestScanStart(unittest.TestCase):

    def _scan_task(self):
        from aegis.workers.tasks.scan import scan_start
        return scan_start

    def test_happy_path_returns_expected_keys(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "10.0.0.1", "scanner": "strix",
                        "instruction": None},
        )

        disp_result = MagicMock()
        disp_result.findings = [MagicMock(), MagicMock(), MagicMock()]
        disp_result.exit_code = 0
        sess.get.return_value = job  # second get() inside task body

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch", return_value=disp_result), \
             patch("aegis.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])

            result = self._scan_task().apply(args=["job-scan-001"]).get()

        self.assertEqual(result["run_id"], "run-001")
        self.assertEqual(result["scanner"], "strix")
        self.assertEqual(result["findings"], 3)
        self.assertEqual(result["exit_code"], 0)

    def test_authorize_called_with_scanner_and_target(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "192.168.1.1", "scanner": "trivy",
                        "instruction": "scan everything"},
        )

        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize") as mock_auth, \
             patch("aegis.scanners.dispatch", return_value=disp_result), \
             patch("aegis.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=["192.168.1.1"])

            self._scan_task().apply(args=["job-scan-002"]).get()

        mock_auth.assert_called_once()
        auth_args = mock_auth.call_args
        self.assertIn("scan.execute.trivy", auth_args[0])
        self.assertEqual(auth_args[0][1], "192.168.1.1")

    def test_findings_saved_on_run_state(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "host", "scanner": "strix",
                        "instruction": None},
        )

        disp_result = MagicMock()
        disp_result.findings = [MagicMock()]
        disp_result.exit_code = 0

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch", return_value=disp_result), \
             patch("aegis.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            self._scan_task().apply(args=["job-scan-003"]).get()

        ctx.run_state.save_findings.assert_called_once_with(disp_result.findings)

    def test_default_scanner_is_strix_when_missing_from_detail(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            # detail has no 'scanner' key
            job_detail={"target": "host"},
        )

        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch", return_value=disp_result) as mock_dispatch, \
             patch("aegis.scanners.registry.ScanOptions"):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._scan_task().apply(args=["job-scan-004"]).get()

        # scanner key defaults to "strix"
        self.assertEqual(result["scanner"], "strix")
        # dispatch was called with "strix"
        self.assertEqual(mock_dispatch.call_args[0][0], "strix")


# ---------------------------------------------------------------------------
# fix.py
# ---------------------------------------------------------------------------

class TestFixGenerate(unittest.TestCase):

    def _fix_task(self):
        from aegis.workers.tasks.fix import fix_generate
        return fix_generate

    def _make_outcome(self, status="fixed", **kwargs):
        from aegis.services.fixes import FixOutcome
        defaults = dict(
            success=True, strategy="patch", finding_id="find-001",
            status=status, source="cai", branch="fix/find-001",
            commit_hash="deadbeef", pr_url=None,
        )
        defaults.update(kwargs)
        return FixOutcome(**defaults)

    def test_happy_path_patch_strategy(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={
                "finding_id": "find-001", "strategy": "patch",
                "repo": "/tmp/repo", "apply": True, "open_pr": False,
                "branch": None, "allow_dirty": False, "push": True,
                "use_golden_patch": False,
            },
        )

        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob()
        # sess.get: first call → job, second → finding_row
        sess.get.side_effect = [job, finding_row]

        outcome = self._make_outcome()
        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.fixes.generate_fix", return_value=outcome):
            mock_cfg.return_value = MagicMock()

            result = self._fix_task().apply(args=["job-fix-001"]).get()

        self.assertEqual(result["status"], "fixed")
        self.assertTrue(result["success"])
        self.assertEqual(result["finding_id"], "find-001")
        self.assertEqual(result["branch"], "fix/find-001")
        # F11: finding_row.status should be updated
        self.assertEqual(finding_row.status, "fixed")

    def test_missing_finding_raises_runtime_error(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-missing"},
        )
        # Second get() returns None → finding missing
        sess.get.side_effect = [job, None]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()

            with self.assertRaises(RuntimeError) as cm:
                self._fix_task().apply(args=["job-fix-002"]).get()

        self.assertIn("find-missing", str(cm.exception))

    def test_finding_status_lifted_onto_db_row(self):
        """The F11 contract: finding_row.status is updated from outcome.status."""
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-003", "strategy": "patch"},
        )

        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-003")
        sess.get.side_effect = [job, finding_row]

        outcome = self._make_outcome(status="pending_apply", success=False,
                                     branch=None, commit_hash=None)
        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.fixes.generate_fix", return_value=outcome):
            mock_cfg.return_value = MagicMock()
            self._fix_task().apply(args=["job-fix-003"]).get()

        self.assertEqual(finding_row.status, "pending_apply")

    def test_generate_fix_called_with_correct_strategy_and_flags(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={
                "finding_id": "find-004", "strategy": "live",
                "repo": None, "apply": False, "open_pr": False,
                "branch": None, "allow_dirty": False, "push": True,
                "use_golden_patch": False,
            },
        )

        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-004")
        sess.get.side_effect = [job, finding_row]

        outcome = self._make_outcome(strategy="live", status="fixed")
        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.fixes.generate_fix",
                   return_value=outcome) as mock_gen:
            mock_cfg.return_value = MagicMock()
            self._fix_task().apply(args=["job-fix-004"]).get()

        call_kwargs = mock_gen.call_args[1]
        self.assertEqual(call_kwargs["strategy"], "live")
        self.assertFalse(call_kwargs["apply"])
        self.assertFalse(call_kwargs["open_pr"])


# ---------------------------------------------------------------------------
# verify.py
# ---------------------------------------------------------------------------

class TestVerifyReplay(unittest.TestCase):

    def _verify_task(self):
        from aegis.workers.tasks.verify import verify_replay
        return verify_replay

    def _make_outcome(self, status="verified", strategy="poc"):
        from aegis.services.verify import VerifyOutcome
        return VerifyOutcome(
            finding_id="find-001",
            status=status,
            strategy=strategy,
            evidence={},
            notes="ok",
        )

    def test_verified_maps_to_poc_passed(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-001", "repo_path": None},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob()
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome("verified")):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._verify_task().apply(args=["job-ver-001"]).get()

        self.assertEqual(result["validation_state"], "poc_passed")
        self.assertEqual(finding_row.validation_state, "poc_passed")
        self.assertIsNotNone(finding_row.validated_at)

    def test_still_vulnerable_maps_to_poc_failed(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-002"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-002")
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome("still_vulnerable")):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._verify_task().apply(args=["job-ver-002"]).get()

        self.assertEqual(result["validation_state"], "poc_failed")

    def test_inconclusive_maps_to_inconclusive(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-003"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-003")
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome("inconclusive")):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._verify_task().apply(args=["job-ver-003"]).get()

        self.assertEqual(result["validation_state"], "inconclusive")

    def test_unknown_status_defaults_to_inconclusive(self):
        """An unmapped outcome.status falls back to 'inconclusive'."""
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-004"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-004")
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome("totally_new_status")):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._verify_task().apply(args=["job-ver-004"]).get()

        self.assertEqual(result["validation_state"], "inconclusive")

    def test_repo_path_passed_to_verify_service(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-005", "repo_path": "/tmp/myrepo"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-005")
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome()) as mock_ver:
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            self._verify_task().apply(args=["job-ver-005"]).get()

        call_kwargs = mock_ver.call_args[1]
        self.assertEqual(str(call_kwargs["repo_path"]), "/tmp/myrepo")

    def test_missing_finding_raises_runtime_error(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-missing"},
        )
        sess.get.side_effect = [job, None]  # finding is None

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            with self.assertRaises(RuntimeError):
                self._verify_task().apply(args=["job-ver-missing"]).get()

    def test_return_dict_includes_all_keys(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-006"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob(id="find-006")
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.services.verify.verify",
                   return_value=self._make_outcome(strategy="replay")):
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            result = self._verify_task().apply(args=["job-ver-006"]).get()

        for key in ("job_id", "finding_id", "status", "strategy",
                    "validation_state"):
            self.assertIn(key, result)
        self.assertEqual(result["strategy"], "replay")


# ---------------------------------------------------------------------------
# parallel_fix.py
# ---------------------------------------------------------------------------

class TestParallelFix(unittest.TestCase):

    def _pf_task(self):
        from aegis.workers.tasks.parallel_fix import parallel_fix
        return parallel_fix

    def test_happy_path_enqueues_two_child_jobs_and_returns_outcomes(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-001", "repo": "/tmp/repo"},
        )
        ctx.run_state.session = sess
        sess.get.return_value = job

        group_result = MagicMock()
        group_result.get.return_value = [
            {"status": "fixed", "finding_id": "find-001"},
            {"status": "fixed", "finding_id": "find-001"},
        ]

        mock_fg = MagicMock()
        mock_fg.s = MagicMock(return_value="subtask-sig")

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("celery.group") as mock_group, \
             patch("aegis.workers.tasks.fix.fix_generate", mock_fg):
            mock_group.return_value.apply_async.return_value = group_result

            result = self._pf_task().apply(args=["job-pf-001"]).get()

        self.assertIn("patch_job", result)
        self.assertIn("live_job", result)
        self.assertIn("outcomes", result)
        # Two child Job rows should have been added to the session
        self.assertEqual(sess.add.call_count, 2)
        # session.flush() called to persist child rows
        sess.flush.assert_called()
        # fix_generate.s called twice: once for patch, once for live
        self.assertEqual(mock_fg.s.call_count, 2)
        # group_result.get called with timeout
        group_result.get.assert_called_once_with(timeout=1800)

    def test_missing_finding_id_raises_runtime_error(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"repo": "/tmp/repo"},  # no finding_id
        )
        ctx.run_state.session = sess
        sess.get.return_value = job

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc):
            with self.assertRaises(RuntimeError) as cm:
                self._pf_task().apply(args=["job-pf-002"]).get()

        self.assertIn("finding_id required", str(cm.exception))

    def test_child_jobs_carry_correct_strategies(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-001", "repo": None},
        )
        ctx.run_state.session = sess
        sess.get.return_value = job

        added_jobs = []

        def _capture_add(obj):
            added_jobs.append(obj)

        sess.add.side_effect = _capture_add

        group_result = MagicMock()
        group_result.get.return_value = []

        mock_fg = MagicMock()
        mock_fg.s = MagicMock(return_value="subtask-sig")

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("celery.group") as mock_group, \
             patch("aegis.workers.tasks.fix.fix_generate", mock_fg), \
             patch("aegis.db.models.Job") as MockJob:
            mock_group.return_value.apply_async.return_value = group_result
            # MockJob returns the passed kwargs as a record we can inspect
            MockJob.side_effect = lambda **kw: kw
            self._pf_task().apply(args=["job-pf-003"]).get()

        strategies = {j.get("detail", {}).get("strategy") for j in added_jobs
                      if isinstance(j, dict)}
        self.assertIn("patch", strategies)
        self.assertIn("live", strategies)


# ---------------------------------------------------------------------------
# exports.py
# ---------------------------------------------------------------------------

class TestVulnfixerRender(unittest.TestCase):

    def _exp_task(self):
        from aegis.workers.tasks.exports import vulnfixer_render
        return vulnfixer_render

    def test_happy_path_returns_expected_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx, sess, job, fake_tc = _make_task_ctx()
            run_path = Path(tmpdir)
            ctx.run_state.run_path = run_path
            ctx.run_state.load_findings.return_value = []

            art_ref = MagicMock()
            art_ref.sha256 = "deadbeef" * 8
            art_ref.location = str(run_path / "vulnfixer-export.json")
            ctx.run_state.record_artifact.return_value = art_ref

            summary = {"total": 0, "routable_to_vulnfixer": 0,
                       "requires_code_fix": 0}

            with patch("aegis.workers.bootstrap.task_context",
                       side_effect=fake_tc), \
                 patch("aegis.adapters.vulnfixer_adapter.export_findings",
                       return_value=summary):
                # export_findings writes the file in prod; create it here
                (run_path / "vulnfixer-export.json").write_text('{}')
                result = self._exp_task().apply(args=["job-exp-001"]).get()

        self.assertEqual(result["job_id"], "job-exp-001")
        self.assertIn("summary", result)
        self.assertIn("sha256", result)
        self.assertIn("location", result)

    def test_findings_loaded_and_converted_to_aegis_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_finding = _make_finding_blob()
            ctx, sess, job, fake_tc = _make_task_ctx()
            run_path = Path(tmpdir)
            ctx.run_state.run_path = run_path
            ctx.run_state.load_findings.return_value = [raw_finding]

            art_ref = MagicMock()
            art_ref.sha256 = "aabbcc"
            art_ref.location = str(run_path / "vulnfixer-export.json")
            ctx.run_state.record_artifact.return_value = art_ref

            exported_findings = []

            def _capture_export(findings, path):
                exported_findings.extend(findings)
                return {"total": 1, "routable_to_vulnfixer": 0,
                        "requires_code_fix": 1}

            with patch("aegis.workers.bootstrap.task_context",
                       side_effect=fake_tc), \
                 patch("aegis.adapters.vulnfixer_adapter.export_findings",
                       side_effect=_capture_export):
                (run_path / "vulnfixer-export.json").write_text('{}')
                self._exp_task().apply(args=["job-exp-002"]).get()

        # The task converts raw dicts → AegisFinding objects before passing
        from aegis.schema import AegisFinding
        self.assertEqual(len(exported_findings), 1)
        self.assertIsInstance(exported_findings[0], AegisFinding)

    def test_artifact_recorded_on_run_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx, sess, job, fake_tc = _make_task_ctx()
            run_path = Path(tmpdir)
            ctx.run_state.run_path = run_path
            ctx.run_state.load_findings.return_value = []

            art_ref = MagicMock()
            art_ref.sha256 = "112233"
            art_ref.location = str(run_path / "vulnfixer-export.json")
            ctx.run_state.record_artifact.return_value = art_ref

            with patch("aegis.workers.bootstrap.task_context",
                       side_effect=fake_tc), \
                 patch("aegis.adapters.vulnfixer_adapter.export_findings",
                       return_value={"total": 0, "routable_to_vulnfixer": 0,
                                     "requires_code_fix": 0}):
                (run_path / "vulnfixer-export.json").write_text('{}')
                self._exp_task().apply(args=["job-exp-003"]).get()

        ctx.run_state.record_artifact.assert_called_once_with(
            "vulnfixer_export", b"{}",
            content_type="application/json",
        )


# ---------------------------------------------------------------------------
# ci_gate.py
# ---------------------------------------------------------------------------

class TestCIGate(unittest.TestCase):

    def _cg_task(self):
        from aegis.workers.tasks.ci_gate import ci_gate
        return ci_gate

    def _run(self, findings, policy_detail=None):
        ctx, sess, job, fake_tc = _make_task_ctx(
            findings=findings,
            job_detail={"policy": policy_detail or {}},
        )

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc):
            return self._cg_task().apply(args=["job-cg-001"]).get()

    def test_no_findings_returns_pass(self):
        result = self._run([])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["reason"], "pass")
        self.assertEqual(result["findings_evaluated"], 0)

    def test_critical_finding_triggers_failure_at_high_threshold(self):
        result = self._run(
            [{"severity": "critical", "validation_state": None}],
            policy_detail={"severity_threshold": "high"},
        )
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("1 blocking findings", result["reason"])

    def test_low_finding_passes_high_threshold(self):
        result = self._run(
            [{"severity": "low", "validation_state": None}],
            policy_detail={"severity_threshold": "high"},
        )
        self.assertEqual(result["exit_code"], 0)

    def test_max_findings_exceeded_triggers_failure(self):
        findings = [
            {"severity": "high", "validation_state": "poc_passed"},
            {"severity": "high", "validation_state": "poc_passed"},
            {"severity": "high", "validation_state": "poc_passed"},
        ]
        result = self._run(
            findings,
            policy_detail={"severity_threshold": "high",
                           "max_findings": 2, "require_validated": False},
        )
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("exceeds max 2", result["reason"])

    def test_require_validated_skips_unvalidated_findings(self):
        # Finding is critical but not poc_passed → should NOT block
        findings = [{"severity": "critical", "validation_state": "poc_failed"}]
        result = self._run(
            findings,
            policy_detail={"severity_threshold": "high",
                           "require_validated": True},
        )
        self.assertEqual(result["exit_code"], 0)

    def test_require_validated_blocks_on_poc_passed(self):
        findings = [{"severity": "critical", "validation_state": "poc_passed"}]
        result = self._run(
            findings,
            policy_detail={"severity_threshold": "high",
                           "require_validated": True},
        )
        self.assertEqual(result["exit_code"], 1)

    def test_return_dict_includes_job_id_and_findings_evaluated(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            findings=[{"severity": "medium"}],
            job_detail={"policy": {}},
        )

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc):
            result = self._cg_task().apply(args=["job-cg-detail"]).get()

        self.assertEqual(result["job_id"], "job-cg-detail")
        self.assertIn("findings_evaluated", result)

    def test_policy_defaults_applied_when_detail_empty(self):
        """Empty policy detail → severity_threshold='high', no max, no validated."""
        findings = [{"severity": "high", "validation_state": None}]
        ctx, sess, job, fake_tc = _make_task_ctx(
            findings=findings,
            job_detail={},  # no 'policy' key at all
        )

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc):
            result = self._cg_task().apply(args=["job-cg-defaults"]).get()

        # high severity at high threshold → blocking
        self.assertEqual(result["exit_code"], 1)

    def test_cigatepolicy_and_evaluate_are_re_exported(self):
        from aegis.workers.tasks.ci_gate import CIGatePolicy, evaluate
        policy = CIGatePolicy(severity_threshold="medium")
        exit_code, reason = evaluate(
            [{"severity": "medium"}], policy
        )
        self.assertEqual(exit_code, 1)


# ---------------------------------------------------------------------------
# report.py
# ---------------------------------------------------------------------------

class TestReportRender(unittest.TestCase):

    def _rep_task(self):
        from aegis.workers.tasks.report import report_render
        return report_render

    def test_happy_path_returns_paths(self):
        ctx, sess, job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = []

        from aegis.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/run/report.md",
            json_path="/run/findings.json",
            html_path="/run/report.html",
        )

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.services.reports.render_reports",
                   return_value=outcome):
            result = self._rep_task().apply(args=["job-rep-001"]).get()

        self.assertEqual(result["markdown_path"], "/run/report.md")
        self.assertEqual(result["json_path"], "/run/findings.json")
        self.assertEqual(result["html_path"], "/run/report.html")
        self.assertEqual(result["job_id"], "job-rep-001")

    def test_findings_converted_and_passed_to_render(self):
        raw = _make_finding_blob(id="find-rep-01")
        ctx, sess, job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = [raw]

        from aegis.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/run/report.md",
            json_path="/run/findings.json",
            html_path=None,
        )

        rendered_findings = []

        def _capture_render(*, run_state, findings, html):
            rendered_findings.extend(findings)
            return outcome

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.services.reports.render_reports",
                   side_effect=_capture_render):
            self._rep_task().apply(args=["job-rep-002"]).get()

        from aegis.schema import AegisFinding
        self.assertEqual(len(rendered_findings), 1)
        self.assertIsInstance(rendered_findings[0], AegisFinding)

    def test_render_called_with_html_true(self):
        ctx, sess, job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = []

        from aegis.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/r.md", json_path="/r.json", html_path="/r.html"
        )

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.services.reports.render_reports",
                   return_value=outcome) as mock_render:
            self._rep_task().apply(args=["job-rep-003"]).get()

        call_kwargs = mock_render.call_args[1]
        self.assertTrue(call_kwargs["html"])

    def test_multiple_findings_all_passed(self):
        raws = [_make_finding_blob(id=f"find-{i}") for i in range(5)]
        ctx, sess, job, fake_tc = _make_task_ctx()
        ctx.run_state.load_findings.return_value = raws

        from aegis.services.reports import ReportOutcome
        outcome = ReportOutcome(
            markdown_path="/r.md", json_path="/r.json", html_path="/r.html"
        )
        passed_count = []

        def _cap(*, run_state, findings, html):
            passed_count.append(len(findings))
            return outcome

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.services.reports.render_reports",
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

            import aegis.workers.celery_app as m
            importlib.reload(m)
            return m

    def test_broker_url_taken_from_env(self):
        m = self._fresh_import(
            {"AEGIS_BROKER_URL": "redis://broker-host:9999/3"}
        )
        self.assertEqual(m.app.conf.broker_url, "redis://broker-host:9999/3")

    def test_result_backend_taken_from_env(self):
        m = self._fresh_import(
            {"AEGIS_RESULT_BACKEND": "redis://result-host:8888/7"}
        )
        self.assertEqual(m.app.conf.result_backend, "redis://result-host:8888/7")

    def test_defaults_when_env_not_set(self):
        env_without = {k: v for k, v in os.environ.items()
                       if k not in ("AEGIS_BROKER_URL", "AEGIS_RESULT_BACKEND")}
        for key in list(sys.modules.keys()):
            if "celery_app" in key:
                del sys.modules[key]

        with patch.dict(os.environ, env_without, clear=True):
            import importlib

            import aegis.workers.celery_app as m
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

    def test_app_name_is_aegis(self):
        m = self._fresh_import({})
        self.assertEqual(m.app.main, "aegis")

    def test_task_modules_registered(self):
        m = self._fresh_import({})
        expected_tasks = [
            "aegis.workers.tasks.scan",
            "aegis.workers.tasks.fix",
            "aegis.workers.tasks.verify",
            "aegis.workers.tasks.report",
            "aegis.workers.tasks.exports",
            "aegis.workers.tasks.ci_gate",
            "aegis.workers.tasks.parallel_fix",
        ]
        registered = list(m.app.conf.include)
        for module in expected_tasks:
            self.assertIn(module, registered)


# ---------------------------------------------------------------------------
# Additional edge-case coverage
# ---------------------------------------------------------------------------

class TestVerifyStateMapConstants(unittest.TestCase):
    """Direct import / assertion on _STATE_MAP already covered by existing
    test_worker_status_persistence; included here for completeness."""

    def test_all_three_states_mapped(self):
        from aegis.workers.tasks.verify import _STATE_MAP
        self.assertEqual(_STATE_MAP["verified"], "poc_passed")
        self.assertEqual(_STATE_MAP["still_vulnerable"], "poc_failed")
        self.assertEqual(_STATE_MAP["inconclusive"], "inconclusive")


class TestCIGatePolicyEvaluateDirectly(unittest.TestCase):
    """Drive ``evaluate`` from the re-export in ci_gate to hit that import."""

    def test_re_exported_evaluate_works(self):
        from aegis.workers.tasks.ci_gate import CIGatePolicy, evaluate

        # medium finding, threshold = medium → blocking
        policy = CIGatePolicy(severity_threshold="medium")
        code, reason = evaluate(
            [{"severity": "medium", "validation_state": None}], policy
        )
        self.assertEqual(code, 1)
        self.assertIn("medium", reason)

    def test_empty_findings_always_pass(self):
        from aegis.workers.tasks.ci_gate import CIGatePolicy, evaluate
        code, reason = evaluate([], CIGatePolicy())
        self.assertEqual(code, 0)
        self.assertEqual(reason, "pass")


if __name__ == "__main__":
    unittest.main()
