"""Authenticated-DAST plumbing: API body → Job.detail → worker → ScanOptions.

Covers the non-adapter half of the feature:

  - ``StartScanBody`` accepts (and defaults) ``auth_profile_id``.
  - ``create_scan_job`` persists ``auth_profile_id`` in ``Job.detail`` and
    carries it (id only — never a secret) on the admission audit event.
  - The ``scan_start`` worker resolves the profile and injects the resolved
    dict into ``ScanOptions.extra["auth"]``.
  - Resolution failure fails the job with a secret-free error and never
    dispatches the scanner.

``aegis.services.auth_profiles`` is faked via ``sys.modules`` so these tests
exercise only the contract (``resolve_auth_for_scan(session, profile_id)``),
not that module's implementation.
"""

from __future__ import annotations

import contextlib
import sys
import types
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("celery")

from aegis.audit.chain import InMemoryAuditWriter
from aegis.config import AegisConfig
from aegis.db.models import Base, Job, Organization, Project
from aegis.services.scans import create_scan_job

AUTH_DICT = {
    "kind": "bearer",
    "config": {},
    "secret": "tok-s3cr3t-bearer",
}


# ---------------------------------------------------------------------------
# Helpers (sqlite session factory — mirrors test_admission_audit_before_enqueue)
# ---------------------------------------------------------------------------

def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _compile_jsonb_sqlite(type_, compiler, **kw):  # noqa: ARG001
        return "TEXT"


def _make_session_factory():
    _patch_jsonb_for_sqlite()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine("sqlite://", future=True)
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    return session_cm, engine, Session


def _seed_project(Session) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.commit()


def _make_task_ctx(job_detail: dict | None = None):
    """Mock TaskContext + session, mirroring test_worker_tasks_coverage."""
    ctx = MagicMock()
    ctx.skip = False
    ctx.run_id = "run-001"
    ctx.project_id = "proj-001"
    ctx.actor = "user:alice"

    job = MagicMock()
    job.detail = job_detail or {}

    sess = MagicMock()
    sess.get.return_value = job
    ctx.session = sess
    ctx.run_state.load_findings.return_value = []

    @contextmanager
    def fake_tc(job_id):  # noqa: ARG001
        yield ctx

    return ctx, sess, job, fake_tc


@contextmanager
def _fake_auth_profiles_module(resolve_mock):
    """Install a fake ``aegis.services.auth_profiles`` in sys.modules.

    The real module is being built in parallel; the worker only depends on
    the ``resolve_auth_for_scan`` name, so the fake keeps these tests
    decoupled from its implementation (and importable without it).
    """
    fake = types.ModuleType("aegis.services.auth_profiles")
    fake.resolve_auth_for_scan = resolve_mock
    with patch.dict(sys.modules, {"aegis.services.auth_profiles": fake}):
        yield


# ---------------------------------------------------------------------------
# API body
# ---------------------------------------------------------------------------

class TestStartScanBody(unittest.TestCase):
    def test_accepts_auth_profile_id(self):
        pytest.importorskip("fastapi")
        from aegis.api.v1.scans import StartScanBody
        body = StartScanBody(target="http://localhost:3000",
                             scanner="zap", auth_profile_id="ap-1")
        self.assertEqual(body.auth_profile_id, "ap-1")

    def test_auth_profile_id_defaults_to_none(self):
        pytest.importorskip("fastapi")
        from aegis.api.v1.scans import StartScanBody
        self.assertIsNone(StartScanBody(target="http://x").auth_profile_id)


# ---------------------------------------------------------------------------
# Admission service
# ---------------------------------------------------------------------------

class TestCreateScanJobAuthProfile(unittest.TestCase):
    def _create(self, Session_cm, writer, auth_profile_id):
        return create_scan_job(
            target="http://localhost:3000",
            scanner="strix", project_id="proj-1",
            actor="user:test",
            auth_profile_id=auth_profile_id,
            config=AegisConfig(target_allowlist=["localhost"]),
            audit_writer=writer,
            enqueue=False,
        )

    def test_auth_profile_id_persisted_in_job_detail(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            handle = self._create(session_cm, writer, "ap-1")

        with Session() as s:
            job = s.get(Job, handle.job_id)
            self.assertIsNotNone(job)
            self.assertEqual(job.detail.get("auth_profile_id"), "ap-1")

    def test_auth_profile_id_on_audit_event_detail(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            self._create(session_cm, writer, "ap-1")

        self.assertEqual(len(writer.events), 1)
        self.assertEqual(writer.events[0].action, "scan.start")
        self.assertEqual(writer.events[0].detail.get("auth_profile_id"), "ap-1")

    def test_default_none_keeps_existing_shape(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            handle = create_scan_job(
                target="http://localhost:3000",
                scanner="strix", project_id="proj-1",
                actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer,
                enqueue=False,
            )

        with Session() as s:
            job = s.get(Job, handle.job_id)
            self.assertIsNone(job.detail.get("auth_profile_id"))


# ---------------------------------------------------------------------------
# Worker task
# ---------------------------------------------------------------------------

class TestScanStartAuthInjection(unittest.TestCase):
    def _scan_task(self):
        from aegis.workers.tasks.scan import scan_start
        return scan_start

    def test_worker_injects_extra_auth_when_profile_set(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "http://localhost", "scanner": "zap",
                        "instruction": None, "auth_profile_id": "ap-1"},
        )
        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0
        resolve = MagicMock(return_value=AUTH_DICT)

        with _fake_auth_profiles_module(resolve), \
             patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch", return_value=disp_result) as mock_disp:
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            self._scan_task().apply(args=["job-auth-001"]).get()

        resolve.assert_called_once_with(ctx.session, "ap-1")
        options = mock_disp.call_args[0][2]
        self.assertEqual(options.extra["auth"], AUTH_DICT)

    def test_worker_skips_resolution_without_profile(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "http://localhost", "scanner": "zap"},
        )
        disp_result = MagicMock()
        disp_result.findings = []
        disp_result.exit_code = 0
        resolve = MagicMock()

        with _fake_auth_profiles_module(resolve), \
             patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch", return_value=disp_result) as mock_disp:
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            self._scan_task().apply(args=["job-auth-002"]).get()

        resolve.assert_not_called()
        options = mock_disp.call_args[0][2]
        self.assertNotIn("auth", options.extra)

    def test_worker_fails_cleanly_when_resolution_fails(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"target": "http://localhost", "scanner": "zap",
                        "auth_profile_id": "ap-missing"},
        )
        resolve = MagicMock(
            side_effect=LookupError("auth profile not found: ap-missing"))

        with _fake_auth_profiles_module(resolve), \
             patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config") as mock_cfg, \
             patch("aegis.safety.authorize"), \
             patch("aegis.scanners.dispatch") as mock_disp:
            mock_cfg.return_value = MagicMock(target_allowlist=[])
            with self.assertRaises(RuntimeError) as cm:
                self._scan_task().apply(args=["job-auth-003"]).get()

        # Clear, secret-free error: names the profile and failure class only.
        msg = str(cm.exception)
        self.assertIn("ap-missing", msg)
        self.assertIn("LookupError", msg)
        # The scanner never ran.
        mock_disp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
