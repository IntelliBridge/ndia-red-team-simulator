"""Fix-API ``override_authorized`` threading + ``open_pr`` RBAC gate.

Covers the F6 seam finished here:

- the fix worker (``fix_generate``) reads ``override_authorized`` from
  ``Job.detail`` and passes it into ``services.fixes.generate_fix`` — so a
  target authorized at admission only via the explicit override stays
  authorized through execution;
- ``create_fix_job`` persists ``override_authorized`` on the Job.detail;
- the admission route requires the approver role when ``open_pr=True`` (a
  remediator-only caller is forbidden), matching the apply gate.

All tests are offline: no real Redis/Postgres/network; the session and
service layer are mocked or backed by in-memory sqlite.
"""

from __future__ import annotations

import contextlib
import unittest
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("sqlalchemy")

from aegis.audit.chain import InMemoryAuditWriter
from aegis.config import AegisConfig
from aegis.db.models import Base, Finding, Organization, Project, Run
from aegis.services.fixes import FixOutcome, create_fix_job


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


def _make_task_ctx(job_detail: dict | None = None):
    """Return a mock TaskContext + session wired like a live worker run."""
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

    @contextlib.contextmanager
    def fake_tc(job_id, task=None):  # noqa: ARG001
        yield ctx

    return ctx, sess, job, fake_tc


def _patch_jsonb_for_sqlite() -> None:
    """Compile postgres JSONB → sqlite TEXT so create_all doesn't raise."""
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _compile_jsonb_sqlite(type_, compiler, **kw):  # noqa: ARG001
        return "TEXT"


def _make_session_factory():
    """Return a (session_cm, engine, Session) triple backed by sqlite."""
    _patch_jsonb_for_sqlite()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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


def _seed_finding(Session) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.add(Run(id="run-1", project_id="proj-1", status="running"))
        s.add(Finding(
            id="find-1", scanner_finding_id="vuln-0001",
            run_id="run-1", project_id="proj-1",
            schema_blob=_make_finding_blob(), severity="high",
            source_tool="strix",
        ))
        s.commit()


# ---------------------------------------------------------------------------
# (a) worker threads override_authorized from detail into generate_fix
# ---------------------------------------------------------------------------

class TestFixWorkerOverride(unittest.TestCase):

    def _fix_task(self):
        from aegis.workers.tasks.fix import fix_generate
        return fix_generate

    def _fix_outcome(self):
        return FixOutcome(
            success=True, strategy="live", finding_id="find-001",
            status="fixed", source="cai",
        )

    def test_override_authorized_threaded_into_generate_fix(self):
        # M1: a target authorized at admission only via the explicit override
        # must reach generate_fix, else the execution-time re-check rejects it.
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={
                "finding_id": "find-001", "strategy": "live",
                "repo": None, "apply": True, "open_pr": False,
                "override_authorized": True,
            },
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob()
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config", return_value=MagicMock()), \
             patch("aegis.services.fixes.generate_fix",
                   return_value=self._fix_outcome()) as mock_gen:
            self._fix_task().apply(args=["job-fix-ovr"]).get()

        self.assertIs(mock_gen.call_args.kwargs["override_authorized"], True)

    def test_override_defaults_false_when_absent_from_detail(self):
        ctx, sess, job, fake_tc = _make_task_ctx(
            job_detail={"finding_id": "find-001", "strategy": "patch"},
        )
        finding_row = MagicMock()
        finding_row.schema_blob = _make_finding_blob()
        sess.get.side_effect = [job, finding_row]

        with patch("aegis.workers.bootstrap.task_context", side_effect=fake_tc), \
             patch("aegis.config.load_config", return_value=MagicMock()), \
             patch("aegis.services.fixes.generate_fix",
                   return_value=self._fix_outcome()) as mock_gen:
            self._fix_task().apply(args=["job-fix-noovr"]).get()

        self.assertIs(mock_gen.call_args.kwargs["override_authorized"], False)


# ---------------------------------------------------------------------------
# (b) create_fix_job persists override_authorized on Job.detail
# ---------------------------------------------------------------------------

class TestCreateFixJobPersistsOverride(unittest.TestCase):

    def test_override_authorized_written_to_job_detail(self):
        session_cm, _, Session = _make_session_factory()
        _seed_finding(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            handle = create_fix_job(
                finding_id="find-1", strategy="live",
                apply=True, open_pr=False, repo=None,
                override_authorized=True,
                project_id="proj-1", run_id="run-1",
                actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer, enqueue=False,
            )

        from aegis.db.models import Job
        with Session() as s:
            job = s.get(Job, handle.job_id)
            self.assertIsNotNone(job)
            self.assertIs(job.detail["override_authorized"], True)

    def test_override_defaults_false_in_persisted_detail(self):
        session_cm, _, Session = _make_session_factory()
        _seed_finding(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            handle = create_fix_job(
                finding_id="find-1", strategy="patch",
                apply=False, open_pr=False, repo=None,
                project_id="proj-1", run_id="run-1",
                actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer, enqueue=False,
            )

        from aegis.db.models import Job
        with Session() as s:
            job = s.get(Job, handle.job_id)
            self.assertIs(job.detail["override_authorized"], False)


# ---------------------------------------------------------------------------
# (c) open_pr=True requires approver — remediator caller gets 403
# ---------------------------------------------------------------------------

class TestFixRouteOpenPrGate(unittest.TestCase):

    def _app_and_cm(self):
        from aegis.api.app import create_app
        from aegis.api.settings import APISettings
        session_cm, _, Session = _make_session_factory()
        _seed_finding(Session)
        app = create_app(APISettings(env="dev", auth_mode="dev",
                                     cors_origins=["http://localhost:3000"]))
        return app, session_cm

    def _client(self, app, memberships):
        from fastapi.testclient import TestClient

        from aegis.api.auth import CurrentUser, get_current_user
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships=memberships)
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_open_pr_forbidden_for_remediator(self):
        # open_pr now shares the apply gate (approver). A remediator may
        # generate but not open a PR.
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer",
                   return_value=InMemoryAuditWriter()):
            r = client.post("/v1/findings/find-1/fix",
                            json={"strategy": "patch", "open_pr": True})
        self.assertEqual(r.status_code, 403)

    def test_generate_allowed_for_remediator(self):
        # Same caller, no open_pr / apply → fix.generate gate, allowed.
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.api.v1.fix.load_config",
                   return_value=AegisConfig(target_allowlist=["localhost"])), \
             patch("aegis.workers.tasks.fix.fix_generate") as fix_generate:
            fix_generate.delay = lambda job_id: None
            r = client.post("/v1/findings/find-1/fix",
                            json={"strategy": "patch"})
        self.assertEqual(r.status_code, 200)

    def test_open_pr_allowed_for_approver(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "approver"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.api.v1.fix.load_config",
                   return_value=AegisConfig(target_allowlist=["localhost"])), \
             patch("aegis.workers.tasks.fix.fix_generate") as fix_generate:
            fix_generate.delay = lambda job_id: None
            r = client.post("/v1/findings/find-1/fix",
                            json={"strategy": "patch", "open_pr": True})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
