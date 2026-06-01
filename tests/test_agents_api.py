"""Phase 4 v0.3.1 F6 — agent admission + execution contract.

Mirrors ``tests/test_admission_audit_before_enqueue.py``: an sqlite-
backed harness exercises ``create_agent_job`` (the admission boundary)
without a real Postgres/Redis, asserting the load-bearing ordering
invariant — the chain audit row exists *before* the Run/Job rows and
*before* Celery is touched. A final test drives the worker task body
(``agent_run``) with everything patched out, purely for coverage.
"""

from __future__ import annotations

import contextlib
import unittest
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("sqlalchemy")

from aegis.agents import AgentResult
from aegis.audit.writers import InMemoryAuditWriter
from aegis.config import AegisConfig
from aegis.db.models import Base, Job, Organization, Project, Run
from aegis.safety import AuthorizationError
from aegis.services.agents import create_agent_job


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
    # StaticPool shares the single in-memory connection across threads so
    # route tests (endpoint runs in Starlette's threadpool) see the same
    # DB the test thread seeded.
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


def _seed_project(Session) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.commit()


class TestAgentAdmission(unittest.TestCase):
    def test_agent_admission_emits_chain_row_before_celery(self):
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
             patch("aegis.workers.tasks.agent.agent_run") as agent_run:
            agent_run.delay = fake_delay
            handle = create_agent_job(
                agent_name="codeagent", prompt="fix it",
                project_id="proj-1", actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer,
            )

        # Audit row landed on the chain
        events = writer.events
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].action, "agent.run")
        self.assertEqual(events[0].success, True)
        # target is None here → nothing to match against the allowlist,
        # so authorize records "n/a" (same as the fix service path).
        self.assertEqual(events[0].allowlist_check, "n/a")

        # Run + Job were persisted, queued, with no celery_task_id yet
        with Session() as s:
            run = s.get(Run, handle.run_id)
            self.assertIsNotNone(run)
            self.assertEqual(run.status, "queued")
            job = s.get(Job, handle.job_id)
            self.assertIsNotNone(job)
            self.assertEqual(job.status, "queued")
            self.assertEqual(job.type, "agent.run")
            self.assertIsNone(job.celery_task_id)

        # Enqueue happened *after* the audit row (asserted in fake_delay)
        self.assertEqual(enqueue_calls, [handle.job_id])

    def test_agent_admission_no_dispatch_when_enqueue_false(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.workers.tasks.agent.agent_run") as agent_run:
            handle = create_agent_job(
                agent_name="codeagent", prompt="fix it",
                project_id="proj-1", actor="user:test",
                config=AegisConfig(target_allowlist=["localhost"]),
                audit_writer=writer, enqueue=False,
            )
            # Admission never dispatches when enqueue is False.
            agent_run.delay.assert_not_called()

        self.assertEqual(len(writer.events), 1)
        self.assertEqual(writer.events[0].action, "agent.run")
        with Session() as s:
            self.assertIsNotNone(s.get(Run, handle.run_id))
            self.assertIsNotNone(s.get(Job, handle.job_id))

    def test_agent_admission_refuses_unauthorised_target(self):
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
        writer = InMemoryAuditWriter()

        with patch("aegis.db.session.get_session", session_cm):
            with self.assertRaises(AuthorizationError):
                create_agent_job(
                    agent_name="codeagent", prompt="fix it",
                    target="http://attacker.example.com",
                    project_id="proj-1", actor="user:test",
                    config=AegisConfig(target_allowlist=["localhost"]),
                    audit_writer=writer,
                )

        # The refusal still lands on the chain as a fail.
        self.assertEqual(len(writer.events), 1)
        self.assertEqual(writer.events[0].action, "agent.run")
        self.assertEqual(writer.events[0].allowlist_check, "fail")
        self.assertFalse(writer.events[0].success)

        # And no Run rows were inserted.
        with Session() as s:
            self.assertEqual(s.query(Run).count(), 0)


class TestAgentRunTask(unittest.TestCase):
    def test_agent_run_task_dispatches(self):
        from aegis.workers.tasks.agent import agent_run

        ctx = MagicMock()
        ctx.actor = "service:worker"
        ctx.run_id = "run-1"
        ctx.project_id = "proj-1"
        ctx.audit_writer = MagicMock()
        fake_job = MagicMock()
        fake_job.detail = {"agent": "codeagent", "prompt": "p",
                           "target": None, "finding_id": None,
                           "repo_path": None}
        ctx.run_state.session.get.return_value = fake_job

        @contextlib.contextmanager
        def fake_task_context(job_id):  # noqa: ARG001
            yield ctx

        # task_context/authorize are imported inside the task body, so
        # they aren't attributes of the task module — patch them at
        # their definition sites where the late import resolves them.
        with patch("aegis.workers.bootstrap.task_context",
                   fake_task_context), \
             patch("aegis.safety.authorize") as authorize, \
             patch("aegis.agents.dispatch") as dispatch:
            dispatch.return_value = AgentResult(status="ok", output="done")
            # bound celery task — call the unbound body via .run
            result = agent_run.run("job-1")

        # Worker re-authorized with an agent.execute.* action.
        self.assertEqual(authorize.call_count, 1)
        action = authorize.call_args.args[0]
        self.assertTrue(action.startswith("agent.execute."))

        # dispatch invoked once with (name, prompt, AgentContext).
        self.assertEqual(dispatch.call_count, 1)
        d_args = dispatch.call_args.args
        self.assertEqual(d_args[0], "codeagent")
        self.assertEqual(d_args[1], "p")
        from aegis.agents import AgentContext
        self.assertIsInstance(d_args[2], AgentContext)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output_len"], len("done"))


class TestAgentRoute(unittest.TestCase):
    """Cover the admission route body: 400 (no prompt), 403 (role), 200."""

    def _app_and_cm(self):
        from aegis.api.app import create_app
        from aegis.api.settings import APISettings
        session_cm, _, Session = _make_session_factory()
        _seed_project(Session)
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

    def test_route_enqueues_and_returns_handle(self):
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.agents.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.workers.tasks.agent.agent_run") as agent_run:
            agent_run.delay = lambda job_id: None
            r = client.post("/v1/agents/codeagent/run",
                            json={"project_id": "proj-1", "prompt": "fix it"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("run_id", body)
        self.assertTrue(body["status_url"].endswith(body["run_id"]))

    def test_route_missing_prompt_returns_400(self):
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.agents.resolve_writer",
                   return_value=InMemoryAuditWriter()):
            r = client.post("/v1/agents/codeagent/run",
                            json={"project_id": "proj-1"})
        self.assertEqual(r.status_code, 400)

    def test_route_forbids_role_below_remediator(self):
        app, session_cm = self._app_and_cm()
        # scanner (rank 1) is below the remediator floor for AGENT_RUN → 403.
        client = self._client(app, {"proj-1": "scanner"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.agents.resolve_writer",
                   return_value=InMemoryAuditWriter()):
            r = client.post("/v1/agents/codeagent/run",
                            json={"project_id": "proj-1", "prompt": "x"})
        self.assertEqual(r.status_code, 403)

    def test_route_unauthorised_target_returns_403(self):
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        # RBAC passes (remediator), but the target is off the allowlist →
        # create_agent_job raises AuthorizationError, which the route must
        # translate to 403 (not a 500).
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.agents.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.api.v1.agents.load_config",
                   return_value=AegisConfig(target_allowlist=["localhost"])):
            r = client.post(
                "/v1/agents/codeagent/run",
                json={"project_id": "proj-1", "prompt": "x",
                      "target": "http://attacker.example.com"})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
