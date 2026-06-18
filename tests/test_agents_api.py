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
from aegis.audit.chain import InMemoryAuditWriter
from aegis.config import AegisConfig
from aegis.db.models import Job, Organization, Project, Run
from aegis.safety import AuthorizationError
from aegis.services.agents import create_agent_job
from tests.conftest import make_sqlite_session_factory as _make_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration


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
        ctx.skip = False
        ctx.actor = "service:worker"
        ctx.run_id = "run-1"
        ctx.project_id = "proj-1"
        ctx.audit_writer = MagicMock()
        fake_job = MagicMock()
        fake_job.detail = {"agent": "codeagent", "prompt": "p",
                           "target": None, "finding_id": None,
                           "repo_path": None, "execute": True}
        ctx.session.get.return_value = fake_job

        @contextlib.contextmanager
        def fake_task_context(job_id, task=None):  # noqa: ARG001
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
        # The execute flag threads from job detail into the dispatch context.
        self.assertTrue(d_args[2].execute)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output_len"], len("done"))

    def test_override_authorized_threads_into_worker_authorize(self):
        # M1: the override the caller set at admission must reach the worker's
        # re-authorize, or an off-allowlist (but authorized) target fails here.
        from aegis.workers.tasks.agent import agent_run

        ctx = MagicMock()
        ctx.skip = False
        ctx.actor = "service:worker"
        ctx.run_id = "run-2"
        ctx.project_id = "proj-1"
        ctx.audit_writer = MagicMock()
        fake_job = MagicMock()
        fake_job.detail = {"agent": "recon", "prompt": "p",
                           "target": "10.0.0.9", "finding_id": None,
                           "repo_path": None, "execute": False,
                           "override_authorized": True}
        ctx.session.get.return_value = fake_job

        @contextlib.contextmanager
        def fake_task_context(job_id, task=None):  # noqa: ARG001
            yield ctx

        with patch("aegis.workers.bootstrap.task_context", fake_task_context), \
             patch("aegis.safety.authorize") as authorize, \
             patch("aegis.agents.dispatch") as dispatch:
            dispatch.return_value = AgentResult(status="ok", output="x")
            agent_run.run("job-2")

        self.assertIs(authorize.call_args.kwargs["override_authorized"], True)

    def test_skipped_job_does_not_authorize_or_dispatch(self):
        # H2: a redelivered/cancelled job (ctx.skip) must short-circuit — no
        # re-authorize, no dispatch, no agent execution.
        from aegis.workers.tasks.agent import agent_run

        ctx = MagicMock()
        ctx.skip = True

        @contextlib.contextmanager
        def fake_task_context(job_id, task=None):  # noqa: ARG001
            yield ctx

        with patch("aegis.workers.bootstrap.task_context", fake_task_context), \
             patch("aegis.safety.authorize") as authorize, \
             patch("aegis.agents.dispatch") as dispatch:
            result = agent_run.run("job-skip")

        self.assertEqual(authorize.call_count, 0)
        self.assertEqual(dispatch.call_count, 0)
        self.assertTrue(result.get("skipped"))


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


class TestCatalogListEndpoints(unittest.TestCase):
    """GET /v1/agents and GET /v1/tools — read-only catalog listings.

    Neither touches the DB; they only require an authenticated user. The
    agents route must import the ``aegis.agents`` package (which registers
    the built-ins) so the roster is non-empty.
    """

    def _client(self):
        from fastapi.testclient import TestClient

        from aegis.api.app import create_app
        from aegis.api.auth import CurrentUser, get_current_user
        from aegis.api.settings import APISettings

        app = create_app(APISettings(env="dev", auth_mode="dev",
                                     cors_origins=["http://localhost:3000"]))
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships={"proj-1": "scanner"})
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_list_agents_returns_registered_roster(self):
        client = self._client()
        r = client.get("/v1/agents")
        self.assertEqual(r.status_code, 200)
        agents = r.json()["agents"]
        self.assertIsInstance(agents, list)
        self.assertGreater(len(agents), 0)
        # Each entry carries the four registry fields with JSON-friendly types.
        sample = agents[0]
        self.assertEqual(
            set(sample) >= {"name", "domain", "effect", "wired"}, True)
        self.assertIn(sample["effect"], {"read", "active", "external"})
        self.assertIsInstance(sample["wired"], bool)
        # The codeagent built-in is always wired.
        by_name = {a["name"]: a for a in agents}
        self.assertIn("codeagent", by_name)

    def test_list_tools_returns_catalog(self):
        client = self._client()
        r = client.get("/v1/tools")
        self.assertEqual(r.status_code, 200)
        tools = r.json()["tools"]
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0)
        sample = tools[0]
        self.assertEqual(
            set(sample) >= {"name", "category", "source", "effect",
                            "description"}, True)
        # The Kali family must be present (the /tools page filters on it).
        sources = {t["source"] for t in tools}
        self.assertIn("kali", sources)

    def test_list_endpoints_require_auth(self):
        # With no get_current_user override the dev auth dependency rejects an
        # unauthenticated request (401/403), never 200.
        from fastapi.testclient import TestClient

        from aegis.api.app import create_app
        from aegis.api.settings import APISettings

        app = create_app(APISettings(env="dev", auth_mode="dev",
                                     cors_origins=["http://localhost:3000"]))
        client = TestClient(app, raise_server_exceptions=False)
        for path in ("/v1/agents", "/v1/tools"):
            r = client.get(path)
            self.assertIn(r.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
