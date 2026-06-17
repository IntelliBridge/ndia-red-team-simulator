"""Ticket-sync layer: providers, resolver, service, and API.

All offline: httpx is mocked via a fake transport / MagicMock; the DB is
in-memory sqlite (JSONB compiled to TEXT), mirroring test_fix_override.py.
"""

from __future__ import annotations

import contextlib
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

import httpx

from aegis.audit.chain import InMemoryAuditWriter
from aegis.db.models import Base, Finding, Organization, Project, Run
from aegis.integrations import ticket_provider as tp


def _make_finding_blob(**overrides) -> dict:
    base = {
        "id": "find-001",
        "title": "SQL Injection",
        "severity": "high",
        "finding_type": "sast",
        "description": "Unsanitised input used in query",
        "affected_component": "app/db.py",
        "status": "open",
    }
    base.update(overrides)
    return base


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
# Provider mapping + error handling
# ---------------------------------------------------------------------------

class FakePost:
    """Records the last (url, json, kwargs) and returns a canned Response."""

    def __init__(self, *, json_body, status_code=200):
        self.json_body = json_body
        self.status_code = status_code
        self.calls: list[dict] = []

    def __call__(self, url, *, json=None, **kwargs):
        self.calls.append({"url": url, "json": json, "kwargs": kwargs})
        req = httpx.Request("POST", url)
        return httpx.Response(self.status_code, json=self.json_body, request=req)


class FakeGet:
    """GET stub: records calls and returns a canned Response."""

    def __init__(self, *, json_body, status_code=200):
        self.json_body = json_body
        self.status_code = status_code
        self.calls: list[dict] = []

    def __call__(self, url, *, params=None, **kwargs):
        self.calls.append({"url": url, "params": params, "kwargs": kwargs})
        req = httpx.Request("GET", url)
        return httpx.Response(self.status_code, json=self.json_body, request=req)


class TestJiraProvider(unittest.TestCase):
    def _provider(self):
        return tp.JiraTicketProvider(
            base_url="https://jira.example.com/", user="svc",
            token="s3cr3t", project_key="SEC")

    def test_sync_finding_maps_request_and_returns_ref(self):
        fake = FakePost(json_body={"key": "SEC-42"})
        with patch("httpx.Client.post", new=fake):
            ref = self._provider().sync_finding(
                "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertEqual(ref.provider, "jira")
        self.assertEqual(ref.external_id, "SEC-42")
        self.assertEqual(ref.url, "https://jira.example.com/browse/SEC-42")
        call = fake.calls[0]
        self.assertTrue(call["url"].endswith("/rest/api/2/issue"))
        fields = call["json"]["fields"]
        self.assertEqual(fields["project"]["key"], "SEC")
        self.assertIn("SQL Injection", fields["summary"])
        self.assertIn("HIGH", fields["summary"])
        self.assertIn("find-1", fields["description"])

    def test_http_error_raises_secret_free(self):
        fake = FakePost(json_body={"errorMessages": ["s3cr3t leaked"]},
                        status_code=401)
        with patch("httpx.Client.post", new=fake):
            with self.assertRaises(tp.TicketProviderError) as ctx:
                self._provider().sync_finding(
                    "find-1", _make_finding_blob(), project_id="proj-1")
        msg = str(ctx.exception)
        self.assertIn("401", msg)
        self.assertNotIn("s3cr3t", msg)

    def test_fetch_status(self):
        fake = FakeGet(json_body={"fields": {"status": {"name": "In Progress"}}})
        with patch("httpx.Client.get", new=fake):
            status = self._provider().fetch_status("SEC-42")
        self.assertEqual(status, "In Progress")
        self.assertTrue(fake.calls[0]["url"].endswith("/rest/api/2/issue/SEC-42"))

    def test_from_env_missing_var_raises(self):
        import os
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("AEGIS_JIRA")}
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(tp.TicketProviderError) as ctx:
                tp.JiraTicketProvider.from_env()
        self.assertIn("AEGIS_JIRA_URL", str(ctx.exception))


class TestServiceNowProvider(unittest.TestCase):
    def _provider(self):
        return tp.ServiceNowTicketProvider(
            instance_url="https://acme.service-now.com", token="snow-tok")

    def test_sync_finding_posts_incident(self):
        fake = FakePost(json_body={"result": {"sys_id": "abc123",
                                              "number": "INC0001",
                                              "state": "1"}})
        with patch("httpx.Client.post", new=fake):
            ref = self._provider().sync_finding(
                "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertEqual(ref.provider, "servicenow")
        self.assertEqual(ref.external_id, "abc123")
        self.assertEqual(ref.status, "1")
        call = fake.calls[0]
        self.assertTrue(call["url"].endswith("/api/now/table/incident"))
        self.assertIn("SQL Injection", call["json"]["short_description"])

    def test_http_error_raises_secret_free(self):
        fake = FakePost(json_body={}, status_code=500)
        with patch("httpx.Client.post", new=fake):
            with self.assertRaises(tp.TicketProviderError) as ctx:
                self._provider().sync_finding(
                    "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertIn("500", str(ctx.exception))
        self.assertNotIn("snow-tok", str(ctx.exception))

    def test_fetch_status(self):
        fake = FakeGet(json_body={"result": {"state": "2"}})
        with patch("httpx.Client.get", new=fake):
            status = self._provider().fetch_status("abc123")
        self.assertEqual(status, "2")
        self.assertTrue(fake.calls[0]["url"].endswith(
            "/api/now/table/incident/abc123"))

    def test_from_env_missing_var_raises(self):
        import os
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("AEGIS_SERVICENOW")}
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(tp.TicketProviderError):
                tp.ServiceNowTicketProvider.from_env()


class TestLinearProvider(unittest.TestCase):
    def _provider(self):
        return tp.LinearTicketProvider(api_key="lin_key_secret", team_id="team-9")

    def test_sync_finding_issue_create(self):
        body = {"data": {"issueCreate": {"success": True, "issue": {
            "id": "iss-1", "identifier": "SEC-7",
            "url": "https://linear.app/x/issue/SEC-7",
            "state": {"name": "Todo"}}}}}
        fake = FakePost(json_body=body)
        with patch("httpx.Client.post", new=fake):
            ref = self._provider().sync_finding(
                "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertEqual(ref.provider, "linear")
        self.assertEqual(ref.external_id, "iss-1")
        self.assertEqual(ref.status, "Todo")
        call = fake.calls[0]
        self.assertEqual(call["url"], "https://api.linear.app/graphql")
        self.assertEqual(call["json"]["variables"]["input"]["teamId"], "team-9")

    def test_graphql_errors_raise(self):
        fake = FakePost(json_body={"errors": [{"message": "bad"}]})
        with patch("httpx.Client.post", new=fake):
            with self.assertRaises(tp.TicketProviderError) as ctx:
                self._provider().sync_finding(
                    "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertNotIn("lin_key_secret", str(ctx.exception))

    def test_fetch_status(self):
        body = {"data": {"issue": {"state": {"name": "Done"}}}}
        fake = FakePost(json_body=body)
        with patch("httpx.Client.post", new=fake):
            status = self._provider().fetch_status("iss-1")
        self.assertEqual(status, "Done")

    def test_connection_error_wrapped_secret_free(self):
        def _boom(self, url, **kwargs):  # noqa: ARG001
            raise httpx.ConnectError("dns failed")
        with patch("httpx.Client.post", new=_boom):
            with self.assertRaises(tp.TicketProviderError) as ctx:
                self._provider().sync_finding(
                    "find-1", _make_finding_blob(), project_id="proj-1")
        self.assertIn("connection error", str(ctx.exception))
        self.assertNotIn("lin_key_secret", str(ctx.exception))

    def test_from_env_missing_var_raises(self):
        import os
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("AEGIS_LINEAR")}
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(tp.TicketProviderError):
                tp.LinearTicketProvider.from_env()


class TestNoneProvider(unittest.TestCase):
    def test_sync_raises(self):
        with self.assertRaises(tp.TicketProviderError) as ctx:
            tp.NoneTicketProvider().sync_finding(
                "find-1", {}, project_id="proj-1")
        self.assertIn("no ticket provider configured", str(ctx.exception))


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class TestResolver(unittest.TestCase):
    def tearDown(self):
        tp.reset_ticket_provider_cache()

    def test_default_is_none(self):
        tp.reset_ticket_provider_cache()
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("AEGIS_TICKET_PROVIDER", None)
            prov = tp.resolve_ticket_provider()
        self.assertIsInstance(prov, tp.NoneTicketProvider)

    def test_env_selects_jira_and_caches(self):
        tp.reset_ticket_provider_cache()
        env = {
            "AEGIS_TICKET_PROVIDER": "jira",
            "AEGIS_JIRA_URL": "https://j", "AEGIS_JIRA_USER": "u",
            "AEGIS_JIRA_TOKEN": "t", "AEGIS_JIRA_PROJECT_KEY": "K",
        }
        with patch.dict("os.environ", env, clear=False):
            prov1 = tp.resolve_ticket_provider()
            prov2 = tp.resolve_ticket_provider()
        self.assertIsInstance(prov1, tp.JiraTicketProvider)
        self.assertIs(prov1, prov2)  # cached

    def test_reset_clears_cache(self):
        tp.reset_ticket_provider_cache()
        with patch.dict("os.environ", {"AEGIS_TICKET_PROVIDER": "none"}):
            p1 = tp.resolve_ticket_provider()
        tp.reset_ticket_provider_cache()
        env = {"AEGIS_TICKET_PROVIDER": "servicenow",
               "AEGIS_SERVICENOW_INSTANCE": "https://s",
               "AEGIS_SERVICENOW_TOKEN": "tok"}
        with patch.dict("os.environ", env, clear=False):
            p2 = tp.resolve_ticket_provider()
        self.assertIsInstance(p1, tp.NoneTicketProvider)
        self.assertIsInstance(p2, tp.ServiceNowTicketProvider)

    def test_unknown_provider_raises(self):
        tp.reset_ticket_provider_cache()
        with patch.dict("os.environ", {"AEGIS_TICKET_PROVIDER": "bogus"}):
            with self.assertRaises(tp.TicketProviderError):
                tp.resolve_ticket_provider()

    def test_config_fallback(self):
        tp.reset_ticket_provider_cache()
        from aegis.config import AegisConfig
        cfg = AegisConfig(ticket_provider="none")
        import os
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("AEGIS_TICKET_PROVIDER", None)
            prov = tp.resolve_ticket_provider(cfg)
        self.assertIsInstance(prov, tp.NoneTicketProvider)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class _StubProvider:
    name = "jira"

    def __init__(self):
        self.synced = []

    def sync_finding(self, finding_id, schema_blob, *, project_id):
        self.synced.append(finding_id)
        return tp.TicketRef(provider="jira", external_id="SEC-42",
                            url="https://j/browse/SEC-42", status="Open")

    def fetch_status(self, external_id):
        return "Done"


class TestService(unittest.TestCase):
    def setUp(self):
        self.session_cm, _, self.Session = _make_session_factory()
        _seed_finding(self.Session)

    def test_sync_upserts_and_emits_audit(self):
        from aegis.services import finding_tickets as svc
        writer = InMemoryAuditWriter()
        stub = _StubProvider()
        with self.Session() as sess:
            row1 = svc.sync_finding(sess, "find-1", actor="user:alice",
                                    audit_writer=writer, provider=stub)
            sess.commit()
            rid1 = row1.id
        # second sync is idempotent on (finding_id, provider)
        with self.Session() as sess:
            row2 = svc.sync_finding(sess, "find-1", actor="user:alice",
                                    audit_writer=writer, provider=stub)
            sess.commit()
            rid2 = row2.id
        self.assertEqual(rid1, rid2)
        with self.Session() as sess:
            rows = svc.list_tickets(sess, "find-1")
        self.assertEqual(len(rows), 1)
        actions = [e.action for e in writer.events]
        self.assertEqual(actions, ["ticket.sync", "ticket.sync"])
        ev = writer.events[0]
        self.assertEqual(ev.detail["provider"], "jira")
        self.assertEqual(ev.detail["external_id"], "SEC-42")
        # secret-free: detail carries no creds
        self.assertNotIn("token", ev.detail)

    def test_sync_unknown_finding_raises(self):
        from aegis.services import finding_tickets as svc
        with self.Session() as sess:
            with self.assertRaises(LookupError):
                svc.sync_finding(sess, "nope", actor="user:a",
                                 provider=_StubProvider())

    def test_refresh_updates_status(self):
        from aegis.services import finding_tickets as svc
        stub = _StubProvider()
        with self.Session() as sess:
            row = svc.sync_finding(sess, "find-1", actor="user:a", provider=stub)
            sess.commit()
            tid = row.id
        with self.Session() as sess:
            updated = svc.refresh_status(sess, tid, provider=stub)
            sess.commit()
            self.assertEqual(updated.status, "Done")

    def test_refresh_unknown_raises(self):
        from aegis.services import finding_tickets as svc
        with self.Session() as sess:
            with self.assertRaises(LookupError):
                svc.refresh_status(sess, "tkt-missing", provider=_StubProvider())


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

class TestAPI(unittest.TestCase):
    def setUp(self):
        # The rate-limit middleware keeps module-global token buckets keyed by
        # principal (here ``ip:testclient``). Clear them so this file's burst of
        # POSTs starts with a fresh budget and doesn't leak 429s onto later
        # API tests in the full-suite run.
        import aegis.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()

    def tearDown(self):
        # Leave the shared buckets fresh so this file is hermetic and a later
        # API test (e.g. test_fix_override) doesn't inherit an exhausted budget.
        import aegis.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()

    def _app_and_cm(self):
        from aegis.api.app import create_app
        from aegis.api.settings import APISettings
        session_cm, _, Session = _make_session_factory()
        _seed_finding(Session)
        app = create_app(APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            rate_limit_per_user_per_min=10_000,
            rate_limit_per_project_per_min=10_000,
        ))
        return app, session_cm

    def _client(self, app, memberships):
        from fastapi.testclient import TestClient

        from aegis.api.auth import CurrentUser, get_current_user
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships=memberships)
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_sync_returns_ticket_no_secret(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.finding_tickets.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.services.finding_tickets.resolve_ticket_provider",
                   return_value=_StubProvider()):
            r = client.post("/v1/findings/find-1/ticket")
        self.assertIn(r.status_code, (200, 201))
        body = r.json()
        self.assertEqual(body["provider"], "jira")
        self.assertEqual(body["external_id"], "SEC-42")
        self.assertNotIn("token", body)

    def test_provider_none_returns_409(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.finding_tickets.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.services.finding_tickets.resolve_ticket_provider",
                   return_value=tp.NoneTicketProvider()):
            r = client.post("/v1/findings/find-1/ticket")
        self.assertEqual(r.status_code, 409)
        self.assertIn("no ticket provider configured", r.json()["detail"])

    def test_non_member_forbidden(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"other-proj": "admin"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.post("/v1/findings/find-1/ticket")
        self.assertEqual(r.status_code, 403)

    def test_unknown_finding_404(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.post("/v1/findings/nope/ticket")
        self.assertEqual(r.status_code, 404)

    def test_list_and_refresh(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.finding_tickets.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.services.finding_tickets.resolve_ticket_provider",
                   return_value=_StubProvider()):
            client.post("/v1/findings/find-1/ticket")
            lst = client.get("/v1/findings/find-1/tickets")
            self.assertEqual(lst.status_code, 200)
            tickets = lst.json()["tickets"]
            self.assertEqual(len(tickets), 1)
            tid = tickets[0]["id"]
            ref = client.post(f"/v1/findings/find-1/tickets/{tid}/refresh")
            self.assertEqual(ref.status_code, 200)
            self.assertEqual(ref.json()["status"], "Done")


if __name__ == "__main__":
    unittest.main()
