"""Phase 6 (Multi-tenancy) — GET /v1/orgs/{org_id}/cost dashboard.

Mirrors tests/test_logs_api.py: an in-memory sqlite DB (JSONB→TEXT shim) seeds
two orgs + projects + LLMUsage, and ``aegis.db.session.get_session`` is patched
to the test factory. ``has_org_access`` also resolves project→org via that same
session, so the patch covers both the gate and the aggregation.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.settings import APISettings
from tests.conftest import make_sqlite_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration


def _build_app_with_costs():
    from aegis.db.models import LLMUsage, Organization, Project

    session_cm, _engine, Session = make_sqlite_session_factory()

    now = datetime.now(timezone.utc)
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="org-1",
                           monthly_llm_budget_cents=10_000))
        s.add(Organization(id="org-2", name="B", slug="org-2",
                           monthly_llm_budget_cents=None))
        s.add(Project(id="proj-a", org_id="org-1", name="P", slug="proj-a"))
        s.add(Project(id="proj-b", org_id="org-2", name="Q", slug="proj-b"))
        # org-1 usage: two models, two tasks.
        s.add(LLMUsage(project_id="proj-a", org_id="org-1", model="gpt-5",
                       task="patch", cost_cents=300, created_at=now))
        s.add(LLMUsage(project_id="proj-a", org_id="org-1", model="gpt-5",
                       task="recon", cost_cents=200, created_at=now))
        s.add(LLMUsage(project_id="proj-a", org_id="org-1",
                       model="anthropic/claude-opus-4-8",
                       task="patch", cost_cents=500, created_at=now))
        # org-2 usage: must NOT leak into org-1's totals.
        s.add(LLMUsage(project_id="proj-b", org_id="org-2", model="gpt-5",
                       task="patch", cost_cents=999, created_at=now))
        s.commit()

    settings = APISettings(env="dev", auth_mode="dev",
                            cors_origins=["http://localhost:3000"])
    return create_app(settings), session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


# A member of proj-a (in org-1).
_ORG1_MEMBER = CurrentUser(sub="dev:m1", email="m1@x",
                           project_memberships={"proj-a": "scanner"})
# A member of proj-b only (in org-2) — has no access to org-1.
_ORG2_MEMBER = CurrentUser(sub="dev:m2", email="m2@x",
                           project_memberships={"proj-b": "scanner"})


class TestOrgCostApi(unittest.TestCase):
    def test_member_gets_aggregation_and_budget(self):
        app, session_cm = _build_app_with_costs()
        _override_user(app, _ORG1_MEMBER)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/orgs/org-1/cost?days=30")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["org_id"], "org-1")
        self.assertEqual(body["total_cents"], 1000)   # 300 + 200 + 500
        self.assertEqual(body["call_count"], 3)
        # by_model: gpt-5 = 500, claude = 500
        self.assertEqual(body["by_model"]["gpt-5"], 500)
        self.assertEqual(body["by_model"]["anthropic/claude-opus-4-8"], 500)
        # by_task: patch = 800, recon = 200
        self.assertEqual(body["by_task"]["patch"], 800)
        self.assertEqual(body["by_task"]["recon"], 200)
        # by_day: single seed day carries the full 1000.
        self.assertEqual(sum(body["by_day"].values()), 1000)
        # budget block: cap 10_000, month spend 1000, remaining 9000.
        self.assertEqual(body["budget"]["monthly_cap_cents"], 10_000)
        self.assertEqual(body["budget"]["month_spent_cents"], 1000)
        self.assertEqual(body["budget"]["remaining_cents"], 9000)

    def test_excludes_other_orgs_usage(self):
        app, session_cm = _build_app_with_costs()
        _override_user(app, _ORG1_MEMBER)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/orgs/org-1/cost")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        # org-2's 999-cent row must not appear anywhere in org-1's totals.
        self.assertEqual(body["total_cents"], 1000)
        self.assertNotIn(999, body["by_model"].values())

    def test_uncapped_org_has_null_remaining(self):
        # org-2 has monthly_llm_budget_cents=None → remaining null (uncapped).
        app, session_cm = _build_app_with_costs()
        _override_user(app, _ORG2_MEMBER)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/orgs/org-2/cost")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIsNone(body["budget"]["monthly_cap_cents"])
        self.assertIsNone(body["budget"]["remaining_cents"])
        self.assertEqual(body["budget"]["month_spent_cents"], 999)

    def test_non_member_is_403(self):
        app, session_cm = _build_app_with_costs()
        _override_user(app, _ORG2_MEMBER)  # only in org-2
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/orgs/org-1/cost")
        self.assertEqual(resp.status_code, 403)

    def test_unknown_org_is_404_for_system(self):
        # System user passes the access gate; the handler then 404s on the
        # missing org row.
        app, session_cm = _build_app_with_costs()
        sysuser = CurrentUser(sub="service:worker:1", email="w@x",
                              project_memberships={}, is_system=True)
        _override_user(app, sysuser)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/orgs/does-not-exist/cost")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
