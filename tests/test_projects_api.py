"""Phase 4 v0.3.1 FP — project membership endpoints.

Surface required by v0.4.0's UI role gating (``useRoles`` /
``<RoleGated>``). Membership is project-scoped; admin-only routes
still enforce role rank.
"""

from __future__ import annotations

import contextlib
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.settings import APISettings


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(t, c, **kw):  # noqa: ARG001
        return "TEXT"


def _build_app_with_sqlite():
    _patch_jsonb_for_sqlite()
    from redsim.db.models import (
        Base,
        Organization,
        Project,
        ProjectMembership,
        User,
    )

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        raise unittest.SkipTest(f"sqlite: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)

    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-a", org_id="org-1", name="ProjA", slug="proj-a",
                      daily_llm_budget_cents=10000))
        s.add(Project(id="proj-b", org_id="org-1", name="ProjB", slug="proj-b"))
        s.add(User(id="u-alice", sub="dev:alice@x", email="alice@x",
                   display_name="Alice"))
        s.add(User(id="u-bob", sub="dev:bob@x", email="bob@x",
                   display_name="Bob"))
        s.add(ProjectMembership(user_id="u-alice", project_id="proj-a", role="admin"))
        s.add(ProjectMembership(user_id="u-bob", project_id="proj-a", role="scanner"))
        s.commit()

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

    settings = APISettings(env="dev", auth_mode="dev",
                           cors_origins=["http://localhost:3000"])
    return create_app(settings), session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


class TestProjectsApi(unittest.TestCase):
    def test_list_returns_only_projects_with_membership(self):
        app, session_cm = _build_app_with_sqlite()
        alice = CurrentUser(sub="dev:alice@x", email="alice@x",
                             project_memberships={"proj-a": "admin"})
        _override_user(app, alice)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/projects")
        self.assertEqual(resp.status_code, 200)
        slugs = {p["slug"] for p in resp.json()["projects"]}
        self.assertEqual(slugs, {"proj-a"})
        roles = {p["slug"]: p["role"] for p in resp.json()["projects"]}
        self.assertEqual(roles["proj-a"], "admin")

    def test_membership_403_when_caller_not_in_project(self):
        app, session_cm = _build_app_with_sqlite()
        outsider = CurrentUser(sub="dev:outsider@x", email="o@x",
                                project_memberships={"proj-b": "admin"})
        _override_user(app, outsider)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/projects/proj-a/membership")
        self.assertEqual(resp.status_code, 403)

    def test_membership_lists_users_and_roles(self):
        app, session_cm = _build_app_with_sqlite()
        alice = CurrentUser(sub="dev:alice@x", email="alice@x",
                             project_memberships={"proj-a": "admin"})
        _override_user(app, alice)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/projects/proj-a/membership")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["project"]["slug"], "proj-a")
        roles = {m["email"]: m["role"] for m in body["members"]}
        self.assertEqual(roles, {"alice@x": "admin", "bob@x": "scanner"})

    def test_settings_admin_only(self):
        app, session_cm = _build_app_with_sqlite()
        bob = CurrentUser(sub="dev:bob@x", email="bob@x",
                           project_memberships={"proj-a": "scanner"})
        _override_user(app, bob)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.put(
                "/v1/projects/proj-a/settings",
                json={"daily_llm_budget_cents": 50000},
            )
        self.assertEqual(resp.status_code, 403)

    def test_settings_admin_can_update_budget(self):
        app, session_cm = _build_app_with_sqlite()
        alice = CurrentUser(sub="dev:alice@x", email="alice@x",
                             project_memberships={"proj-a": "admin"})
        _override_user(app, alice)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.put(
                "/v1/projects/proj-a/settings",
                json={"daily_llm_budget_cents": 50000},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["daily_llm_budget_cents"], 50000)


if __name__ == "__main__":
    unittest.main()
