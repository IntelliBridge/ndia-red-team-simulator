"""List endpoints must scope rows to the caller's project memberships.

Regression for the cross-project leak where ``GET /v1/runs`` and
``GET /v1/targets`` returned rows from projects the caller had no
membership on (the ``project`` query param was honoured without an
access check, and ``list_runs`` applied no membership filter at all).

Single-resource gates already enforce this; these tests pin the same
guarantee for the list/collection routes. System principals are
unrestricted.
"""

from __future__ import annotations

import contextlib
import unittest

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
    def _to_text(type_, compiler, **kw):  # noqa: ARG001
        return "TEXT"


def _build_app_with_sqlite():
    _patch_jsonb_for_sqlite()
    from redsim.db.models import Base, Organization, Project, Run, Target

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-a", org_id="org-1", name="ProjA", slug="proj-a"))
        s.add(Project(id="proj-b", org_id="org-1", name="ProjB", slug="proj-b"))
        s.add(Run(id="run-a", project_id="proj-a", mode="api",
                  status="succeeded", stage_table={}))
        s.add(Run(id="run-b", project_id="proj-b", mode="api",
                  status="succeeded", stage_table={}))
        s.add(Target(id="tgt-a", project_id="proj-a", kind="url",
                     value="https://a.example", verified=True))
        s.add(Target(id="tgt-b", project_id="proj-b", kind="url",
                     value="https://b.example", verified=True))
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


def _client(app, user: CurrentUser) -> TestClient:
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


class TestListRunScoping(unittest.TestCase):
    def test_list_runs_omits_unaffiliated_projects(self):
        from unittest.mock import patch
        app, session_cm = _build_app_with_sqlite()
        member_b = CurrentUser(sub="u-b", email="b@x.com",
                               project_memberships={"proj-b": "scanner"})
        client = _client(app, member_b)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 200)
        ids = {r["id"] for r in resp.json()["runs"]}
        self.assertEqual(ids, {"run-b"})

    def test_list_runs_403_for_unaffiliated_project_filter(self):
        from unittest.mock import patch
        app, session_cm = _build_app_with_sqlite()
        member_b = CurrentUser(sub="u-b", email="b@x.com",
                               project_memberships={"proj-b": "scanner"})
        client = _client(app, member_b)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/runs", params={"project": "proj-a"})
        self.assertEqual(resp.status_code, 403)

    def test_list_runs_system_sees_all(self):
        from unittest.mock import patch
        app, session_cm = _build_app_with_sqlite()
        system = CurrentUser(sub="svc", email="svc@x.com", is_system=True)
        client = _client(app, system)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual({r["id"] for r in resp.json()["runs"]},
                         {"run-a", "run-b"})


class TestListTargetScoping(unittest.TestCase):
    def test_list_targets_403_for_unaffiliated_project(self):
        from unittest.mock import patch
        app, session_cm = _build_app_with_sqlite()
        member_b = CurrentUser(sub="u-b", email="b@x.com",
                               project_memberships={"proj-b": "scanner"})
        client = _client(app, member_b)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/targets", params={"project": "proj-a"})
        self.assertEqual(resp.status_code, 403)

    def test_list_targets_returns_member_project(self):
        from unittest.mock import patch
        app, session_cm = _build_app_with_sqlite()
        member_b = CurrentUser(sub="u-b", email="b@x.com",
                               project_memberships={"proj-b": "scanner"})
        client = _client(app, member_b)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/targets", params={"project": "proj-b"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual({t["id"] for t in resp.json()["targets"]}, {"tgt-b"})


if __name__ == "__main__":
    unittest.main()
