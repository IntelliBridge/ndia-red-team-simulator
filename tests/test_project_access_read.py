"""Phase 4 v0.3.1 F12 — project-access on report / WebSocket.

A user with no membership on a run's project receives 403 (HTTP) or
close 1008 (WebSocket). The same routes are also 404 for an unknown
run id. Membership grants read; mutation still requires role rank.
"""

from __future__ import annotations

import contextlib
import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.settings import APISettings


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(type_, compiler, **kw):
        return "TEXT"


def _build_app_with_sqlite():
    """Construct an app whose ``get_session`` is patched to a sqlite DB.

    Uses a shared in-memory connection (``StaticPool``) so every session
    on the engine sees the same schema and rows — the default sqlite
    pool would hand each session a fresh connection backed by an empty
    in-memory DB.
    """
    from sqlalchemy.pool import StaticPool
    _patch_jsonb_for_sqlite()
    from redsim.db.models import Base, Organization, Project, Run

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:  # noqa: BLE001 - skip on any sqlite failure
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-a", org_id="org-1", name="ProjA", slug="proj-a"))
        s.add(Project(id="proj-b", org_id="org-1", name="ProjB", slug="proj-b"))
        s.add(Run(id="run-a", project_id="proj-a", mode="api",
                  status="succeeded", stage_table={}))
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
    app = create_app(settings)
    return app, session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


class TestProjectAccessRead(unittest.TestCase):
    def test_report_403_when_no_membership(self):
        app, session_cm = _build_app_with_sqlite()
        outsider = CurrentUser(sub="u-outsider", email="o@x.com",
                                project_memberships={"proj-b": "admin"})
        _override_user(app, outsider)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm), \
             patch("redsim.api.policy.get_session", session_cm, create=True):
            # The route imports get_session inside ensure_run_access, so
            # patch the source module too. Already patched above.
            resp = client.get("/v1/runs/run-a/report.md")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("no membership", resp.json()["detail"])

    def test_report_404_when_run_unknown(self):
        app, session_cm = _build_app_with_sqlite()
        member = CurrentUser(sub="u-1", email="a@x.com",
                              project_memberships={"proj-a": "scanner"})
        _override_user(app, member)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/run-missing/report.md")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["detail"], "run not found")

    def test_ws_closes_1008_for_unauthorised_project(self):
        """WS upgrade succeeds, then closes 1008 when user has no membership.

        The bearer subprotocol carries dev:<email>, which the dev auth
        resolver maps to ``project_memberships={"default": "admin"}`` —
        that user has no membership on ``proj-a``, so the upgrade should
        reject.
        """
        from starlette.websockets import WebSocketDisconnect

        app, session_cm = _build_app_with_sqlite()
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm), \
             patch.dict(os.environ,
                        {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"},
                        clear=False):
            with self.assertRaises(WebSocketDisconnect) as cm, client.websocket_connect(
                    "/v1/runs/run-a/events",
                    subprotocols=["redsim.bearer.dev:outsider@x.com"]) as ws:
                # Receiving a message forces the test client to surface
                # the server-side close.
                ws.receive_json()
            self.assertEqual(cm.exception.code, 1008)

    def test_report_404_when_no_artifact(self):
        # F12 returns 404 (not 500) when the membership check passes but
        # the body just isn't present yet — blob store empty, no file.
        app, session_cm = _build_app_with_sqlite()
        member = CurrentUser(sub="u-1", email="a@x.com",
                              project_memberships={"proj-a": "scanner"})
        _override_user(app, member)
        client = TestClient(app)
        with patch("redsim.db.session.get_session", session_cm), \
             patch.dict(os.environ, {"REDSIM_OUTPUT_DIR": "/tmp/redsim-empty"},
                        clear=False):
            resp = client.get("/v1/runs/run-a/report.html")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
