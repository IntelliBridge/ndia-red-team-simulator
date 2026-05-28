"""Phase 4 v0.4.1 F22 — /v1/logs admin endpoint."""

from __future__ import annotations

import contextlib
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from aegis.api.app import create_app
from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.settings import APISettings


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(t, c, **kw):  # noqa: ARG001
        return "TEXT"


def _build_app_with_logs():
    _patch_jsonb_for_sqlite()
    from aegis.db.models import (
        ApplicationLog, Base, Organization, Project,
    )

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-a", org_id="org-1", name="P", slug="proj-a"))
        for i in range(5):
            s.add(ApplicationLog(
                ts=now, severity="info" if i % 2 == 0 else "error",
                service="aegis-api", message=f"event {i}",
                run_id="run-1", project_id="proj-a",
                request_id="req-abc",
            ))
        s.commit()

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        finally:
            sess.close()

    settings = APISettings(env="dev", auth_mode="dev",
                            cors_origins=["http://localhost:3000"])
    return create_app(settings), session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


class TestLogsApi(unittest.TestCase):
    def test_admin_can_list_logs(self):
        app, session_cm = _build_app_with_logs()
        admin = CurrentUser(sub="dev:admin", email="a@x",
                              project_memberships={"default": "admin"})
        _override_user(app, admin)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.audit.chain.resolve_writer",
                   return_value=_DiscardWriter()):
            resp = client.get("/v1/logs?run=run-1")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(len(body["logs"]), 5)
        self.assertEqual(body["count"], 5)
        # Newest first
        self.assertGreater(body["logs"][0]["id"], body["logs"][-1]["id"])

    def test_non_admin_is_403(self):
        app, session_cm = _build_app_with_logs()
        scanner = CurrentUser(sub="dev:scanner", email="s@x",
                                project_memberships={"default": "scanner"})
        _override_user(app, scanner)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/logs")
        self.assertEqual(resp.status_code, 403)

    def test_filters_apply(self):
        app, session_cm = _build_app_with_logs()
        admin = CurrentUser(sub="dev:admin", email="a@x",
                              project_memberships={"default": "admin"})
        _override_user(app, admin)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.audit.chain.resolve_writer",
                   return_value=_DiscardWriter()):
            resp = client.get("/v1/logs?severity=error")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        # 2 of the 5 seed rows are severity=error.
        for row in body["logs"]:
            self.assertEqual(row["severity"], "error")
        self.assertEqual(len(body["logs"]), 2)


class _DiscardWriter:
    """A no-op AuditWriter so the audit event emission doesn't fail."""

    def append(self, **kwargs):
        return None

    def read_chain(self, chain_id):
        return iter(())

    def iter_chain_ids(self):
        return iter(())


if __name__ == "__main__":
    unittest.main()
