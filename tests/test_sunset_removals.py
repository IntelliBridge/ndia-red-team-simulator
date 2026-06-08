"""v0.5 sunset removals stay gone.

Two long-deprecated surfaces were dropped:

  - ``GET /v1/findings/by-scanner-id`` (the pre-Phase-4 finding URL shape;
    the same content is reachable via ``GET /v1/findings?run=`` and
    ``GET /v1/findings/{uuid}``).
  - the legacy ``?token=`` query-parameter WebSocket auth fallback.

This suite asserts both are unreachable. The findings probe runs against
a real sqlite-backed session so the request reaches the router: with the
dedicated handler gone, ``/by-scanner-id`` falls through to the
``/{finding_id}`` lookup, which 404s on the missing id (rather than being
served by the deprecated route).
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

from aegis.api.app import create_app
from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.settings import APISettings


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(type_, compiler, **kw):  # noqa: ARG001
        return "TEXT"


def _build_client():
    _patch_jsonb_for_sqlite()
    from aegis.db.models import Base

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
    Session = sessionmaker(bind=engine, future=True)

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        finally:
            sess.close()

    app = create_app(APISettings(
        env="dev",
        auth_mode="dev",
        cors_origins=["http://localhost:3000"],
    ))
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        sub="dev:admin@test", email="admin@test",
        project_memberships={"default": "admin"},
    )
    client = TestClient(app, raise_server_exceptions=False)
    return client, session_cm


class SunsetRemovalsTest(unittest.TestCase):
    def test_findings_by_scanner_id_is_gone(self) -> None:
        client, session_cm = _build_client()
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings/by-scanner-id",
                              params={"run": "run-a", "scanner_id": "vuln-0001"})
        self.assertEqual(resp.status_code, 404)

    def test_ws_legacy_query_param_token_is_rejected(self) -> None:
        from starlette.websockets import WebSocketDisconnect

        client, _ = _build_client()
        with self.assertRaises(WebSocketDisconnect) as cm:
            with client.websocket_connect(
                    "/v1/runs/run-a/events?token=dev:admin@test") as ws:
                ws.receive_json()
        self.assertEqual(cm.exception.code, 1008)


if __name__ == "__main__":
    unittest.main()
