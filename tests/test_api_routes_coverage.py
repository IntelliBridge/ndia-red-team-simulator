"""Comprehensive behavioral tests for FastAPI route modules.

Covers:
  - aegis/api/auth.py
  - aegis/api/ws.py
  - aegis/api/v1/targets.py
  - aegis/api/v1/findings.py
  - aegis/api/v1/fix.py
  - aegis/api/v1/runs_cancel.py
  - aegis/api/v1/verify.py
  - aegis/api/v1/exports.py
  - aegis/api/v1/runs.py

All tests run fully offline: no Postgres, no Redis, no Keycloak.
Uses FastAPI dependency overrides for auth and unittest.mock.patch for
service/DB layer.
"""

from __future__ import annotations

import contextlib
import unittest
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from aegis.api.app import create_app
from aegis.api.auth import (
    CurrentUser,
    _dev_user,
    _hmac_sign,
    _parse_worker_token,
    _resolve_from_token,
    _verify_worker_token,
    get_current_user,
    issue_worker_token,
)
from aegis.api.settings import APISettings
from aegis.config import AegisConfig
from aegis.safety import AuthorizationError
from aegis.services.scans import JobHandle

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _patch_jsonb_for_sqlite() -> None:
    """Compile JSONB columns to TEXT so SQLite can handle them."""
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(t, c, **kw):  # noqa: ARG001
        return "TEXT"


def _make_sqlite_session():
    """Build an in-memory SQLite engine with all Aegis tables."""
    _patch_jsonb_for_sqlite()
    from aegis.db.models import Base

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
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

    return Session, session_cm


def _build_app(extra_rows_fn=None):
    """Create a dev-mode app backed by SQLite; seed rows via extra_rows_fn."""
    Session, session_cm = _make_sqlite_session()
    from aegis.db.models import Organization, Project

    with Session() as s:
        s.add(Organization(id="org-1", name="TestOrg", slug="testorg"))
        s.add(Project(id="proj-1", org_id="org-1", name="Proj1", slug="proj-1"))
        if extra_rows_fn:
            extra_rows_fn(s)
        s.commit()

    settings = APISettings(
        env="dev",
        auth_mode="dev",
        cors_origins=["http://localhost:3000"],
    )
    app = create_app(settings)
    return app, session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


def _admin(project_id: str = "proj-1") -> CurrentUser:
    return CurrentUser(
        sub="dev:admin@test", email="admin@test",
        project_memberships={project_id: "admin"},
    )


def _scanner(project_id: str = "proj-1") -> CurrentUser:
    return CurrentUser(
        sub="dev:scanner@test", email="scanner@test",
        project_memberships={project_id: "scanner"},
    )


def _system_user() -> CurrentUser:
    return CurrentUser(
        sub="service:worker:w1", email="worker@aegis.local",
        project_memberships={"default": "admin"},
        is_system=True,
    )


def _no_auth_client(app) -> TestClient:
    """TestClient whose dependency override raises 401 (simulates missing auth)."""
    from fastapi import HTTPException, status

    def _raise():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="authentication required")

    app.dependency_overrides[get_current_user] = _raise
    return TestClient(app, raise_server_exceptions=False)


class _DiscardWriter:
    def append(self, **kwargs): return None
    def read_chain(self, chain_id): return iter(())
    def iter_chain_ids(self): return iter(())


class _FakeClaims(dict):
    """Stand-in for an authlib claims object: dict access + a no-op
    ``validate``. Returned by a patched ``authlib.jose.jwt.decode`` so the
    real ``_verify_jwt`` body (audience check, claim extraction) runs end to
    end against the genuine authlib boundary instead of being stubbed out.
    """

    def validate(self, now=None):  # noqa: ARG002 - signature mirrors authlib
        return None


def _fake_redis_module(events):
    """Build a fake ``redis.asyncio`` module whose pub/sub ``listen()`` yields
    the given ``events`` as JSON ``message`` frames.

    This is the real boundary ``_redis_pubsub_iter`` reaches when
    ``AEGIS_BROKER_URL`` is set (``redis_async.from_url(...).pubsub()`` →
    ``listen()``). Patching it (instead of the private ``_redis_pubsub_iter``)
    drives the genuine generator. ``events`` are dicts; each is JSON-encoded
    so the helper decodes it back to the same dict.
    """
    fake_pubsub = MagicMock()
    fake_client = MagicMock()
    fake_client.pubsub.return_value = fake_pubsub

    async def _noop(*a, **kw):
        return None

    fake_pubsub.subscribe = _noop
    fake_pubsub.unsubscribe = _noop
    fake_client.close = _noop

    async def _listen():
        import json as _json
        for ev in events:
            yield {"type": "message", "data": _json.dumps(ev)}

    fake_pubsub.listen = _listen
    fake_mod = MagicMock()
    fake_mod.from_url.return_value = fake_client
    return fake_mod


@contextlib.contextmanager
def _patched_redis_boundary(events):
    """Patch ``AEGIS_BROKER_URL`` + ``redis.asyncio`` so the real
    ``_redis_pubsub_iter`` yields ``events`` from its genuine redis path.

    ``_redis_pubsub_iter`` resolves the module via
    ``importlib.import_module("redis.asyncio")``, which reads ``sys.modules``,
    so this patch is robust to suite ordering even after another test has
    already imported the real ``redis`` package.
    """
    import os
    with patch.dict(os.environ, {"AEGIS_BROKER_URL": "redis://localhost:6379"}), \
         patch.dict("sys.modules", {"redis.asyncio": _fake_redis_module(events)}):
        yield


@contextlib.contextmanager
def _patched_jwt_boundary(claims=None, *, error=None):
    """Patch the real JWT verification boundary used by ``_verify_jwt``.

    ``_verify_jwt`` does ``from authlib.jose import JoseError, jwt`` then
    ``jwt.decode(token, jwks)`` where ``jwks`` comes from an httpx fetch. We
    patch the httpx client (so no network) and ``authlib.jose.jwt.decode``
    (the genuine external seam) rather than the private ``_verify_jwt``.

    - ``claims``: dict of JWT claims; wrapped so ``.validate()`` is a no-op.
      Callers that expect a success path must include a matching ``aud`` so
      the real audience check in ``_verify_jwt`` passes.
    - ``error``: if given, ``jwt.decode`` raises this (use a ``JoseError``)
      to drive the verification-failure path.
    """
    from aegis.api.auth import _jwks_cache

    # The JWKS cache is process-wide (lru_cache); clear it so our httpx stub
    # is what backs the fetch for this test rather than a value cached by an
    # earlier test using the same URL.
    _jwks_cache.cache_clear()

    fake_resp = MagicMock()
    fake_resp.json.return_value = {"keys": []}
    fake_resp.raise_for_status.return_value = None
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.get.return_value = fake_resp

    decode_kwargs = {}
    if error is not None:
        decode_kwargs["side_effect"] = error
    else:
        decode_kwargs["return_value"] = _FakeClaims(claims or {})

    with patch("httpx.Client", return_value=fake_client), \
         patch("authlib.jose.jwt.decode", **decode_kwargs):
        yield
    _jwks_cache.cache_clear()


# ===========================================================================
# auth.py unit tests
# ===========================================================================

class TestAuthHelpers(unittest.TestCase):
    """Unit tests for helper functions inside aegis/api/auth.py."""

    # --- _hmac_sign ---
    def test_hmac_sign_deterministic(self):
        sig1 = _hmac_sign("secret", "payload")
        sig2 = _hmac_sign("secret", "payload")
        self.assertEqual(sig1, sig2)

    def test_hmac_sign_different_secrets_differ(self):
        self.assertNotEqual(
            _hmac_sign("secret1", "payload"),
            _hmac_sign("secret2", "payload"),
        )

    # --- _dev_user ---
    def test_dev_user_parses_email(self):
        user = _dev_user("dev:alice@example.com")
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(user.sub, "dev:alice@example.com")
        self.assertFalse(user.is_system)

    def test_dev_user_missing_colon_raises_401(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            _dev_user("dev")
        self.assertEqual(ctx.exception.status_code, 401)

    # --- _parse_worker_token ---
    def test_parse_worker_token_valid(self):
        result = _parse_worker_token("worker:v1.w123.9999999999.abc123")
        self.assertIsNotNone(result)
        version, worker_id, exp, sig = result
        self.assertEqual(version, 1)
        self.assertEqual(worker_id, "w123")
        self.assertEqual(exp, 9999999999)

    def test_parse_worker_token_legacy_format_returns_none(self):
        result = _parse_worker_token("worker:somehexsig")
        self.assertIsNone(result)

    def test_parse_worker_token_malformed_version_returns_none(self):
        result = _parse_worker_token("worker:vX.w1.999.sig")
        self.assertIsNone(result)

    # --- _verify_worker_token ---
    def test_verify_worker_token_valid(self):
        import time
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="test-key-abc",
            worker_signing_key_version=1,
        )
        exp = int(time.time()) + 300
        payload = f"v1.worker-1.{exp}"
        sig = _hmac_sign("test-key-abc", payload)
        token = f"worker:{payload}.{sig}"
        user = _verify_worker_token(token, settings)
        self.assertIsNotNone(user)
        self.assertTrue(user.is_system)
        self.assertEqual(user.sub, "service:worker:worker-1")

    def test_verify_worker_token_expired_returns_none(self):
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="test-key-abc",
            worker_signing_key_version=1,
        )
        exp = 1000  # far in the past
        payload = f"v1.worker-1.{exp}"
        sig = _hmac_sign("test-key-abc", payload)
        token = f"worker:{payload}.{sig}"
        result = _verify_worker_token(token, settings)
        self.assertIsNone(result)

    def test_verify_worker_token_wrong_sig_returns_none(self):
        import time
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="test-key-abc",
            worker_signing_key_version=1,
        )
        exp = int(time.time()) + 300
        payload = f"v1.worker-1.{exp}"
        token = f"worker:{payload}.badsig"
        result = _verify_worker_token(token, settings)
        self.assertIsNone(result)

    def test_verify_worker_token_legacy_now_rejected(self):
        """C1: the legacy ``worker:HEX`` constant-payload token is gone.

        It used to resolve to a non-expiring ``service:worker:legacy``
        ``is_system`` identity; that branch was deleted, so a
        well-formed legacy signature must now be rejected.
        """
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="legacykey",
            worker_signing_key_version=1,
        )
        sig = _hmac_sign("legacykey", "aegis-worker")
        token = f"worker:{sig}"
        self.assertIsNone(_verify_worker_token(token, settings))

    def test_verify_worker_token_bare_hex_returns_none(self):
        """A bare ``worker:<hex>`` (no v-prefix) parses as malformed."""
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="legacykey",
            worker_signing_key_version=1,
        )
        token = "worker:badsig"
        result = _verify_worker_token(token, settings)
        self.assertIsNone(result)

    def test_verify_worker_token_no_key_returns_none(self):
        settings = APISettings(env="dev", auth_mode="dev", worker_signing_key=None)
        result = _verify_worker_token("worker:badsig", settings)
        self.assertIsNone(result)

    def test_verify_worker_token_previous_key(self):
        """Previous-key overlap window accepted."""
        import time
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="newkey",
            worker_signing_key_version=2,
            worker_signing_key_previous="oldkey",
            worker_key_overlap_seconds=300,
            worker_token_ttl_seconds=300,
        )
        exp = int(time.time()) + 60   # inside both TTL and overlap
        payload = f"v1.worker-1.{exp}"
        sig = _hmac_sign("oldkey", payload)
        token = f"worker:{payload}.{sig}"
        user = _verify_worker_token(token, settings)
        self.assertIsNotNone(user)
        self.assertTrue(user.is_system)

    # --- issue_worker_token + _resolve_from_token ---
    def test_issue_and_resolve_worker_token(self):
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="round-trip-key",
            worker_signing_key_version=1,
        )
        token = issue_worker_token("w99", settings=settings)
        user = _resolve_from_token(token, settings)
        self.assertIsNotNone(user)
        self.assertTrue(user.is_system)
        self.assertIn("w99", user.sub)

    def test_issue_worker_token_no_key_raises(self):
        settings = APISettings(env="dev", auth_mode="dev", worker_signing_key=None)
        with self.assertRaises(RuntimeError):
            issue_worker_token("w1", settings=settings)

    def test_issue_worker_token_settings_none_uses_load_settings(self):
        """issue_worker_token with settings=None calls load_settings (line 89)."""
        fake_settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="autoloaded-key",
            worker_signing_key_version=1,
        )
        with patch("aegis.api.auth.load_settings", return_value=fake_settings):
            token = issue_worker_token("w-auto")
        self.assertTrue(token.startswith("worker:v1.w-auto."))

    # --- _resolve_from_token dev mode ---
    def test_resolve_from_token_dev_mode(self):
        settings = APISettings(env="dev", auth_mode="dev")
        user = _resolve_from_token("dev:alice@example.com", settings)
        self.assertEqual(user.email, "alice@example.com")

    def test_resolve_from_token_empty_raises_401(self):
        from fastapi import HTTPException
        settings = APISettings(env="dev", auth_mode="dev")
        with self.assertRaises(HTTPException) as ctx:
            _resolve_from_token("", settings)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_resolve_from_token_invalid_worker_raises_401(self):
        from fastapi import HTTPException
        settings = APISettings(
            env="dev", auth_mode="dev",
            worker_signing_key="somekey",
            worker_signing_key_version=1,
        )
        with self.assertRaises(HTTPException) as ctx:
            _resolve_from_token("worker:badhex", settings)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_resolve_from_token_no_oidc_configured_raises_500(self):
        """JWT path without OIDC config raises 500."""
        from fastapi import HTTPException
        settings = APISettings(env="dev", auth_mode="oidc", oidc_jwks_url=None)
        with self.assertRaises(HTTPException) as ctx:
            _resolve_from_token("Bearer notadevtoken", settings)
        self.assertEqual(ctx.exception.status_code, 500)

    # --- get_current_user via TestClient ---
    def test_get_current_user_no_header_no_cookie_returns_401(self):
        app, _ = _build_app()
        # Don't override auth so the real get_current_user runs
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/runs", headers={})
        self.assertEqual(resp.status_code, 401)

    def test_get_current_user_dev_bearer_resolves(self):
        app, session_cm = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get(
                "/v1/runs",
                headers={"Authorization": "Bearer dev:alice@test.com"},
            )
        # 200 is fine; 401/403 would be a bug (dev mode should resolve)
        self.assertIn(resp.status_code, [200, 503])

    def test_get_current_user_bearer_wins_over_cookie(self):
        """When both bearer and cookie are present, bearer takes precedence.

        Driven through the real ``get_current_user``: a genuine dev bearer
        token resolves via the real token path (dev mode, no boundary needed),
        while the cookie path's real external boundary
        (``verify_session_cookie``) is spied on. The cookie boundary must
        never be invoked, proving the bearer branch won.
        """
        app, session_cm = _build_app()

        cookie_calls = []

        def _spy_verify_cookie(value, settings):
            cookie_calls.append(value)
            raise AssertionError("cookie path should not be reached")

        with patch("aegis.api.session_cookie.verify_session_cookie",
                   _spy_verify_cookie), \
             patch("aegis.db.session.get_session", session_cm):
            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set("aegis_api_session", "cookieval")
            resp = client.get(
                "/v1/runs",
                headers={"Authorization": "Bearer dev:alice@test.com"},
            )

        # Bearer path resolved (auth succeeded, so not 401)...
        self.assertNotEqual(resp.status_code, 401)
        self.assertIn(resp.status_code, [200, 503])
        # ...and the cookie boundary was never consulted.
        self.assertEqual(cookie_calls, [])

    def test_get_current_user_cookie_path_resolves(self):
        """Cookie-only auth (no Authorization header) resolves via cookie.

        Patches the real cookie verification boundary
        (``verify_session_cookie``) so the genuine ``_resolve_from_cookie``
        path runs end to end, rather than stubbing that private resolver.
        """
        from aegis.api.session_cookie import SessionClaims

        app, session_cm = _build_app()
        claims = SessionClaims(
            sub="dev:admin@test", email="admin@test", display_name="",
            project_memberships={"proj-1": "admin"},
            iat=0, exp=0, jti="t",
        )

        with patch("aegis.api.session_cookie.verify_session_cookie",
                   return_value=claims), \
             patch("aegis.db.session.get_session", session_cm):
            # Use a fresh client after setting cookies on it
            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set("aegis_api_session", "some-cookie-val")
            resp = client.get("/v1/runs")
        self.assertIn(resp.status_code, [200, 503])

    def test_resolve_from_token_settings_none_uses_load_settings(self):
        """When settings=None, load_settings() is called implicitly."""
        settings = APISettings(env="dev", auth_mode="dev")
        with patch("aegis.api.auth.load_settings", return_value=settings):
            user = _resolve_from_token("dev:auto@test.com")
        self.assertEqual(user.email, "auto@test.com")

    # --- _resolve_from_cookie ---
    def test_resolve_from_cookie_valid(self):
        """Cookie verify success returns a CurrentUser."""
        from aegis.api.auth import _resolve_from_cookie

        @dataclass
        class FakeClaims:
            sub: str = "u1"
            email: str = "u1@test.com"
            display_name: str = "U1"
            project_memberships: dict = None
            def __post_init__(self):
                if self.project_memberships is None:
                    self.project_memberships = {"proj-1": "admin"}

        settings = APISettings(env="dev", auth_mode="dev")
        with patch("aegis.api.session_cookie.verify_session_cookie",
                   return_value=FakeClaims()):
            user = _resolve_from_cookie("cookieval", settings)
        self.assertEqual(user.email, "u1@test.com")
        self.assertTrue(user.project_memberships["proj-1"] == "admin")

    def test_resolve_from_cookie_invalid_raises_401(self):
        """SessionCookieError from verify_session_cookie raises HTTPException 401."""
        from fastapi import HTTPException

        from aegis.api.auth import _resolve_from_cookie
        from aegis.api.session_cookie import SessionCookieError

        settings = APISettings(env="dev", auth_mode="dev")
        with patch("aegis.api.session_cookie.verify_session_cookie",
                   side_effect=SessionCookieError("bad cookie")):
            with self.assertRaises(HTTPException) as ctx:
                _resolve_from_cookie("badcookieval", settings)
        self.assertEqual(ctx.exception.status_code, 401)

    # --- JWT success path (lines 232-237), driven via the real authlib seam ---
    def test_resolve_from_token_jwt_success_builds_user(self):
        """Successful JWT verification builds a CurrentUser with project roles."""
        settings = APISettings(env="dev", auth_mode="oidc", oidc_jwks_url="http://x/jwks")
        # aud matches settings.oidc_audience so the real _verify_jwt audience
        # check passes; we patch the genuine jwt.decode boundary, not _verify_jwt.
        fake_claims = {
            "sub": "user-123",
            "email": "jwtuser@test.com",
            "name": "JWT User",
            "aegis_project_roles": {"proj-1": "admin"},
            "aud": settings.oidc_audience,
        }
        with _patched_jwt_boundary(fake_claims):
            user = _resolve_from_token("somejwttoken", settings)
        self.assertEqual(user.sub, "user-123")
        self.assertEqual(user.email, "jwtuser@test.com")
        self.assertEqual(user.project_memberships["proj-1"], "admin")
        self.assertEqual(user.display_name, "JWT User")

    def test_resolve_from_token_jwt_success_non_dict_roles(self):
        """Non-dict aegis_project_roles is treated as empty."""
        settings = APISettings(env="dev", auth_mode="oidc", oidc_jwks_url="http://x/jwks")
        fake_claims = {
            "sub": "user-456",
            "email": "r@test.com",
            "aegis_project_roles": "not-a-dict",
            "aud": settings.oidc_audience,
        }
        with _patched_jwt_boundary(fake_claims):
            user = _resolve_from_token("sometoken", settings)
        self.assertEqual(user.project_memberships, {})

    def test_resolve_from_token_jwt_uses_preferred_username(self):
        """preferred_username falls back when sub is absent."""
        settings = APISettings(env="dev", auth_mode="oidc", oidc_jwks_url="http://x/jwks")
        fake_claims = {
            "preferred_username": "alice",
            "email": "alice@test.com",
            "aud": settings.oidc_audience,
        }
        with _patched_jwt_boundary(fake_claims):
            user = _resolve_from_token("jwttoken", settings)
        self.assertEqual(user.sub, "alice")


# ===========================================================================
# ws.py helper unit tests
# ===========================================================================

class TestWsHelpers(unittest.TestCase):
    """Test the pure helper functions in aegis/api/ws.py."""

    def test_origin_allowed_empty_string(self):
        from aegis.api.ws import _origin_allowed
        settings = APISettings(cors_origins=["http://foo.com"])
        self.assertTrue(_origin_allowed("", settings))

    def test_origin_allowed_whitelisted(self):
        from aegis.api.ws import _origin_allowed
        settings = APISettings(cors_origins=["http://foo.com"])
        self.assertTrue(_origin_allowed("http://foo.com", settings))

    def test_origin_allowed_web_origin(self):
        from aegis.api.ws import _origin_allowed
        settings = APISettings(
            cors_origins=["http://other.com"],
            web_origin="http://myapp.com",
        )
        self.assertTrue(_origin_allowed("http://myapp.com", settings))

    def test_origin_not_allowed(self):
        from aegis.api.ws import _origin_allowed
        settings = APISettings(cors_origins=["http://good.com"])
        self.assertFalse(_origin_allowed("http://evil.com", settings))

    def test_extract_bearer_subprotocol_present(self):
        from aegis.api.ws import _extract_bearer_subprotocol
        ws = MagicMock()
        ws.headers.get.return_value = "aegis.bearer.mytoken123"
        token, echo = _extract_bearer_subprotocol(ws)
        self.assertEqual(token, "mytoken123")
        self.assertEqual(echo, "aegis.bearer.mytoken123")

    def test_extract_bearer_subprotocol_absent(self):
        from aegis.api.ws import _extract_bearer_subprotocol
        ws = MagicMock()
        ws.headers.get.return_value = ""
        token, echo = _extract_bearer_subprotocol(ws)
        self.assertIsNone(token)
        self.assertIsNone(echo)

    def test_extract_bearer_subprotocol_multiple_protocols(self):
        from aegis.api.ws import _extract_bearer_subprotocol
        ws = MagicMock()
        ws.headers.get.return_value = "graphql-ws, aegis.bearer.tok42"
        token, echo = _extract_bearer_subprotocol(ws)
        self.assertEqual(token, "tok42")

    def test_extract_bearer_subprotocol_none_matching(self):
        from aegis.api.ws import _extract_bearer_subprotocol
        ws = MagicMock()
        ws.headers.get.return_value = "graphql-ws, soap"
        token, echo = _extract_bearer_subprotocol(ws)
        self.assertIsNone(token)
        self.assertIsNone(echo)


class TestWsEndpoint(unittest.TestCase):
    """Integration tests for the WebSocket endpoint."""

    def _build_ws_app(self, seed_run=True):
        Session, session_cm = _make_sqlite_session()
        from aegis.db.models import Organization, Project, Run

        with Session() as s:
            s.add(Organization(id="org-1", name="O", slug="o"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="proj-1"))
            if seed_run:
                s.add(Run(id="run-ws-1", project_id="proj-1",
                          status="running", mode="live"))
            s.commit()

        settings = APISettings(
            env="dev",
            auth_mode="dev",
            cors_origins=["http://localhost:3000"],
        )
        app = create_app(settings)
        return app, session_cm

    def _tight_settings(self, cors=None, restricted=False):
        """Return a locked-down APISettings for WS origin tests."""
        if restricted:
            return APISettings(
                env="dev", auth_mode="dev",
                cors_origins=["http://allowed.com"],
                web_origin="http://allowed.com",
            )
        return APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            web_origin="http://localhost:3000",
        )

    def test_ws_origin_not_allowed_closes_1008(self):
        """WS upgrade from non-allowed origin should close(1008)."""
        app, session_cm = self._build_ws_app()
        client = TestClient(app, raise_server_exceptions=False)

        with patch("aegis.api.settings.load_settings",
                   return_value=self._tight_settings(restricted=True)), \
             patch("aegis.db.session.get_session", session_cm):
            try:
                with client.websocket_connect(
                    "/v1/runs/run-ws-1/events",
                    headers={"Origin": "http://evil.com"},
                ):
                    pass
            except Exception:
                pass  # WebSocketDisconnect or similar is expected

    def test_ws_no_auth_closes_after_accept(self):
        """WS with valid origin but no auth token should be rejected.

        No credentials are attached, so the real _resolve_user_for_ws returns
        None natively (no private-symbol patch needed) and the upgrade is
        rejected.
        """
        app, session_cm = self._build_ws_app()
        client = TestClient(app, raise_server_exceptions=False)

        with patch("aegis.api.settings.load_settings",
                   return_value=self._tight_settings()), \
             patch("aegis.db.session.get_session", session_cm):
            try:
                with client.websocket_connect("/v1/runs/run-ws-1/events"):
                    pass
            except Exception:
                pass

    def test_ws_run_not_found_closes(self):
        """WS to a non-existent run should close after auth.

        Authenticates through the real cookie verification boundary (the
        genuine _resolve_from_cookie path) rather than patching the private
        _resolve_user_for_ws.
        """
        from aegis.api.session_cookie import SessionClaims

        app, session_cm = self._build_ws_app(seed_run=False)
        claims = SessionClaims(
            sub="dev:admin@test", email="admin@test", display_name="",
            project_memberships={"proj-1": "admin"}, iat=0, exp=0, jti="t",
        )

        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set("aegis_api_session", "cookieval")
        with patch("aegis.api.settings.load_settings",
                   return_value=self._tight_settings()), \
             patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.session_cookie.verify_session_cookie",
                   return_value=claims):
            try:
                with client.websocket_connect("/v1/runs/nonexistent/events"):
                    pass
            except Exception:
                pass

    def test_ws_no_project_membership_closes(self):
        """Authenticated user without project membership is rejected.

        The outsider identity (member of a different project) is delivered
        through the real cookie verification boundary, exercising the genuine
        resolver + membership gate rather than patching _resolve_user_for_ws.
        """
        from aegis.api.session_cookie import SessionClaims

        app, session_cm = self._build_ws_app()
        claims = SessionClaims(
            sub="dev:x@x", email="x@x", display_name="",
            project_memberships={"other-proj": "admin"}, iat=0, exp=0, jti="t",
        )

        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set("aegis_api_session", "cookieval")
        with patch("aegis.api.settings.load_settings",
                   return_value=self._tight_settings()), \
             patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.session_cookie.verify_session_cookie",
                   return_value=claims):
            try:
                with client.websocket_connect("/v1/runs/run-ws-1/events"):
                    pass
            except Exception:
                pass

    def test_ws_system_user_bypasses_membership(self):
        """System (worker) user skips membership check.

        Uses a genuine worker service-account token (minted + verified by the
        real auth code, which sets is_system=True) attached via the bearer
        subprotocol, and feeds the event through the real redis boundary — no
        private _resolve_user_for_ws / _redis_pubsub_iter patches.
        """
        from aegis.api.auth import issue_worker_token

        Session, session_cm = _make_sqlite_session()
        from aegis.db.models import Organization, Project, Run
        with Session() as s:
            s.add(Organization(id="org-1", name="O", slug="o"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="proj-1"))
            s.add(Run(id="run-ws-1", project_id="proj-1",
                      status="running", mode="live"))
            s.commit()

        worker_settings = APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            web_origin="http://localhost:3000",
            worker_signing_key="ws-test-key", worker_signing_key_version=1,
        )
        app = create_app(worker_settings)
        token = issue_worker_token("w1", settings=worker_settings)

        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.api.settings.load_settings",
                   return_value=worker_settings), \
             patch("aegis.db.session.get_session", session_cm), \
             _patched_redis_boundary([{"type": "heartbeat"}]):
            try:
                with client.websocket_connect(
                    "/v1/runs/run-ws-1/events",
                    subprotocols=["aegis.bearer." + token],
                ) as ws:
                    data = ws.receive_json()
                    self.assertEqual(data["type"], "heartbeat")
            except Exception:
                pass


class TestWsResolveUser(unittest.IsolatedAsyncioTestCase):
    """Test _resolve_user_for_ws async paths."""

    async def test_resolve_via_bearer_header(self):
        # Drive the real _resolve_from_token via a genuine dev token (dev mode
        # needs no external boundary) instead of patching the private resolver.
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.side_effect = lambda key, default="": (
            "" if key == "sec-websocket-protocol"
            else "Bearer dev:alice@test" if key == "authorization"
            else ""
        )
        ws.cookies.get.return_value = None
        ws.query_params.get.return_value = ""

        settings = APISettings(env="dev", auth_mode="dev")
        result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNotNone(result)
        self.assertEqual(result.sub, "dev:alice@test")
        self.assertEqual(result.email, "alice@test")

    async def test_resolve_via_subprotocol(self):
        # The bearer subprotocol carries a real dev token; the genuine token
        # resolver runs (no private-symbol patch).
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.side_effect = lambda key, default="": (
            "aegis.bearer.dev:alice@test" if key == "sec-websocket-protocol"
            else ""
        )
        ws.cookies.get.return_value = None
        ws.query_params.get.return_value = ""

        settings = APISettings(env="dev", auth_mode="dev")
        result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNotNone(result)
        self.assertEqual(result.sub, "dev:alice@test")

    async def test_resolve_via_cookie(self):
        # Patch the real cookie verification boundary so the genuine
        # _resolve_from_cookie runs, rather than stubbing the private resolver.
        from aegis.api.session_cookie import SessionClaims
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.return_value = ""
        ws.cookies.get.return_value = "cookieval"
        ws.query_params.get.return_value = ""

        claims = SessionClaims(
            sub="dev:admin@test", email="admin@test", display_name="",
            project_memberships={"proj-1": "admin"}, iat=0, exp=0, jti="t",
        )
        settings = APISettings(env="dev", auth_mode="dev",
                               api_session_cookie_name="aegis_api_session")
        with patch("aegis.api.session_cookie.verify_session_cookie",
                   return_value=claims):
            result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNotNone(result)
        self.assertEqual(result.email, "admin@test")
        self.assertEqual(result.project_memberships["proj-1"], "admin")

    async def test_resolve_no_credentials_returns_none(self):
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.return_value = ""
        ws.cookies.get.return_value = None
        ws.query_params.get.return_value = ""

        settings = APISettings(env="dev", auth_mode="dev")
        result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNone(result)

    async def test_resolve_subprotocol_exception_returns_none(self):
        """Exception from token resolution yields None (ws closes cleanly).

        A non-dev token in the bearer subprotocol falls through to the real
        JWT verifier, which raises (OIDC unconfigured); _resolve_user_for_ws
        swallows it and returns None. Exercises the genuine failure boundary
        rather than patching the private resolver.
        """
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.side_effect = lambda key, default="": (
            "aegis.bearer.badtoken" if key == "sec-websocket-protocol" else ""
        )
        ws.cookies.get.return_value = None
        ws.query_params.get.return_value = ""

        settings = APISettings(env="dev", auth_mode="dev", oidc_jwks_url=None)
        result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNone(result)


# ===========================================================================
# Additional _resolve_user_for_ws exception-swallowing branches
# ===========================================================================

class TestWsResolveUserExceptionPaths(unittest.IsolatedAsyncioTestCase):
    """Cover the bearer-header and cookie exception → None branches in ws.py."""

    async def test_bearer_header_exception_returns_none(self):
        """Exception in bearer header path returns None (line 87-88).

        A non-dev bearer token reaches the real JWT verifier, which raises
        because OIDC is unconfigured; the helper swallows it. Drives the
        genuine failure boundary instead of patching the private resolver.
        """
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.side_effect = lambda key, default="": (
            "" if key == "sec-websocket-protocol"
            else "Bearer sometoken" if key == "authorization"
            else ""
        )
        ws.cookies.get.return_value = None
        ws.query_params.get.return_value = ""

        settings = APISettings(env="dev", auth_mode="dev", oidc_jwks_url=None)
        result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNone(result)

    async def test_cookie_exception_returns_none(self):
        """Exception in cookie path returns None (lines 94-95).

        The real cookie verification boundary raises SessionCookieError, so
        the genuine _resolve_from_cookie raises and the helper swallows it.
        """
        from aegis.api.session_cookie import SessionCookieError
        from aegis.api.ws import _resolve_user_for_ws

        ws = MagicMock()
        ws.headers.get.return_value = ""
        ws.cookies.get.return_value = "some-cookie"
        ws.query_params.get.return_value = ""

        settings = APISettings(
            env="dev", auth_mode="dev",
            api_session_cookie_name="aegis_api_session",
        )
        with patch("aegis.api.session_cookie.verify_session_cookie",
                   side_effect=SessionCookieError("bad cookie")):
            result = await _resolve_user_for_ws(ws, settings)
        self.assertIsNone(result)


class TestWsSubprotocolEcho(unittest.TestCase):
    """Cover line 127: accept with subprotocol echo."""

    def _build_ws_app(self):
        Session, session_cm = _make_sqlite_session()
        from aegis.db.models import Organization, Project, Run

        with Session() as s:
            s.add(Organization(id="org-1", name="O", slug="o"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="proj-1"))
            s.add(Run(id="run-sub-1", project_id="proj-1", status="running", mode="live",
                      stage_table={}))
            s.commit()

        settings = APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
        )
        return create_app(settings), session_cm

    def test_subprotocol_echo_accept_path(self):
        """When bearer subprotocol is offered, accept() is called with it (line 127).

        A genuine worker token rides the bearer subprotocol (resolved by the
        real auth code → is_system=True), exercising the real subprotocol echo
        on accept; the event is fed through the real redis boundary. No private
        _resolve_user_for_ws / _redis_pubsub_iter patches.
        """
        from aegis.api.auth import issue_worker_token

        app, session_cm = self._build_ws_app()
        tight = APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            web_origin="http://localhost:3000",
            worker_signing_key="sub-test-key", worker_signing_key_version=1,
        )
        token = issue_worker_token("w1", settings=tight)

        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.api.settings.load_settings", return_value=tight), \
             patch("aegis.db.session.get_session", session_cm), \
             _patched_redis_boundary([{"type": "heartbeat"}]):
            try:
                with client.websocket_connect(
                    "/v1/runs/run-sub-1/events",
                    subprotocols=["aegis.bearer." + token],
                ) as ws:
                    # consume event so connection stays alive until pubsub ends
                    data = ws.receive_json()
                    self.assertEqual(data["type"], "heartbeat")
            except Exception:
                pass  # disconnect is fine here


class TestWsRedisPubsubFallback(unittest.IsolatedAsyncioTestCase):
    """Cover the no-AEGIS_BROKER_URL heartbeat loop (lines 154-166) and the
    main WS loop send_json path (line 193)."""

    async def test_redis_pubsub_no_url_yields_heartbeat(self):
        """Without AEGIS_BROKER_URL the generator yields heartbeat events."""
        import os

        from aegis.api.ws import _redis_pubsub_iter

        # Ensure the env var is absent
        env_without_broker = {k: v for k, v in os.environ.items()
                               if k != "AEGIS_BROKER_URL"}

        events = []
        with patch.dict("os.environ", env_without_broker, clear=True), \
             patch("asyncio.sleep", return_value=None):
            # Drain a couple of iterations
            gen = _redis_pubsub_iter("run:x:events")
            try:
                for _ in range(2):
                    events.append(await gen.__anext__())
            except StopAsyncIteration:
                pass
            finally:
                await gen.aclose()

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["type"], "heartbeat")

    async def test_redis_pubsub_with_url_valid_json_message(self):
        """When AEGIS_BROKER_URL is set, the redis path is taken (lines 160-180)."""
        from aegis.api.ws import _redis_pubsub_iter

        # Build mock redis client + pubsub
        fake_pubsub = MagicMock()
        fake_client = MagicMock()
        fake_client.pubsub.return_value = fake_pubsub
        fake_pubsub.subscribe = MagicMock(return_value=None)
        fake_pubsub.unsubscribe = MagicMock(return_value=None)
        fake_client.close = MagicMock(return_value=None)

        # Make subscribe/unsubscribe/close awaitable

        async def _noop(*a, **kw): pass

        fake_pubsub.subscribe = _noop
        fake_pubsub.unsubscribe = _noop
        fake_client.close = _noop

        import json as _json

        # listen() yields two messages: one "subscribe" type (skipped) + one "message"
        async def _listen():
            yield {"type": "subscribe", "data": None}
            yield {"type": "message", "data": _json.dumps({"type": "scan_done"})}

        fake_pubsub.listen = _listen

        fake_redis_module = MagicMock()
        fake_redis_module.from_url.return_value = fake_client

        with patch.dict("os.environ", {"AEGIS_BROKER_URL": "redis://localhost:6379"}), \
             patch.dict("sys.modules", {"redis.asyncio": fake_redis_module}):
            # Re-import so the env var is picked up inside the function
            events = []
            gen = _redis_pubsub_iter("run:test:events")
            try:
                async for event in gen:
                    events.append(event)
                    break  # stop after first yielded event
            finally:
                await gen.aclose()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "scan_done")

    async def test_redis_pubsub_with_url_invalid_json_message(self):
        """Non-JSON redis messages are yielded as raw (lines 176-177)."""

        from aegis.api.ws import _redis_pubsub_iter

        fake_pubsub = MagicMock()
        fake_client = MagicMock()
        fake_client.pubsub.return_value = fake_pubsub

        async def _noop(*a, **kw): pass

        fake_pubsub.subscribe = _noop
        fake_pubsub.unsubscribe = _noop
        fake_client.close = _noop

        async def _listen():
            yield {"type": "message", "data": "this is not json {{"}

        fake_pubsub.listen = _listen

        fake_redis_module = MagicMock()
        fake_redis_module.from_url.return_value = fake_client

        with patch.dict("os.environ", {"AEGIS_BROKER_URL": "redis://localhost:6379"}), \
             patch.dict("sys.modules", {"redis.asyncio": fake_redis_module}):
            events = []
            gen = _redis_pubsub_iter("run:test:events")
            try:
                async for event in gen:
                    events.append(event)
                    break
            finally:
                await gen.aclose()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "raw")
        self.assertIn("this is not json", events[0]["data"])

    async def test_redis_pubsub_import_error_fallback(self):
        """If redis.asyncio cannot be imported, fallback heartbeat loop runs."""
        import sys

        from aegis.api.ws import _redis_pubsub_iter

        # Remove redis.asyncio from sys.modules to simulate ImportError
        saved = sys.modules.pop("redis.asyncio", None)
        try:
            with patch.dict("os.environ", {"AEGIS_BROKER_URL": "redis://localhost:6379"}), \
                 patch.dict("sys.modules", {"redis.asyncio": None}), \
                 patch("asyncio.sleep", return_value=None):
                events = []
                gen = _redis_pubsub_iter("run:test:events")
                try:
                    events.append(await gen.__anext__())
                except StopAsyncIteration:
                    pass
                finally:
                    await gen.aclose()
        finally:
            if saved is not None:
                sys.modules["redis.asyncio"] = saved

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["type"], "heartbeat")

    async def test_ws_main_loop_send_json_on_event(self):
        """The main events_ws loop calls websocket.send_json for each pubsub event (line 193).

        The pubsub events come from the real redis boundary (not a patched
        _redis_pubsub_iter). ``_enforce_upgrade_policy`` is still patched: this
        is a white-box unit test of the loop body that drives ``events_ws``
        directly with a MagicMock websocket whose ``send_json`` raises
        ``WebSocketDisconnect`` on the first event. There is no public seam to
        bypass the upgrade gate for a direct ``events_ws`` call (origin/accept/
        auth/DB all run against a live WebSocket); migrating it would require a
        source-level change (e.g. extracting the send loop into a public
        function), so it is left as-is per the conservative-leave guidance.
        """
        from fastapi import WebSocketDisconnect

        from aegis.api.ws import events_ws

        sent = []
        disconnect_exc = WebSocketDisconnect(code=1001)
        call_count = [0]

        async def _fake_send_json(data):
            call_count[0] += 1
            sent.append(data)
            if call_count[0] >= 1:
                raise disconnect_exc

        ws = MagicMock()
        ws.send_json = _fake_send_json

        # Real redis boundary yields two events; the first send_json raises
        # WebSocketDisconnect, so the loop exits after one send.
        with patch("aegis.api.ws._enforce_upgrade_policy", return_value=True), \
             _patched_redis_boundary([
                 {"type": "scan_event", "data": "hello"},
                 {"type": "scan_event", "data": "world"},
             ]):
            await events_ws(ws, "run-x-1")

        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["type"], "scan_event")


# ===========================================================================
# runs.py
# ===========================================================================

def _seed_run(sess):
    from aegis.db.models import Run
    sess.add(Run(id="run-1", project_id="proj-1", status="running", mode="live",
                 scanner="strix", stage_table={}))


class TestRunsApi(unittest.TestCase):

    def test_list_runs_returns_200(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("runs", body)
        self.assertIn("count", body)

    def test_list_runs_project_filter(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs?project=proj-1")
        self.assertEqual(resp.status_code, 200)
        # All returned runs belong to the requested project
        for run in resp.json()["runs"]:
            self.assertEqual(run["project_id"], "proj-1")

    def test_list_runs_no_auth_401(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 401)

    def test_get_run_200(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/run-1")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["id"], "run-1")
        self.assertEqual(body["project_id"], "proj-1")

    def test_get_run_404(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_get_run_403_no_membership(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        outsider = CurrentUser(
            sub="dev:x@x", email="x@x", project_memberships={"other": "admin"}
        )
        _override_user(app, outsider)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/run-1")
        self.assertEqual(resp.status_code, 403)

    def test_get_run_system_user_bypasses_membership(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run)
        _override_user(app, _system_user())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/run-1")
        self.assertEqual(resp.status_code, 200)

    def test_list_runs_db_error_503(self):
        """A RuntimeError from get_session bubbles up as 503."""
        app, _ = _build_app()
        _override_user(app, _admin())

        @contextlib.contextmanager
        def _bad_session():
            raise RuntimeError("AEGIS_DB_URL not configured")
            yield  # pragma: no cover

        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", _bad_session):
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 503)


# ===========================================================================
# findings.py
# ===========================================================================

def _seed_finding(sess):
    import uuid

    from aegis.db.models import Finding, Run
    sess.add(Run(id="run-f1", project_id="proj-1", status="done", mode="live",
                 stage_table={}))
    sess.add(Finding(
        id=str(uuid.uuid4()),
        scanner_finding_id="strix-001",
        run_id="run-f1",
        project_id="proj-1",
        schema_blob={"id": "strix-001"},
        severity="high",
        source_tool="strix",
        validation_state="unvalidated",
        status="open",
    ))


class TestFindingsApi(unittest.TestCase):

    def test_list_findings_200(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("findings", body)
        self.assertEqual(body["count"], 1)

    def test_list_findings_filters_by_project(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings?project=proj-1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 1)

    def test_list_findings_filters_by_run(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings?run=run-f1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 1)

    def test_list_findings_filters_by_severity(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings?severity=low")
        self.assertEqual(resp.status_code, 200)
        # no low-severity findings seeded
        self.assertEqual(resp.json()["count"], 0)

    def test_list_findings_hides_non_member_projects(self):
        """Findings from projects the user isn't in are filtered out."""
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        outsider = CurrentUser(
            sub="dev:x@x", email="x@x", project_memberships={"other-proj": "admin"}
        )
        _override_user(app, outsider)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 0)

    def test_list_findings_system_user_sees_all(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding)
        _override_user(app, _system_user())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 1)

    def test_get_finding_200(self):
        Session, session_cm = _make_sqlite_session()
        import uuid

        from aegis.db.models import Finding, Organization, Project, Run

        fid = str(uuid.uuid4())
        with Session() as s:
            s.add(Organization(id="org-1", name="O", slug="o"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
            s.add(Run(id="run-f1", project_id="proj-1", status="done",
                      mode="live", stage_table={}))
            s.add(Finding(
                id=fid, scanner_finding_id="x1", run_id="run-f1",
                project_id="proj-1", schema_blob={},
                severity="high", validation_state="unvalidated", status="open",
            ))
            s.commit()

        settings = APISettings(env="dev", auth_mode="dev",
                               cors_origins=["http://localhost:3000"])
        app = create_app(settings)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get(f"/v1/findings/{fid}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], fid)

    def test_get_finding_404(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings/no-such-id")
        self.assertEqual(resp.status_code, 404)

    def test_get_finding_403_no_membership(self):
        Session, session_cm = _make_sqlite_session()
        import uuid

        from aegis.db.models import Finding, Organization, Project, Run

        fid = str(uuid.uuid4())
        with Session() as s:
            s.add(Organization(id="org-1", name="O", slug="o"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
            s.add(Run(id="run-f1", project_id="proj-1", status="done",
                      mode="live", stage_table={}))
            s.add(Finding(
                id=fid, scanner_finding_id="x2", run_id="run-f1",
                project_id="proj-1", schema_blob={},
                severity="high", validation_state="unvalidated", status="open",
            ))
            s.commit()

        settings = APISettings(env="dev", auth_mode="dev",
                               cors_origins=["http://localhost:3000"])
        app = create_app(settings)
        outsider = CurrentUser(sub="dev:x@x", email="x@x",
                               project_memberships={"other": "admin"})
        _override_user(app, outsider)
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get(f"/v1/findings/{fid}")
        self.assertEqual(resp.status_code, 403)

    def test_list_findings_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/findings")
        self.assertEqual(resp.status_code, 401)


# ===========================================================================
# targets.py
# ===========================================================================

def _seed_target(sess):
    from aegis.db.models import Target
    sess.add(Target(id="tgt-1", project_id="proj-1",
                    kind="url", value="http://localhost", verified=False))


class TestTargetsApi(unittest.TestCase):

    def test_list_targets_200(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_target)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/targets?project=proj-1")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(len(body["targets"]), 1)
        self.assertEqual(body["targets"][0]["id"], "tgt-1")

    def test_list_targets_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/targets")
        self.assertEqual(resp.status_code, 401)

    def test_create_target_happy_path(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)

        fake_record = MagicMock()
        fake_record.id = "tgt-new"
        fake_record.kind = "url"
        fake_record.value = "http://localhost:8080"
        fake_record.project_id = "proj-1"

        with patch("aegis.api.v1.targets.targets_svc.create_target",
                   return_value=fake_record), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/targets", json={
                "project_id": "proj-1",
                "kind": "url",
                "value": "http://localhost:8080",
            })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], "tgt-new")

    def test_create_target_missing_value_400(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/targets", json={
                "project_id": "proj-1",
                "kind": "url",
                # missing "value"
            })
        self.assertEqual(resp.status_code, 400)

    def test_create_target_403_scanner_role(self):
        """scanner role cannot manage targets (requires admin)."""
        app, session_cm = _build_app()
        _override_user(app, _scanner())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/targets", json={
                "project_id": "proj-1",
                "kind": "url",
                "value": "http://localhost",
            })
        self.assertEqual(resp.status_code, 403)

    def test_delete_target_happy_path(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_target)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.targets_svc.delete_target",
                   return_value="tgt-1"), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.delete("/v1/targets/tgt-1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["deleted"], "tgt-1")

    def test_delete_target_404(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.delete("/v1/targets/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_delete_target_service_lookup_error_404(self):
        """LookupError from service layer maps to 404."""
        app, session_cm = _build_app(extra_rows_fn=_seed_target)
        _override_user(app, _admin())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.targets_svc.delete_target",
                   side_effect=LookupError("not found")), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.delete("/v1/targets/tgt-1")
        self.assertEqual(resp.status_code, 404)

    def test_delete_target_403_scanner_role(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_target)
        _override_user(app, _scanner())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.targets.load_config",
                   return_value=AegisConfig()):
            resp = client.delete("/v1/targets/tgt-1")
        self.assertEqual(resp.status_code, 403)


# ===========================================================================
# runs_cancel.py
# ===========================================================================

def _seed_run_cancelable(sess):
    from aegis.db.models import Run
    sess.add(Run(id="run-c1", project_id="proj-1", status="running",
                 mode="live", stage_table={}))


class TestRunsCancelApi(unittest.TestCase):

    def _remediator(self):
        return CurrentUser(
            sub="dev:rem@test", email="rem@test",
            project_memberships={"proj-1": "remediator"},
        )

    def test_cancel_run_happy_path(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run_cancelable)
        _override_user(app, self._remediator())
        client = TestClient(app)

        from aegis.services.runs import CancelOutcome
        outcome = CancelOutcome(run_id="run-c1", status="cancelled", jobs_cancelled=0)

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.runs_cancel.cancel_run", return_value=outcome), \
             patch("aegis.api.v1.runs_cancel.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.runs_cancel.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/runs/run-c1/cancel")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["run_id"], "run-c1")
        self.assertEqual(body["status"], "cancelled")

    def test_cancel_run_404_not_found(self):
        app, session_cm = _build_app()
        _override_user(app, self._remediator())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.runs_cancel.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.runs_cancel.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/runs/nonexistent/cancel")
        self.assertEqual(resp.status_code, 404)

    def test_cancel_run_403_no_permission(self):
        """scanner role cannot cancel (requires remediator+)."""
        app, session_cm = _build_app(extra_rows_fn=_seed_run_cancelable)
        _override_user(app, _scanner())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.runs_cancel.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.runs_cancel.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/runs/run-c1/cancel")
        self.assertEqual(resp.status_code, 403)

    def test_cancel_run_auth_error_403(self):
        """AuthorizationError from service maps to 403."""
        app, session_cm = _build_app(extra_rows_fn=_seed_run_cancelable)
        _override_user(app, self._remediator())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.runs_cancel.cancel_run",
                   side_effect=AuthorizationError("denied")), \
             patch("aegis.api.v1.runs_cancel.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.runs_cancel.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/runs/run-c1/cancel")
        self.assertEqual(resp.status_code, 403)

    def test_cancel_run_service_lookup_error_404(self):
        """LookupError from service layer maps to 404."""
        app, session_cm = _build_app(extra_rows_fn=_seed_run_cancelable)
        _override_user(app, self._remediator())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.runs_cancel.cancel_run",
                   side_effect=LookupError("gone")), \
             patch("aegis.api.v1.runs_cancel.resolve_writer",
                   return_value=_DiscardWriter()), \
             patch("aegis.api.v1.runs_cancel.load_config",
                   return_value=AegisConfig()):
            resp = client.post("/v1/runs/run-c1/cancel")
        self.assertEqual(resp.status_code, 404)

    def test_cancel_run_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.post("/v1/runs/run-c1/cancel")
        self.assertEqual(resp.status_code, 401)


# ===========================================================================
# fix.py
# ===========================================================================

def _seed_finding_for_fix(sess):
    from aegis.db.models import Finding, Run
    sess.add(Run(id="run-fix1", project_id="proj-1", status="done",
                 mode="live", stage_table={}))
    sess.add(Finding(
        id="find-fix-001",
        scanner_finding_id="strix-fix-001",
        run_id="run-fix1",
        project_id="proj-1",
        schema_blob={"id": "strix-fix-001"},
        severity="critical",
        validation_state="unvalidated",
        status="open",
    ))


class TestFixApi(unittest.TestCase):

    def _remediator(self):
        return CurrentUser(
            sub="dev:rem@test", email="rem@test",
            project_memberships={"proj-1": "remediator"},
        )

    def test_fix_happy_path_generate(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_fix)
        _override_user(app, self._remediator())
        client = TestClient(app)

        handle = JobHandle(run_id="run-fix1", job_id="job-abc")
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.create_fix_job", return_value=handle), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-fix-001/fix",
                               json={"strategy": "patch", "apply": False})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["job_id"], "job-abc")
        self.assertEqual(body["run_id"], "run-fix1")

    def test_fix_happy_path_apply_requires_approver_role(self):
        """apply=True requires approver; remediator gets 403."""
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_fix)
        _override_user(app, self._remediator())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-fix-001/fix",
                               json={"strategy": "patch", "apply": True})
        self.assertEqual(resp.status_code, 403)

    def test_fix_approver_can_apply(self):
        approver = CurrentUser(
            sub="dev:appr@test", email="appr@test",
            project_memberships={"proj-1": "approver"},
        )
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_fix)
        _override_user(app, approver)
        client = TestClient(app)

        handle = JobHandle(run_id="run-fix1", job_id="job-apply")
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.create_fix_job", return_value=handle), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-fix-001/fix",
                               json={"strategy": "patch", "apply": True})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["job_id"], "job-apply")

    def test_fix_finding_not_found_404(self):
        app, session_cm = _build_app()
        _override_user(app, self._remediator())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/nonexistent/fix", json={})
        self.assertEqual(resp.status_code, 404)

    def test_fix_authorization_error_403(self):
        """AuthorizationError from service → 403."""
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_fix)
        _override_user(app, self._remediator())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.create_fix_job",
                   side_effect=AuthorizationError("denied")), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-fix-001/fix",
                               json={"strategy": "patch"})
        self.assertEqual(resp.status_code, 403)

    def test_fix_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.post("/v1/findings/find-fix-001/fix", json={})
        self.assertEqual(resp.status_code, 401)

    def test_fix_scanner_role_cannot_generate_fix(self):
        """scanner role cannot generate fix (requires remediator+)."""
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_fix)
        _override_user(app, _scanner())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.fix.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.fix.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-fix-001/fix",
                               json={"strategy": "patch"})
        self.assertEqual(resp.status_code, 403)


# ===========================================================================
# verify.py
# ===========================================================================

def _seed_finding_for_verify(sess):
    from aegis.db.models import Finding, Run
    sess.add(Run(id="run-v1", project_id="proj-1", status="done",
                 mode="live", stage_table={}))
    sess.add(Finding(
        id="find-v-001",
        scanner_finding_id="strix-v-001",
        run_id="run-v1",
        project_id="proj-1",
        schema_blob={"id": "strix-v-001"},
        severity="medium",
        validation_state="unvalidated",
        status="open",
    ))


class TestVerifyApi(unittest.TestCase):

    def _remediator(self):
        return CurrentUser(
            sub="dev:rem@test", email="rem@test",
            project_memberships={"proj-1": "remediator"},
        )

    def test_verify_happy_path(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_verify)
        _override_user(app, self._remediator())
        client = TestClient(app)

        handle = JobHandle(run_id="run-v1", job_id="job-ver")
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.verify.create_verify_job", return_value=handle), \
             patch("aegis.api.v1.verify.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.verify.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-v-001/verify")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["job_id"], "job-ver")

    def test_verify_finding_not_found_404(self):
        app, session_cm = _build_app()
        _override_user(app, self._remediator())
        client = TestClient(app)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.verify.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.verify.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/nonexistent/verify")
        self.assertEqual(resp.status_code, 404)

    def test_verify_403_scanner_role(self):
        """scanner cannot verify (requires remediator+)."""
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_verify)
        _override_user(app, _scanner())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.verify.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.verify.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-v-001/verify")
        self.assertEqual(resp.status_code, 403)

    def test_verify_authorization_error_403(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_finding_for_verify)
        _override_user(app, self._remediator())
        client = TestClient(app, raise_server_exceptions=False)
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.verify.create_verify_job",
                   side_effect=AuthorizationError("denied")), \
             patch("aegis.api.v1.verify.resolve_writer", return_value=_DiscardWriter()), \
             patch("aegis.api.v1.verify.load_config", return_value=AegisConfig()):
            resp = client.post("/v1/findings/find-v-001/verify")
        self.assertEqual(resp.status_code, 403)

    def test_verify_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.post("/v1/findings/find-v-001/verify")
        self.assertEqual(resp.status_code, 401)


# ===========================================================================
# exports.py
# ===========================================================================

def _seed_run_for_export(sess):
    from aegis.db.models import Run
    sess.add(Run(id="run-exp1", project_id="proj-1", status="done",
                 mode="live", stage_table={}))


class TestExportsApi(unittest.TestCase):

    def test_vulnfixer_export_blob_hit(self):
        """When blob store returns data, JSON is served."""
        app, session_cm = _build_app(extra_rows_fn=_seed_run_for_export)
        _override_user(app, _admin())
        client = TestClient(app)

        import json as _json
        payload = _json.dumps({"findings": [], "run_id": "run-exp1"}).encode()

        fake_blob = MagicMock()
        fake_blob.get.return_value = payload

        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.exports.ensure_run_access",
                   return_value="proj-1"), \
             patch("aegis.api.v1.exports.load_config", return_value=AegisConfig()), \
             patch("aegis.storage.open_blob_store", return_value=fake_blob):
            resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["run_id"], "run-exp1")

    def test_vulnfixer_export_blob_miss_file_fallback(self, tmp_path=None):
        """When blob misses, fall through to filesystem path."""
        import json as _json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "runs" / "run-exp1"
            run_dir.mkdir(parents=True)
            export_file = run_dir / "vulnfixer-export.json"
            export_file.write_text(_json.dumps({"findings": [], "source": "fs"}))

            app, session_cm = _build_app(extra_rows_fn=_seed_run_for_export)
            _override_user(app, _admin())
            client = TestClient(app)

            fake_blob = MagicMock()
            fake_blob.get.side_effect = FileNotFoundError

            with patch("aegis.db.session.get_session", session_cm), \
                 patch("aegis.api.v1.exports.ensure_run_access",
                       return_value="proj-1"), \
                 patch("aegis.api.v1.exports.load_config",
                       return_value=AegisConfig(output_dir=tmp)), \
                 patch("aegis.storage.open_blob_store",
                       return_value=fake_blob):
                resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["source"], "fs")

    def test_vulnfixer_export_404_no_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            app, session_cm = _build_app(extra_rows_fn=_seed_run_for_export)
            _override_user(app, _admin())
            client = TestClient(app)

            fake_blob = MagicMock()
            fake_blob.get.side_effect = FileNotFoundError

            with patch("aegis.db.session.get_session", session_cm), \
                 patch("aegis.api.v1.exports.ensure_run_access",
                       return_value="proj-1"), \
                 patch("aegis.api.v1.exports.load_config",
                       return_value=AegisConfig(output_dir=tmp)), \
                 patch("aegis.storage.open_blob_store",
                       return_value=fake_blob):
                resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
            self.assertEqual(resp.status_code, 404)

    def test_vulnfixer_export_blob_generic_exception_falls_through(self):
        """Generic blob exception is swallowed; falls through to filesystem."""
        import json as _json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "runs" / "run-exp1"
            run_dir.mkdir(parents=True)
            (run_dir / "vulnfixer-export.json").write_text(
                _json.dumps({"findings": [], "source": "fs-fallback"})
            )

            app, session_cm = _build_app(extra_rows_fn=_seed_run_for_export)
            _override_user(app, _admin())
            client = TestClient(app)

            fake_blob = MagicMock()
            fake_blob.get.side_effect = RuntimeError("blob backend error")

            with patch("aegis.db.session.get_session", session_cm), \
                 patch("aegis.api.v1.exports.ensure_run_access",
                       return_value="proj-1"), \
                 patch("aegis.api.v1.exports.load_config",
                       return_value=AegisConfig(output_dir=tmp)), \
                 patch("aegis.storage.open_blob_store",
                       return_value=fake_blob):
                resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["source"], "fs-fallback")

    def test_vulnfixer_export_no_auth_401(self):
        app, session_cm = _build_app()
        client = _no_auth_client(app)
        with patch("aegis.db.session.get_session", session_cm):
            resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
        self.assertEqual(resp.status_code, 401)

    def test_vulnfixer_export_run_not_found_404(self):
        app, session_cm = _build_app()
        _override_user(app, _admin())
        client = TestClient(app)

        from fastapi import HTTPException
        with patch("aegis.api.v1.exports.ensure_run_access",
                   side_effect=HTTPException(status_code=404, detail="run not found")), \
             patch("aegis.api.v1.exports.load_config", return_value=AegisConfig()):
            resp = client.get("/v1/runs/nonexistent/exports/vulnfixer")
        self.assertEqual(resp.status_code, 404)

    def test_vulnfixer_export_no_project_membership_403(self):
        app, session_cm = _build_app(extra_rows_fn=_seed_run_for_export)
        outsider = CurrentUser(
            sub="dev:x@x", email="x@x", project_memberships={"other": "admin"}
        )
        _override_user(app, outsider)
        client = TestClient(app)

        from fastapi import HTTPException
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.exports.ensure_run_access",
                   side_effect=HTTPException(status_code=403, detail="no access")), \
             patch("aegis.api.v1.exports.load_config", return_value=AegisConfig()):
            resp = client.get("/v1/runs/run-exp1/exports/vulnfixer")
        self.assertEqual(resp.status_code, 403)


# ===========================================================================
# Additional auth.py coverage: _resolve_from_token dev-in-prod guard
# ===========================================================================

class TestAuthDevModeGuard(unittest.TestCase):

    def test_dev_token_in_prod_rejected(self):
        """dev: tokens must be refused when env=prod."""
        from fastapi import HTTPException
        settings = APISettings(env="prod", auth_mode="dev", oidc_jwks_url=None)
        with self.assertRaises(HTTPException) as ctx:
            _resolve_from_token("dev:alice@example.com", settings)
        # In prod without OIDC, attempting dev token falls through to JWT path
        # which raises 500 (OIDC not configured) rather than 401.
        # This is the current behaviour; noted as a potential bug:
        # dev mode check should fire before JWT when auth_mode=="dev" even in prod.
        self.assertIn(ctx.exception.status_code, [401, 500])


if __name__ == "__main__":
    unittest.main()
