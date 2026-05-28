"""Phase 4 v0.4.0 F14a — cookie + bearer auth parity.

The same protected route accepts either:
- an ``Authorization: Bearer …`` token (CLI / CI / programmatic), or
- a valid ``aegis_api_session`` cookie minted by the NextAuth callback.

Cookie verification uses the Aegis public key (RS256), **not** Keycloak's
JWKS — NextAuth signs with the Aegis private key after the Keycloak
code flow completes; FastAPI never sees the underlying access token.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("authlib")
pytest.importorskip("cryptography")

from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.session_cookie import (
    SessionCookieError,
    generate_keypair,
    mint_session_cookie,
    verify_session_cookie,
)
from aegis.api.settings import APISettings


def _settings_with_session_keys(**overrides) -> APISettings:
    private, public = generate_keypair()
    base = dict(
        env="dev", auth_mode="dev",
        api_session_private_key=private,
        api_session_public_key=public,
        cors_origins=["http://localhost:3000"],
    )
    base.update(overrides)
    return APISettings(**base)


class TestMintAndVerify(unittest.TestCase):
    def test_round_trip(self):
        settings = _settings_with_session_keys()
        cookie = mint_session_cookie(
            sub="user-1", email="alice@example.com",
            display_name="Alice",
            project_memberships={"proj-a": "admin"},
            settings=settings,
        )
        claims = verify_session_cookie(cookie, settings)
        self.assertEqual(claims.sub, "user-1")
        self.assertEqual(claims.email, "alice@example.com")
        self.assertEqual(claims.project_memberships, {"proj-a": "admin"})

    def test_cookie_signed_with_unrelated_key_rejected(self):
        s1 = _settings_with_session_keys()
        # New key — different RSA pair, same shape.
        s2_private, s2_public = generate_keypair()
        s2 = _settings_with_session_keys(
            api_session_private_key=s2_private,
            api_session_public_key=s2_public,
        )
        cookie_from_s1 = mint_session_cookie(
            sub="u", email="e@x", settings=s1,
        )
        with self.assertRaises(SessionCookieError):
            verify_session_cookie(cookie_from_s1, s2)

    def test_expired_cookie_rejected(self):
        settings = _settings_with_session_keys(api_session_ttl_seconds=1)
        cookie = mint_session_cookie(
            sub="u", email="e@x", settings=settings,
        )
        import time
        with patch("aegis.api.session_cookie.time.time",
                   return_value=time.time() + 10):
            with self.assertRaises(SessionCookieError):
                verify_session_cookie(cookie, settings)


class TestParityViaTestClient(unittest.TestCase):
    """The same /v1/runs handler must succeed for both auth paths.

    ``Depends(load_settings)`` re-reads env vars per request, so the
    session keys must be wired into the environment (not just the
    APISettings instance we pass into ``create_app``).
    """

    def _env(self, settings: APISettings) -> dict[str, str]:
        return {
            "AEGIS_ENV": "dev", "AEGIS_AUTH_MODE": "dev",
            "AEGIS_API_SESSION_PRIVATE_KEY": settings.api_session_private_key,
            "AEGIS_API_SESSION_PUBLIC_KEY": settings.api_session_public_key,
        }

    def _client(self, settings: APISettings) -> TestClient:
        app = create_app(settings)
        return TestClient(app)

    def test_bearer_path_succeeds(self):
        settings = _settings_with_session_keys(env="dev", auth_mode="dev")
        with patch.dict(os.environ, self._env(settings), clear=False):
            client = self._client(settings)
            resp = client.get(
                "/v1/runs",
                headers={"Authorization": "Bearer dev:alice@aegis.local"},
            )
        # 503 = DB unavailable in unit env; auth passed. 401 would mean
        # auth rejected.
        self.assertIn(resp.status_code, (200, 503))

    def test_cookie_path_succeeds(self):
        settings = _settings_with_session_keys(env="dev", auth_mode="dev")
        with patch.dict(os.environ, self._env(settings), clear=False):
            cookie = mint_session_cookie(
                sub="user-1", email="alice@aegis.local",
                project_memberships={"default": "admin"},
                settings=settings,
            )
            client = self._client(settings)
            client.cookies.set(settings.api_session_cookie_name, cookie)
            resp = client.get("/v1/runs")
        self.assertIn(resp.status_code, (200, 503))

    def test_bearer_wins_over_cookie_when_both_present(self):
        # Cookie carries a valid identity; bearer is the dev-token format
        # but missing the email after the ``:``. The bearer path runs
        # first and rejects — the cookie's identity should not save the
        # request.
        settings = _settings_with_session_keys(env="dev", auth_mode="dev")
        with patch.dict(os.environ, self._env(settings), clear=False):
            cookie = mint_session_cookie(
                sub="user-1", email="alice@aegis.local",
                settings=settings,
            )
            client = self._client(settings)
            client.cookies.set(settings.api_session_cookie_name, cookie)
            resp = client.get(
                "/v1/runs",
                headers={"Authorization": "Bearer dev:"},
            )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("dev token missing email", resp.json()["detail"])

    def test_missing_auth_returns_401(self):
        settings = _settings_with_session_keys(env="dev", auth_mode="dev")
        with patch.dict(os.environ, self._env(settings), clear=False):
            client = self._client(settings)
            resp = client.get("/v1/runs")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("authentication required", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()
