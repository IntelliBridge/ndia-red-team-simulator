"""Phase 4 v0.4.0 F14b — CSRF double-submit + CORS hardening.

Cookie-authenticated mutations require an ``X-Redsim-CSRF`` header that
matches the ``redsim_csrf`` cookie. Bearer callers are exempt. Read
methods are out of scope. CORS exposes ``allow_credentials=True``
only against an explicit origin list.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("cryptography")

from fastapi.testclient import TestClient

from redsim.api.app import create_app
from redsim.api.middleware.csrf import issue_csrf_token
from redsim.api.session_cookie import generate_keypair, mint_session_cookie
from redsim.api.settings import APISettings


def _settings_with_session_keys(**overrides) -> APISettings:
    priv, pub = generate_keypair()
    base = dict(
        env="dev", auth_mode="dev",
        api_session_private_key=priv,
        api_session_public_key=pub,
        cors_origins=["http://localhost:3000"],
        web_origin="http://localhost:3000",
    )
    base.update(overrides)
    return APISettings(**base)


def _env_for(settings: APISettings) -> dict[str, str]:
    return {
        "REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev",
        "REDSIM_API_SESSION_PRIVATE_KEY": settings.api_session_private_key,
        "REDSIM_API_SESSION_PUBLIC_KEY": settings.api_session_public_key,
    }


class TestCsrfDoubleSubmit(unittest.TestCase):
    def test_cookie_post_without_csrf_header_is_403(self):
        settings = _settings_with_session_keys()
        with patch.dict(os.environ, _env_for(settings), clear=False):
            cookie = mint_session_cookie(
                sub="u-1", email="a@x", settings=settings,
                project_memberships={"default": "admin"},
            )
            client = TestClient(create_app(settings))
            client.cookies.set(settings.api_session_cookie_name, cookie)
            client.cookies.set(settings.api_csrf_cookie_name, issue_csrf_token())
            resp = client.post(
                "/v1/scans",
                json={"target": "http://localhost:3000"},
                # No X-Redsim-CSRF header
            )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("CSRF", resp.json()["detail"])

    def test_cookie_post_with_mismatched_csrf_header_is_403(self):
        settings = _settings_with_session_keys()
        with patch.dict(os.environ, _env_for(settings), clear=False):
            cookie = mint_session_cookie(
                sub="u-1", email="a@x", settings=settings,
                project_memberships={"default": "admin"},
            )
            client = TestClient(create_app(settings))
            client.cookies.set(settings.api_session_cookie_name, cookie)
            client.cookies.set(settings.api_csrf_cookie_name, "abc")
            resp = client.post(
                "/v1/scans",
                json={"target": "http://localhost:3000"},
                headers={settings.api_csrf_header_name: "definitely-not-abc"},
            )
        self.assertEqual(resp.status_code, 403)

    def test_cookie_post_with_matched_csrf_passes_through(self):
        settings = _settings_with_session_keys()
        with patch.dict(os.environ, _env_for(settings), clear=False):
            cookie = mint_session_cookie(
                sub="u-1", email="a@x", settings=settings,
                project_memberships={"default": "admin"},
            )
            csrf = issue_csrf_token()
            # ``raise_server_exceptions=False`` so a downstream handler
            # exception (no DB in unit env) surfaces as 500, not a
            # raised RuntimeError — we only care that CSRF didn't 403.
            client = TestClient(create_app(settings), raise_server_exceptions=False)
            client.cookies.set(settings.api_session_cookie_name, cookie)
            client.cookies.set(settings.api_csrf_cookie_name, csrf)
            resp = client.post(
                "/v1/scans",
                json={"target": "http://localhost:3000"},
                headers={settings.api_csrf_header_name: csrf},
            )
        self.assertNotEqual(resp.status_code, 403)

    def test_bearer_post_without_csrf_passes_through(self):
        # Bearer-only callers (CLI / CI) are exempt from CSRF — there's
        # no automatic-credential surface for them to be confused about.
        settings = _settings_with_session_keys()
        with patch.dict(os.environ, _env_for(settings), clear=False):
            client = TestClient(create_app(settings), raise_server_exceptions=False)
            resp = client.post(
                "/v1/scans",
                json={"target": "http://localhost:3000"},
                headers={"Authorization": "Bearer dev:alice@redsim.local"},
            )
        self.assertNotEqual(resp.status_code, 403,
                            f"unexpected 403 for bearer POST: {resp.text}")

    def test_get_endpoint_does_not_require_csrf(self):
        # CSRF only fires on mutating methods. A cookie-authed GET must
        # never be blocked by the middleware.
        settings = _settings_with_session_keys()
        with patch.dict(os.environ, _env_for(settings), clear=False):
            cookie = mint_session_cookie(
                sub="u-1", email="a@x", settings=settings,
                project_memberships={"default": "admin"},
            )
            client = TestClient(create_app(settings))
            client.cookies.set(settings.api_session_cookie_name, cookie)
            resp = client.get("/v1/runs")
        self.assertNotEqual(resp.status_code, 403)


class TestCorsHardening(unittest.TestCase):
    def test_credentials_response_only_for_listed_origin(self):
        settings = _settings_with_session_keys(
            cors_origins=["https://web.example.com"],
            web_origin="https://web.example.com",
        )
        with patch.dict(os.environ, _env_for(settings), clear=False):
            client = TestClient(create_app(settings))
            resp = client.options(
                "/v1/runs",
                headers={
                    "Origin": "https://attacker.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        # Starlette's CORS middleware doesn't emit
        # ``access-control-allow-origin`` for unlisted origins.
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in resp.headers})


if __name__ == "__main__":
    unittest.main()
