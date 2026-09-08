"""Rate-limit middleware contract (redsim.api.middleware.rate_limit).

The token-bucket middleware gates only *write* requests on a small set
of ``/v1`` write-path prefixes. This suite drives the **real**
``rate_limit_middleware`` through a FastAPI ``TestClient`` (mirroring the
``create_app`` + ``TestClient`` pattern in ``tests/test_agents_api.py``)
and asserts the three load-bearing behaviours:

  (a) read-only methods and non-write paths BYPASS the limiter entirely;
  (b) the (capacity + 1)th write inside one window is rejected with
      HTTP 429 and a ``Retry-After`` header;
  (c) the module-level ``_BUCKETS`` dict is reset between cases so token
      state never leaks across tests.

We wire the middleware exactly as ``redsim.api.app.create_app`` does
(``user_per_min``/``project_per_min`` sourced from ``APISettings``) onto
a tiny app whose routes echo, so the assertions exercise the limiter in
isolation from auth/DB/route concerns. ``create_app`` is preferred and
used when it imports cleanly; the harness falls back to the equivalent
hand-wired app if an *unrelated* import error in the wider router tree
makes the factory unimportable, keeping this suite deterministic.

Capacity is pinned low (via ``APISettings``) so the window-trip is
deterministic: with a 2-token user bucket the refill rate is
2/60 ≈ 0.033 tok/s, far too slow to top up across a few millisecond-
spaced requests, so the third rapid write always trips.
"""

from __future__ import annotations

import unittest

import pytest

# Needs the ``api`` extra (FastAPI + Starlette's httpx-backed TestClient); the
# lightweight ``unit`` job installs only [test,dev], so skip there. The
# coverage / api-integration jobs install the extra and run this suite.
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI
from fastapi.testclient import TestClient

import redsim.api.middleware.rate_limit as rl
from redsim.api.settings import APISettings

# A write path whose prefix the middleware guards (see ``write_paths`` in
# rate_limit.py). The limiter runs before any route handler, so a tripped
# bucket yields 429 regardless of what the route itself would return.
WRITE_PATH = "/v1/scans"
# A read-only / non-guarded path used for the bypass assertions.
SAFE_PATH = "/health"
USER_CAP = 2  # tiny user-bucket capacity → 3rd write trips deterministically
PROJECT_CAP = 10_000  # generous, so the *user* bucket is what trips first


def _settings() -> APISettings:
    return APISettings(
        env="dev",
        auth_mode="dev",
        cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=USER_CAP,
        rate_limit_per_project_per_min=PROJECT_CAP,
    )


def _wire_like_create_app(app: FastAPI, settings: APISettings) -> None:
    """Attach the real rate-limit middleware the same way create_app does."""
    app.middleware("http")(rl.rate_limit_middleware(
        user_per_min=settings.rate_limit_per_user_per_min,
        project_per_min=settings.rate_limit_per_project_per_min,
    ))


def _build_app(settings: APISettings) -> FastAPI:
    """Prefer the real create_app; fall back to a minimal equivalent.

    ``create_app`` is the production wiring and is used whenever its
    (large) router tree imports cleanly. If an import error elsewhere in
    that tree — unrelated to rate limiting — makes the factory raise, we
    still test the genuine middleware on a tiny hand-wired app configured
    identically, so this suite asserts real behaviour deterministically.
    """
    try:
        from redsim.api.app import create_app
        return create_app(settings)
    except Exception:  # noqa: BLE001 - fall back to the minimal app
        app = FastAPI()
        _wire_like_create_app(app, settings)

        @app.get(SAFE_PATH)
        def _safe() -> dict:  # pragma: no cover - trivial echo
            return {"ok": True}

        @app.post(SAFE_PATH)
        def _safe_post() -> dict:  # pragma: no cover - trivial echo
            return {"ok": True}

        @app.post(WRITE_PATH)
        def _write() -> dict:  # pragma: no cover - trivial echo
            return {"ok": True}

        return app


class RateLimitMiddlewareTest(unittest.TestCase):
    def setUp(self) -> None:
        # (c) Reset the module-level bucket dict so buckets from a prior
        # test (or import-time state) never leak token counts into this one.
        rl._BUCKETS.clear()
        self.addCleanup(rl._BUCKETS.clear)
        self.app = _build_app(_settings())
        self.client = TestClient(self.app, raise_server_exceptions=False)

    # (a) BYPASS: a GET request is never gated, regardless of path.
    def test_get_request_bypasses_limiter(self) -> None:
        # Far more GETs than the user capacity; none may be limited.
        for _ in range(USER_CAP + 5):
            r = self.client.get(SAFE_PATH)
            self.assertNotEqual(
                r.status_code, 429,
                "GET requests must bypass the rate limiter",
            )
        # The bypass is total: the limiter never even created a bucket.
        self.assertEqual(rl._BUCKETS, {})

    # (a) BYPASS: a write method on a NON-write path is also not gated.
    def test_write_method_on_non_write_path_bypasses_limiter(self) -> None:
        # POST to a path outside ``write_paths`` (``/health`` is not a
        # guarded prefix) sails past the limiter every time.
        for _ in range(USER_CAP + 5):
            r = self.client.post(SAFE_PATH)
            self.assertNotEqual(
                r.status_code, 429,
                "writes off the guarded prefixes must bypass the limiter",
            )
        self.assertEqual(rl._BUCKETS, {})

    # (b) The (capacity + 1)th write within the window is a 429 + Retry-After.
    def test_capacity_plus_one_write_returns_429_with_retry_after(self) -> None:
        # The first ``USER_CAP`` writes consume tokens and pass the limiter
        # (whatever the downstream handler then returns, it is not a
        # limiter-issued 429).
        for i in range(USER_CAP):
            r = self.client.post(WRITE_PATH, json={})
            self.assertNotEqual(
                r.status_code, 429,
                f"write #{i + 1} within capacity must not be rate-limited",
            )

        # The very next write exhausts the bucket → limiter rejects it.
        limited = self.client.post(WRITE_PATH, json={})
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Retry-After", limited.headers)
        self.assertEqual(limited.headers["Retry-After"], "60")
        self.assertEqual(limited.json()["detail"], "user rate limit exceeded")

    # (c) Prove isolation: a fresh setUp bucket reset means this test gets a
    # full bucket even though another test exhausted one.
    def test_buckets_do_not_leak_across_cases(self) -> None:
        # Exhaust the bucket within this test...
        for _ in range(USER_CAP):
            self.client.post(WRITE_PATH, json={})
        self.assertEqual(
            self.client.post(WRITE_PATH, json={}).status_code, 429)

        # ...then emulate the per-test reset and confirm the bucket is full
        # again (the same reset setUp performs between real test methods).
        rl._BUCKETS.clear()
        first = self.client.post(WRITE_PATH, json={})
        self.assertNotEqual(
            first.status_code, 429,
            "a reset bucket must start full; state leaked across tests",
        )


class RateLimitScopeTest(unittest.TestCase):
    """Throttle-by-method across ``/v1`` (not a static allowlist) and bucket
    by authenticated principal / client IP (not the spoofable header).
    """

    def setUp(self) -> None:
        rl._BUCKETS.clear()
        self.addCleanup(rl._BUCKETS.clear)

    def _app_with(self, *paths: str) -> FastAPI:
        app = FastAPI()
        _wire_like_create_app(app, _settings())
        for p in paths:
            app.add_api_route(p, lambda: {"ok": True}, methods=["POST"])
        return app

    def test_agent_run_is_now_throttled(self) -> None:
        # /v1/agents/* sat outside the old static write_paths list and was
        # silently un-throttled; the method+prefix gate now covers it.
        client = TestClient(self._app_with("/v1/agents/scout/run"),
                            raise_server_exceptions=False)
        for _ in range(USER_CAP):
            self.assertNotEqual(
                client.post("/v1/agents/scout/run").status_code, 429)
        self.assertEqual(
            client.post("/v1/agents/scout/run").status_code, 429)

    def test_project_bucket_is_scoped_by_principal(self) -> None:
        # M3: ?project is client-supplied, so a bare ``p:{project}`` key would
        # let any caller drain another tenant's bucket. The key must embed the
        # principal. Pin the project cap low so it is the gate (not the user).
        settings = APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            rate_limit_per_user_per_min=10_000,
            rate_limit_per_project_per_min=2,
        )
        app = FastAPI()
        app.middleware("http")(rl.rate_limit_middleware(
            user_per_min=settings.rate_limit_per_user_per_min,
            project_per_min=settings.rate_limit_per_project_per_min,
        ))
        app.add_api_route("/v1/scans", lambda: {"ok": True}, methods=["POST"])
        client = TestClient(app, raise_server_exceptions=False)

        for _ in range(2):
            self.assertNotEqual(
                client.post("/v1/scans?project=victim").status_code, 429)
        self.assertEqual(
            client.post("/v1/scans?project=victim").status_code, 429)

        project_keys = [k for k in rl._BUCKETS if k.startswith("p:")]
        self.assertTrue(project_keys)
        # The spoofable bare key is never used; the real key embeds the principal.
        self.assertNotIn("p:victim", rl._BUCKETS)
        self.assertTrue(
            any(k.endswith(":victim") and k != "p:victim" for k in project_keys),
            f"project bucket not principal-scoped: {project_keys}",
        )

    def test_only_health_is_excluded_from_throttling(self) -> None:
        # The GitHub-webhook prefix that used to be pre-exempted was removed
        # with the pentest domain; no unauthenticated prefix is exempt now, so
        # a write landing under /v1/webhooks/ is throttled like any other.
        self.assertEqual(rl._THROTTLE_EXCLUDE, ("/v1/health",))
        self.assertTrue(rl._is_throttled("POST", "/v1/webhooks/github"))
        self.assertFalse(rl._is_throttled("POST", "/v1/health"))

    def test_x_redsim_user_header_does_not_partition_buckets(self) -> None:
        # Distinct spoofed X-Redsim-User values must share one (IP) bucket, so
        # the (cap+1)th write trips regardless of the header value.
        client = TestClient(self._app_with("/v1/scans"),
                            raise_server_exceptions=False)
        for i in range(USER_CAP):
            self.assertNotEqual(
                client.post(
                    "/v1/scans", headers={"X-Redsim-User": f"user-{i}"},
                ).status_code, 429)
        self.assertEqual(
            client.post(
                "/v1/scans", headers={"X-Redsim-User": "user-final"},
            ).status_code, 429)


if __name__ == "__main__":
    unittest.main()
