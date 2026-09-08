"""FastAPI auth + RBAC smoke tests (in-memory app)."""

import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from redsim.api.app import create_app
from redsim.api.settings import APISettings


def _client(*, env="dev", auth_mode="dev",
            cors_origins=None) -> TestClient:
    settings = APISettings(env=env, auth_mode=auth_mode,
                           cors_origins=cors_origins or ["http://localhost:3000"])
    app = create_app(settings)
    # The Depends(load_settings) call always re-reads env; for these tests we
    # poke the auth.load_settings cache by setting REDSIM_AUTH_MODE / REDSIM_ENV.
    return TestClient(app)


class TestHealthOpen(unittest.TestCase):
    def test_health_is_unauthenticated(self):
        with patch.dict(os.environ, {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"}, clear=False):
            client = _client()
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "ok")


class TestDevAuthFallback(unittest.TestCase):
    def test_dev_token_works_in_dev_env(self):
        with patch.dict(os.environ, {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev",
                                      "REDSIM_DB_URL": ""}, clear=False):
            client = _client()
            # /v1/runs needs a DB to list; we just want to confirm auth passes.
            resp = client.get("/v1/runs",
                              headers={"Authorization": "Bearer dev:alice@redsim.local"})
            # 503 (DB unavailable) means auth passed and we got into the handler;
            # 401 would mean auth was rejected.
            self.assertIn(resp.status_code, (200, 503))

    def test_dev_token_rejected_in_prod(self):
        with patch.dict(os.environ, {"REDSIM_ENV": "prod", "REDSIM_AUTH_MODE": "dev"}, clear=False):
            client = _client(env="prod")
            resp = client.get("/v1/runs",
                              headers={"Authorization": "Bearer dev:alice@redsim.local"})
            self.assertEqual(resp.status_code, 401)
            self.assertIn("dev auth disabled", resp.json()["detail"])

    def test_missing_bearer_returns_401(self):
        with patch.dict(os.environ, {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"}, clear=False):
            client = _client()
            resp = client.get("/v1/runs")
            self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
