"""Correlation-id + metrics smoke tests."""

import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.settings import APISettings
from aegis.observability import current_request_id


class TestCorrelationId(unittest.TestCase):
    def test_id_propagates_in_response_header(self):
        with patch.dict(os.environ,
                        {"AEGIS_ENV": "dev", "AEGIS_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/health",
                              headers={"X-Aegis-Request-ID": "abc-123"})
            self.assertEqual(resp.headers.get("X-Aegis-Request-ID"), "abc-123")

    def test_id_generated_when_missing(self):
        with patch.dict(os.environ,
                        {"AEGIS_ENV": "dev", "AEGIS_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/health")
            self.assertTrue(resp.headers.get("X-Aegis-Request-ID"))


class TestMetricsEndpoint(unittest.TestCase):
    def test_metrics_endpoint_returns_exposition(self):
        with patch.dict(os.environ,
                        {"AEGIS_ENV": "dev", "AEGIS_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/metrics")
            self.assertEqual(resp.status_code, 200)
            body = resp.text
            for counter in ("aegis_scans_total", "aegis_fix_success_total",
                            "aegis_verify_status_total"):
                self.assertIn(counter, body)


if __name__ == "__main__":
    unittest.main()
