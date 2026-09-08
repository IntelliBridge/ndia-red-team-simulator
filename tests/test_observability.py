"""Correlation-id + metrics smoke tests."""

import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from redsim.api.app import create_app
from redsim.api.settings import APISettings


class TestCorrelationId(unittest.TestCase):
    def test_id_propagates_in_response_header(self):
        with patch.dict(os.environ,
                        {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/health",
                              headers={"X-Redsim-Request-ID": "abc-123"})
            self.assertEqual(resp.headers.get("X-Redsim-Request-ID"), "abc-123")

    def test_id_generated_when_missing(self):
        with patch.dict(os.environ,
                        {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/health")
            self.assertTrue(resp.headers.get("X-Redsim-Request-ID"))


class TestMetricsEndpoint(unittest.TestCase):
    def test_metrics_endpoint_returns_exposition(self):
        with patch.dict(os.environ,
                        {"REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.get("/metrics")
            self.assertEqual(resp.status_code, 200)
            body = resp.text
            for counter in ("redsim_scans_total", "redsim_fix_success_total",
                            "redsim_verify_status_total"):
                self.assertIn(counter, body)


if __name__ == "__main__":
    unittest.main()
