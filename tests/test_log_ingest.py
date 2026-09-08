"""Phase 4 v0.4.1 F20c — redsim-log-ingest service.

Two ingress paths converge on the same batched writer:
- POST /ingest (native JSON, used by the default profile)
- POST /v1/logs (OTLP/Logs JSON, from the Collector)
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from redsim.api.auth import issue_worker_token
from redsim.api.settings import APISettings
from redsim.log_ingest.server import create_app
from redsim.log_ingest.writer import (
    LogIngestRow,
    LogIngestWriter,
    severity_from_otlp,
    ts_from_unix_nano,
)


class TestLogIngestRow(unittest.TestCase):
    def test_requires_tz_aware_ts(self):
        with self.assertRaises(ValueError):
            LogIngestRow(ts=datetime(2026, 1, 1),  # noqa: DTZ001 - naive on purpose
                          severity="info", service="api", message="hi")

    def test_oversize_message_truncated(self):
        big = "x" * (20 * 1024)
        r = LogIngestRow(
            ts=datetime.now(UTC),
            severity="info", service="api", message=big,
        )
        self.assertLess(len(r.message), 20 * 1024)
        self.assertTrue(r.message.endswith("[truncated]"))


class TestSeverityMapping(unittest.TestCase):
    def test_text_wins(self):
        self.assertEqual(severity_from_otlp(17, "DEBUG"), "debug")

    def test_otlp_number_buckets(self):
        self.assertEqual(severity_from_otlp(9, None), "info")
        self.assertEqual(severity_from_otlp(17, None), "error")
        self.assertEqual(severity_from_otlp(21, None), "fatal")

    def test_unknown_defaults_info(self):
        self.assertEqual(severity_from_otlp(None, None), "info")

    def test_ts_from_unix_nano_zero_falls_back_to_now(self):
        self.assertIsInstance(ts_from_unix_nano(None), datetime)
        self.assertIsInstance(ts_from_unix_nano(0), datetime)


class TestNativeIngestEndpoint(unittest.TestCase):
    def test_post_ingest_buffers_records(self):
        writer = LogIngestWriter()  # no session — buffers only
        app = create_app(writer)
        client = TestClient(app)
        resp = client.post(
            "/ingest",
            json={
                "records": [
                    {
                        "ts": "2026-05-28T12:00:00+00:00",
                        "severity": "info",
                        "service": "api",
                        "message": "scan started",
                        "run_id": "run-1",
                        "request_id": "req-abc",
                    },
                ],
            },
        )
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(writer.buffered(), 1)
        self.assertEqual(writer._queue[0].run_id, "run-1")

    def test_bad_payload_returns_400(self):
        writer = LogIngestWriter()
        app = create_app(writer)
        client = TestClient(app)
        resp = client.post("/ingest", json={"not_records": []})
        self.assertEqual(resp.status_code, 400)


class TestOtlpIngestEndpoint(unittest.TestCase):
    def test_post_v1_logs_parses_otlp_envelope(self):
        writer = LogIngestWriter()
        app = create_app(writer)
        client = TestClient(app)
        resp = client.post(
            "/v1/logs",
            json={
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name",
                                 "value": {"stringValue": "redsim-worker"}},
                            ],
                        },
                        "scopeLogs": [
                            {
                                "logRecords": [
                                    {
                                        "timeUnixNano":
                                            "1717248000000000000",
                                        "severityNumber": 17,
                                        "severityText": "ERROR",
                                        "body": {
                                            "stringValue":
                                                "patch_workflow: commit failed",
                                        },
                                        "attributes": [
                                            {"key": "run_id",
                                             "value": {"stringValue":
                                                       "run-xyz"}},
                                            {"key": "exit_code",
                                             "value": {"intValue": "2"}},
                                        ],
                                        "traceId": "deadbeefcafebabe",
                                        "spanId": "feedface",
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        )
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(writer.buffered(), 1)
        row = writer._queue[0]
        self.assertEqual(row.service, "redsim-worker")
        self.assertEqual(row.severity, "error")
        self.assertEqual(row.run_id, "run-xyz")
        self.assertEqual(row.trace_id, "deadbeefcafebabe")
        self.assertEqual(row.span_id, "feedface")
        self.assertEqual(row.attrs.get("exit_code"), 2)
        self.assertEqual(row.message, "patch_workflow: commit failed")


class TestMetricsAndHealth(unittest.TestCase):
    def test_metrics_exposes_counters(self):
        writer = LogIngestWriter()
        writer.append(LogIngestRow(
            ts=datetime.now(UTC),
            severity="info", service="api", message="hi",
        ))
        app = create_app(writer)
        client = TestClient(app)
        resp = client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("redsim_log_ingest_buffered", resp.text)
        self.assertIn("redsim_log_ingest_inserted_total", resp.text)

    def test_health_returns_ok(self):
        writer = LogIngestWriter()
        client = TestClient(create_app(writer))
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")


class TestWriteSurfaceAuth(unittest.TestCase):
    """The host-exposed write routes require a worker token once a signing
    key is configured; with no key the service stays open (offline profile).
    """

    @staticmethod
    def _enforced_settings() -> APISettings:
        return APISettings(
            env="prod", auth_mode="oidc",
            worker_signing_key="key-v1",
            worker_signing_key_previous=None,
            worker_signing_key_version=1,
            worker_key_overlap_seconds=300,
            worker_token_ttl_seconds=300,
        )

    @staticmethod
    def _record() -> dict:
        return {
            "ts": "2026-05-28T12:00:00+00:00", "severity": "info",
            "service": "api", "message": "hi", "actor": "user:alice",
        }

    def test_ingest_without_token_is_401_when_key_set(self):
        writer = LogIngestWriter()
        client = TestClient(create_app(writer, self._enforced_settings()))
        resp = client.post("/ingest", json={"records": [self._record()]})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(writer.buffered(), 0)

    def test_ingest_with_invalid_token_is_401(self):
        writer = LogIngestWriter()
        client = TestClient(create_app(writer, self._enforced_settings()))
        resp = client.post(
            "/ingest",
            headers={"Authorization": "Bearer worker:v1.w1.9999999999.bad"},
            json={"records": [self._record()]},
        )
        self.assertEqual(resp.status_code, 401)

    def test_ingest_with_valid_token_stamps_provenance(self):
        settings = self._enforced_settings()
        token = issue_worker_token("w1", settings=settings)
        writer = LogIngestWriter()
        client = TestClient(create_app(writer, settings))
        resp = client.post(
            "/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"records": [self._record()]},
        )
        self.assertEqual(resp.status_code, 202)
        row = writer._queue[0]
        # Relayed multi-tenant actor is preserved (not clobbered)...
        self.assertEqual(row.actor, "user:alice")
        # ...and the authenticated shipper is recorded as provenance.
        self.assertEqual(row.attrs["_ingested_by"], "service:worker:w1")

    def test_otlp_with_valid_token_stamps_provenance(self):
        settings = self._enforced_settings()
        token = issue_worker_token("w1", settings=settings)
        writer = LogIngestWriter()
        client = TestClient(create_app(writer, settings))
        resp = client.post(
            "/v1/logs",
            headers={"Authorization": f"Bearer {token}"},
            json={"resourceLogs": [{
                "resource": {"attributes": [
                    {"key": "service.name",
                     "value": {"stringValue": "redsim-worker"}}]},
                "scopeLogs": [{"logRecords": [{
                    "timeUnixNano": "1717248000000000000",
                    "severityText": "INFO",
                    "body": {"stringValue": "hi"},
                    "attributes": [
                        {"key": "run_id",
                         "value": {"stringValue": "run-xyz"}}],
                }]}],
            }]},
        )
        self.assertEqual(resp.status_code, 202)
        row = writer._queue[0]
        self.assertEqual(row.run_id, "run-xyz")  # relayed attribution kept
        self.assertEqual(row.attrs["_ingested_by"], "service:worker:w1")

    def test_no_key_leaves_write_surface_open(self):
        # Graceful degradation: no signing key → offline/local profile,
        # writes accepted without a token and no provenance stamped.
        writer = LogIngestWriter()
        settings = APISettings(env="dev", auth_mode="dev",
                               worker_signing_key=None)
        client = TestClient(create_app(writer, settings))
        resp = client.post("/ingest", json={"records": [self._record()]})
        self.assertEqual(resp.status_code, 202)
        self.assertNotIn("_ingested_by", writer._queue[0].attrs)


if __name__ == "__main__":
    unittest.main()
