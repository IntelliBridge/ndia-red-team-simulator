"""Correlation-id + metrics smoke tests, ML product metrics, per-stage spans,
and the direct-mode log-ingest shipper (G-OBS)."""

import logging
import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx
from fastapi.testclient import TestClient

from redsim import observability
from redsim.api.app import create_app
from redsim.api.settings import APISettings
from redsim.observability import (
    LOG_INGEST_URL_ENV,
    LogIngestShipper,
    bind_job_context,
    configure_log_shipper,
    get_metrics,
    record_campaign_outcome,
    stage_span,
)


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
                            "redsim_ml_campaigns_total",
                            "redsim_ml_stage_seconds"):
                self.assertIn(counter, body)


def _sample(name: str, labels: dict) -> float:
    from prometheus_client import REGISTRY
    return REGISTRY.get_sample_value(name, labels) or 0.0


class TestMlProductMetrics(unittest.TestCase):
    def test_campaign_outcome_counter_increments_by_status(self):
        get_metrics()
        before = _sample("redsim_ml_campaigns_total", {"status": "succeeded"})
        other = _sample("redsim_ml_campaigns_total", {"status": "failed"})
        record_campaign_outcome("succeeded")
        record_campaign_outcome("succeeded")
        self.assertEqual(
            _sample("redsim_ml_campaigns_total", {"status": "succeeded"}), before + 2,
        )
        self.assertEqual(_sample("redsim_ml_campaigns_total", {"status": "failed"}), other)

    def test_stage_span_observes_stage_seconds(self):
        get_metrics()
        before = _sample("redsim_ml_stage_seconds_count", {"stage": "clean_eval"})
        with stage_span("clean_eval", n_samples=10):
            pass
        self.assertEqual(
            _sample("redsim_ml_stage_seconds_count", {"stage": "clean_eval"}), before + 1,
        )
        self.assertGreaterEqual(
            _sample("redsim_ml_stage_seconds_sum", {"stage": "clean_eval"}), 0.0,
        )

    def test_stage_span_observes_even_when_the_stage_raises(self):
        get_metrics()
        before = _sample("redsim_ml_stage_seconds_count", {"stage": "attack:fgsm"})
        with self.assertRaises(RuntimeError):
            with stage_span("attack:fgsm"):
                raise RuntimeError("attack failed")
        self.assertEqual(
            _sample("redsim_ml_stage_seconds_count", {"stage": "attack:fgsm"}), before + 1,
        )

    def test_metric_helpers_never_raise(self):
        with patch.object(observability, "get_metrics", side_effect=RuntimeError("no registry")):
            record_campaign_outcome("failed")  # must not raise
            with stage_span("score"):
                pass


class TestStageSpanTracing(unittest.TestCase):
    """The span itself, through an in-memory exporter when the global tracer
    provider has not been claimed by anything else in this process."""

    @classmethod
    def setUpClass(cls):
        pytest.importorskip("opentelemetry.sdk")
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        cls.exporter = InMemorySpanExporter()
        current = trace.get_tracer_provider()
        if type(current).__name__ == "ProxyTracerProvider":
            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(cls.exporter))
            trace.set_tracer_provider(provider)
            cls.owned = True
        elif isinstance(current, TracerProvider):
            current.add_span_processor(SimpleSpanProcessor(cls.exporter))
            cls.owned = True
        else:  # pragma: no cover - some other provider owns the process
            cls.owned = False

    def setUp(self):
        if not self.owned:
            self.skipTest("global tracer provider owned elsewhere")
        self.exporter.clear()

    def test_stage_span_carries_stage_and_bound_job_ids(self):
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            with stage_span("attack", attack_id="fgsm", eps=0.03, skipped=None) as active:
                self.assertIsNotNone(active)
        spans = self.exporter.get_finished_spans()
        names = [s.name for s in spans]
        self.assertIn("ml.stage.attack", names)
        span = next(s for s in spans if s.name == "ml.stage.attack")
        attrs = dict(span.attributes or {})
        self.assertEqual(attrs["stage"], "attack")
        self.assertEqual(attrs["attack_id"], "fgsm")
        self.assertEqual(attrs["eps"], 0.03)
        self.assertEqual(attrs["run_id"], "run-1")
        self.assertEqual(attrs["job_id"], "job-1")
        self.assertEqual(attrs["project_id"], "proj-1")
        self.assertNotIn("skipped", attrs)  # None attributes are dropped

    def test_trace_ids_reach_structlog_events_inside_span(self):
        from redsim.observability import _inject_correlation_ids
        with stage_span("score"):
            event = _inject_correlation_ids(None, "info", {"event": "scoring"})
        self.assertEqual(len(event["trace_id"]), 32)
        self.assertEqual(len(event["span_id"]), 16)


class _Capture:
    def __init__(self, status_code: int = 202, raise_exc: Exception | None = None):
        self.requests: list[httpx.Request] = []
        self.status_code = status_code
        self.raise_exc = raise_exc

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_exc is not None:
            raise self.raise_exc
        return httpx.Response(self.status_code, json={"accepted": 1})


class TestLogIngestShipper(unittest.TestCase):
    """Direct-mode ``POST /ingest`` shipper: batch shape, redaction, auth,
    and the drop-never-raise failure posture."""

    def _shipper(self, capture: _Capture, **kwargs) -> LogIngestShipper:
        client = httpx.Client(
            base_url="http://ingest.test", transport=httpx.MockTransport(capture),
        )
        shipper = LogIngestShipper(
            "http://ingest.test", service="redsim-worker", batch_size=50,
            flush_seconds=60, client=client, **kwargs,
        )
        self.addCleanup(shipper.close)
        return shipper

    def _logger(self, shipper: LogIngestShipper) -> logging.Logger:
        log = logging.getLogger(f"tests.shipper.{id(shipper)}")
        log.setLevel(logging.INFO)
        log.propagate = False
        log.addHandler(shipper)
        self.addCleanup(log.removeHandler, shipper)
        return log

    def test_records_carry_bound_ids_and_redacted_message(self):
        capture = _Capture()
        shipper = self._shipper(capture)
        log = self._logger(shipper)
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            log.info("pythia call with Bearer %s", "pk_fixture-not-a-real-key-0123456789")
            log.warning("stage %s done", "attack")
        shipper.flush()
        self.assertEqual(len(capture.requests), 1)
        request = capture.requests[0]
        self.assertEqual(request.url.path, "/ingest")
        self.assertNotIn("Authorization", request.headers)  # no signing key → open
        import json
        body = json.loads(request.content)
        records = body["records"]
        self.assertEqual(len(records), 2)
        first, second = records
        self.assertEqual(first["service"], "redsim-worker")
        self.assertEqual(first["severity"], "info")
        self.assertEqual(second["severity"], "warning")
        self.assertEqual(first["run_id"], "run-1")
        self.assertEqual(first["job_id"], "job-1")
        self.assertEqual(first["project_id"], "proj-1")
        self.assertIn("<REDACTED>", first["message"])
        self.assertNotIn("pk_fixture", first["message"])
        self.assertEqual(first["attrs"]["logger"], log.name)
        self.assertTrue(first["ts"].startswith("20"))
        self.assertEqual(shipper.shipped, 2)

    def test_bearer_token_sent_when_provider_configured(self):
        capture = _Capture()
        shipper = self._shipper(capture, token_provider=lambda: "worker:v1.w.9.sig")
        self._logger(shipper).info("hello")
        shipper.flush()
        self.assertEqual(
            capture.requests[0].headers["Authorization"], "Bearer worker:v1.w.9.sig",
        )

    def test_batch_size_triggers_flush(self):
        capture = _Capture()
        client = httpx.Client(
            base_url="http://ingest.test", transport=httpx.MockTransport(capture),
        )
        shipper = LogIngestShipper(
            "http://ingest.test", service="redsim-api", batch_size=2,
            flush_seconds=60, client=client,
        )
        self.addCleanup(shipper.close)
        log = self._logger(shipper)
        log.info("one")
        self.assertEqual(capture.requests, [])
        log.info("two")
        self.assertEqual(len(capture.requests), 1)

    def test_delivery_failure_drops_and_never_raises(self):
        capture = _Capture(raise_exc=httpx.ConnectError("refused"))
        shipper = self._shipper(capture)
        self._logger(shipper).info("lost")
        shipper.flush()  # must not raise
        self.assertEqual(shipper.dropped, 1)
        self.assertEqual(shipper.shipped, 0)

    def test_rejected_batch_is_counted_as_dropped(self):
        capture = _Capture(status_code=401)
        shipper = self._shipper(capture)
        self._logger(shipper).info("unauthorised")
        shipper.flush()
        self.assertEqual(shipper.dropped, 1)

    def test_transport_loggers_are_ignored_to_avoid_recursion(self):
        capture = _Capture()
        shipper = self._shipper(capture)
        record = logging.LogRecord("httpx", logging.INFO, __file__, 1, "GET", None, None)
        shipper.emit(record)
        shipper.flush()
        self.assertEqual(capture.requests, [])


class TestConfigureLogShipper(unittest.TestCase):
    def tearDown(self):
        shipper = observability._SHIPPER
        if shipper is not None:
            logging.getLogger().removeHandler(shipper)
            shipper.close()
        observability._SHIPPER = None

    def test_default_off_without_url(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(LOG_INGEST_URL_ENV, None)
            self.assertIsNone(configure_log_shipper("redsim-api"))
        self.assertIsNone(observability._SHIPPER)

    def test_attaches_once_when_url_given(self):
        with patch.dict(os.environ, {"REDSIM_WORKER_SIGNING_KEY": ""}, clear=False):
            first = configure_log_shipper("redsim-worker", url="http://ingest.test:4319")
            second = configure_log_shipper("redsim-worker", url="http://ingest.test:4319")
        self.assertIsNotNone(first)
        self.assertIs(first, second)
        self.assertIn(first, logging.getLogger().handlers)
        self.assertEqual(first.service, "redsim-worker")

    def test_worker_observability_init_is_idempotent_per_process(self):
        observability._WORKER_OBS_PID = None
        with patch.object(observability, "configure_otel") as otel, \
             patch.object(observability, "configure_structlog") as slog, \
             patch.object(observability, "configure_log_shipper") as ship:
            observability.configure_worker_observability()
            observability.configure_worker_observability()
        otel.assert_called_once_with(service_name="redsim-worker")
        slog.assert_called_once_with(service_name="redsim-worker")
        ship.assert_called_once_with(service_name="redsim-worker")
        observability._WORKER_OBS_PID = None


class TestCeleryWorkerSignals(unittest.TestCase):
    def test_worker_init_signals_call_observability_init(self):
        pytest.importorskip("celery")
        from celery.signals import worker_init, worker_process_init

        from redsim.workers import celery_app

        for signal in (worker_init, worker_process_init):
            # Signal.receivers holds (lookup_key, receiver) pairs; connected
            # with weak=False so the receiver is the function itself.
            funcs = [r if callable(r) else r() for _, r in signal.receivers]
            self.assertIn(celery_app.init_worker_observability, funcs, signal.name)
        with patch.object(observability, "configure_worker_observability") as init:
            celery_app.init_worker_observability(sender=None)
        init.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
