"""Phase 4 v0.4.1 F21 — structlog correlation processor.

Every event carries request_id (from the ContextVar set by the API's
request_id_middleware) plus trace_id / span_id when an OTel span is
active. The actual OTel SDK wiring is gated on
``OTEL_EXPORTER_OTLP_ENDPOINT`` — this test exercises the processor
in isolation so it doesn't depend on the SDK exporter being reachable.
"""

from __future__ import annotations

import unittest

import pytest

pytest.importorskip("structlog")

import logging

import structlog

from redsim.observability import (
    CorrelationFilter,
    _inject_correlation_ids,
    bind_job_context,
    current_job_context,
    set_request_id,
)


class TestInjectCorrelationIds(unittest.TestCase):
    def setUp(self):
        set_request_id(None)

    def test_request_id_lifted_when_set(self):
        set_request_id("req-abc")
        result = _inject_correlation_ids(None, "info", {"event": "scan.start"})
        self.assertEqual(result["request_id"], "req-abc")
        self.assertEqual(result["event"], "scan.start")

    def test_request_id_absent_when_unset(self):
        result = _inject_correlation_ids(None, "info", {"event": "x"})
        self.assertNotIn("request_id", result)

    def test_explicit_request_id_in_event_wins(self):
        set_request_id("from-context")
        result = _inject_correlation_ids(
            None, "info", {"event": "x", "request_id": "from-call"},
        )
        self.assertEqual(result["request_id"], "from-call")

    def test_no_active_span_means_no_trace_keys(self):
        # An import error or no active span path leaves the dict alone.
        result = _inject_correlation_ids(None, "info", {"event": "x"})
        self.assertNotIn("trace_id", result)
        self.assertNotIn("span_id", result)

    def test_job_ids_absent_when_unbound(self):
        result = _inject_correlation_ids(None, "info", {"event": "x"})
        for key in ("run_id", "job_id", "project_id"):
            self.assertNotIn(key, result)


class TestBindJobContext(unittest.TestCase):
    """G-OBS: run_id / job_id / project_id bound for the worker task body."""

    def test_ids_lifted_onto_events_inside_and_gone_after(self):
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            result = _inject_correlation_ids(None, "info", {"event": "stage"})
            self.assertEqual(result["run_id"], "run-1")
            self.assertEqual(result["job_id"], "job-1")
            self.assertEqual(result["project_id"], "proj-1")
            self.assertEqual(
                current_job_context(),
                {"run_id": "run-1", "job_id": "job-1", "project_id": "proj-1"},
            )
        after = _inject_correlation_ids(None, "info", {"event": "stage"})
        self.assertNotIn("run_id", after)
        self.assertEqual(current_job_context(), {})

    def test_explicit_event_values_win(self):
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            result = _inject_correlation_ids(
                None, "info", {"event": "x", "run_id": "explicit"},
            )
        self.assertEqual(result["run_id"], "explicit")

    def test_none_values_are_not_bound(self):
        with bind_job_context(run_id="run-1", job_id=None, project_id=None):
            self.assertEqual(current_job_context(), {"run_id": "run-1"})

    def test_nested_binding_restores_outer(self):
        with bind_job_context(run_id="outer", job_id="j1", project_id="p"):
            with bind_job_context(run_id="inner", job_id="j2", project_id="p"):
                self.assertEqual(current_job_context()["run_id"], "inner")
            self.assertEqual(current_job_context()["run_id"], "outer")
            self.assertEqual(current_job_context()["job_id"], "j1")

    def test_structlog_contextvars_mirror_the_binding(self):
        structlog.contextvars.clear_contextvars()
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            bound = structlog.contextvars.get_contextvars()
            self.assertEqual(bound.get("run_id"), "run-1")
            self.assertEqual(bound.get("job_id"), "job-1")
        self.assertNotIn("run_id", structlog.contextvars.get_contextvars())

    def test_bound_context_survives_an_exception(self):
        with self.assertRaises(RuntimeError):
            with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
                raise RuntimeError("body failed")
        self.assertEqual(current_job_context(), {})


class TestCorrelationFilter(unittest.TestCase):
    """stdlib records leaving the process carry the same ids as attributes."""

    def _record(self) -> logging.LogRecord:
        return logging.LogRecord(
            "redsim.test", logging.INFO, __file__, 1, "hello", None, None,
        )

    def setUp(self):
        set_request_id(None)

    def test_stamps_bound_ids_and_never_rejects(self):
        flt = CorrelationFilter()
        set_request_id("req-1")
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            record = self._record()
            self.assertTrue(flt.filter(record))
        self.assertEqual(record.run_id, "run-1")  # type: ignore[attr-defined]
        self.assertEqual(record.job_id, "job-1")  # type: ignore[attr-defined]
        self.assertEqual(record.project_id, "proj-1")  # type: ignore[attr-defined]
        self.assertEqual(record.request_id, "req-1")  # type: ignore[attr-defined]

    def test_unbound_record_untouched(self):
        record = self._record()
        self.assertTrue(CorrelationFilter().filter(record))
        for key in ("run_id", "job_id", "project_id", "request_id"):
            self.assertFalse(hasattr(record, key))

    def test_existing_record_attribute_wins(self):
        record = self._record()
        record.run_id = "explicit"  # type: ignore[attr-defined]
        with bind_job_context(run_id="run-1", job_id="job-1", project_id="proj-1"):
            CorrelationFilter().filter(record)
        self.assertEqual(record.run_id, "explicit")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
