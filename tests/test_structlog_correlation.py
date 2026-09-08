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

from redsim.observability import (
    _inject_correlation_ids,
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


if __name__ == "__main__":
    unittest.main()
