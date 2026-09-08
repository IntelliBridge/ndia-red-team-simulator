"""OpenTelemetry + structlog + correlation-id wiring.

Designed to no-op cleanly when OTel exporters or structlog aren't installed
— the Phase 2 offline CLI must keep working without these extras.
"""

from __future__ import annotations

import os
import uuid
from contextvars import ContextVar
from typing import Any, Callable, MutableMapping

_REQUEST_ID: ContextVar[str | None] = ContextVar("redsim_request_id", default=None)


def configure_otel(service_name: str = "redsim") -> None:
    """Initialise OpenTelemetry tracer + meter. No-op when env disables it."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
        )
    except ImportError:  # pragma: no cover
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)


def _inject_correlation_ids(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor that lifts request_id / trace_id onto every event.

    The request id is request-scoped via the ContextVar; the trace + span
    ids come from the active OTel span (None when no span is active).
    """
    rid = _REQUEST_ID.get()
    if rid and "request_id" not in event_dict:
        event_dict["request_id"] = rid
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            if "trace_id" not in event_dict:
                event_dict["trace_id"] = format(ctx.trace_id, "032x")
            if "span_id" not in event_dict:
                event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:
        pass
    return event_dict


def _configure_otel_logs(service_name: str) -> None:
    """Pipe structlog -> stdlib logging -> OTel LoggingHandler -> OTLP.

    F21: when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set we route every
    structlog event through the OTel Logs SDK's ``LoggingHandler`` so
    the Collector receives canonical OTLP/Logs records. When the env
    var is unset the function is a no-op and logs go to stdout via the
    structlog JSONRenderer — Phase 2 offline path is unchanged.
    """
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        import logging

        from opentelemetry._logs import set_logger_provider
        from opentelemetry.exporter.otlp.proto.http._log_exporter import (
            OTLPLogExporter,
        )
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.sdk.resources import Resource
    except ImportError:  # pragma: no cover
        return

    resource = Resource.create({"service.name": service_name})
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter())
    )
    set_logger_provider(provider)
    root = logging.getLogger()
    root.addHandler(LoggingHandler(level=logging.INFO,
                                    logger_provider=provider))
    root.setLevel(logging.INFO)


def configure_structlog(service_name: str = "redsim") -> None:
    """Wire structlog + optional OTel Logs SDK.

    F21: every event carries ``request_id`` / ``trace_id`` / ``span_id``
    when they're in scope. When ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set,
    the same events also stream to the Collector via the OTel Logs SDK.
    """
    try:
        import structlog
    except ImportError:  # pragma: no cover
        return
    _configure_otel_logs(service_name)
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            _inject_correlation_ids,
            structlog.processors.JSONRenderer(),
        ],
    )


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(value: str | None) -> None:
    _REQUEST_ID.set(value)


def request_id_middleware() -> Callable:
    """ASGI middleware that propagates / generates X-Redsim-Request-ID."""
    async def middleware(request: Any, call_next: Any) -> Any:
        rid = (request.headers.get("X-Redsim-Request-ID")
               or uuid.uuid4().hex)
        token = _REQUEST_ID.set(rid)
        try:
            response = await call_next(request)
        finally:
            _REQUEST_ID.reset(token)
        response.headers["X-Redsim-Request-ID"] = rid
        return response
    return middleware


# ---- Prometheus metrics ----------------------------------------------------


class _NoopCounter:
    def labels(self, *args: Any, **kwargs: Any) -> _NoopCounter:
        return self
    def inc(self, *args: Any, **kwargs: Any) -> None:
        pass


def _make_counters() -> dict[str, Any]:
    try:
        from prometheus_client import Counter, Gauge
    except ImportError:  # pragma: no cover
        return {
            "redsim_scans_total": _NoopCounter(),
            "redsim_fix_success_total": _NoopCounter(),
            "redsim_verify_status_total": _NoopCounter(),
            "redsim_jobs_active": _NoopCounter(),
            "redsim_rate_limited_total": _NoopCounter(),
        }
    return {
        "redsim_scans_total": Counter(
            "redsim_scans_total", "Scans started", ["status"]
        ),
        "redsim_fix_success_total": Counter(
            "redsim_fix_success_total", "Successful fixes",
        ),
        "redsim_verify_status_total": Counter(
            "redsim_verify_status_total", "Verify outcomes", ["status"],
        ),
        "redsim_jobs_active": Gauge(
            "redsim_jobs_active", "Active jobs"
        ),
        "redsim_rate_limited_total": Counter(
            "redsim_rate_limited_total", "Rate-limited requests"
        ),
    }


_METRICS: dict | None = None


def get_metrics() -> dict[str, Any]:
    """Return the metrics dict, building (and registering) it on first call.

    Memoized so the Counter/Gauge objects register into the process-global
    Prometheus registry exactly once, on first real use — never at import
    time. This mirrors the deferred init of configure_otel/create_app and
    avoids duplicate-registration failures on re-import.
    """
    global _METRICS
    if _METRICS is None:
        _METRICS = _make_counters()
    return _METRICS


def metrics_handler() -> Callable[[], Any]:
    """Return a FastAPI route handler that emits Prometheus exposition format."""
    try:
        from fastapi.responses import Response
        from prometheus_client import (
            CONTENT_TYPE_LATEST,
            REGISTRY,
            generate_latest,
        )
    except ImportError:  # pragma: no cover
        async def _no_metrics() -> dict[str, str]:
            return {"detail": "prometheus_client not installed"}
        return _no_metrics
    # Ensure the counters are registered before we serialize the registry.
    get_metrics()
    async def metrics() -> Any:
        return Response(generate_latest(REGISTRY),
                        media_type=CONTENT_TYPE_LATEST)
    return metrics
