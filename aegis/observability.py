"""OpenTelemetry + structlog + correlation-id wiring.

Designed to no-op cleanly when OTel exporters or structlog aren't installed
— the Phase 2 offline CLI must keep working without these extras.
"""

from __future__ import annotations

import os
import uuid
from contextvars import ContextVar
from typing import Callable

_REQUEST_ID: ContextVar[str | None] = ContextVar("aegis_request_id", default=None)


def configure_otel(service_name: str = "aegis") -> None:
    """Initialise OpenTelemetry tracer + meter. No-op when env disables it."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:  # pragma: no cover
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)


def configure_structlog() -> None:
    try:
        import structlog
    except ImportError:  # pragma: no cover
        return
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(value: str | None) -> None:
    _REQUEST_ID.set(value)


def request_id_middleware() -> Callable:
    """ASGI middleware that propagates / generates X-Aegis-Request-ID."""
    async def middleware(request, call_next):
        rid = (request.headers.get("X-Aegis-Request-ID")
               or uuid.uuid4().hex)
        token = _REQUEST_ID.set(rid)
        try:
            response = await call_next(request)
        finally:
            _REQUEST_ID.reset(token)
        response.headers["X-Aegis-Request-ID"] = rid
        return response
    return middleware


# ---- Prometheus metrics ----------------------------------------------------


class _NoopCounter:
    def labels(self, *args, **kwargs):
        return self
    def inc(self, *args, **kwargs):
        pass


def _make_counters():
    try:
        from prometheus_client import Counter, Gauge
    except ImportError:  # pragma: no cover
        return {
            "aegis_scans_total": _NoopCounter(),
            "aegis_fix_success_total": _NoopCounter(),
            "aegis_verify_status_total": _NoopCounter(),
            "aegis_jobs_active": _NoopCounter(),
            "aegis_rate_limited_total": _NoopCounter(),
        }
    return {
        "aegis_scans_total": Counter(
            "aegis_scans_total", "Scans started", ["status"]
        ),
        "aegis_fix_success_total": Counter(
            "aegis_fix_success_total", "Successful fixes",
        ),
        "aegis_verify_status_total": Counter(
            "aegis_verify_status_total", "Verify outcomes", ["status"],
        ),
        "aegis_jobs_active": Gauge(
            "aegis_jobs_active", "Active jobs"
        ),
        "aegis_rate_limited_total": Counter(
            "aegis_rate_limited_total", "Rate-limited requests"
        ),
    }


METRICS = _make_counters()


def metrics_handler():
    """Return a FastAPI route handler that emits Prometheus exposition format."""
    try:
        from fastapi.responses import Response
        from prometheus_client import (
            CONTENT_TYPE_LATEST, generate_latest, REGISTRY,
        )
    except ImportError:  # pragma: no cover
        async def _no_metrics():
            return {"detail": "prometheus_client not installed"}
        return _no_metrics
    async def metrics():
        return Response(generate_latest(REGISTRY),
                        media_type=CONTENT_TYPE_LATEST)
    return metrics
