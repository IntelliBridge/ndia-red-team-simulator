"""OpenTelemetry + structlog + correlation-id wiring.

Designed to no-op cleanly when OTel exporters or structlog aren't installed
— the Phase 2 offline CLI must keep working without these extras.

Correlation model
-----------------
Four ContextVars carry the correlation ids the platform cares about:

* ``request_id`` — set by :func:`request_id_middleware` in the API process.
* ``run_id`` / ``job_id`` / ``project_id`` — bound by the worker's
  ``task_context`` (``redsim.workers.bootstrap``) for the duration of a task
  body through :func:`bind_job_context`.

They reach every log line three ways, all of which degrade to no-ops:

* structlog events via :func:`_inject_correlation_ids` (plus
  ``structlog.contextvars`` when structlog is installed);
* stdlib ``LogRecord`` attributes via :class:`CorrelationFilter`, which is
  attached to the OTel ``LoggingHandler`` so OTLP log records carry them as
  attributes (``redsim-log-ingest`` lifts ``run_id``/``job_id``/``project_id``
  into columns);
* the direct-mode :class:`LogIngestShipper`, which posts stdlib records to
  ``POST {REDSIM_LOG_INGEST_URL}/ingest`` when that variable is set.

Spans and metrics
-----------------
:func:`span` opens an OTel span when the SDK is importable (no-op otherwise);
:func:`stage_span` is the per-stage variant the ML campaign task uses — it also
observes ``redsim_ml_stage_seconds{stage}``. :func:`record_campaign_outcome`
increments ``redsim_ml_campaigns_total{status}``. Both metrics are registered
lazily with the other product counters in :func:`get_metrics`.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections.abc import Callable, Iterator, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

_REQUEST_ID: ContextVar[str | None] = ContextVar("redsim_request_id", default=None)
_RUN_ID: ContextVar[str | None] = ContextVar("redsim_run_id", default=None)
_JOB_ID: ContextVar[str | None] = ContextVar("redsim_job_id", default=None)
_PROJECT_ID: ContextVar[str | None] = ContextVar("redsim_project_id", default=None)

_JOB_CONTEXT_VARS: dict[str, ContextVar[str | None]] = {
    "run_id": _RUN_ID,
    "job_id": _JOB_ID,
    "project_id": _PROJECT_ID,
}

#: Env var naming the direct-mode ``redsim-log-ingest`` endpoint. Unset (the
#: default) means no shipper is attached — logs stay on stdout / OTLP.
LOG_INGEST_URL_ENV = "REDSIM_LOG_INGEST_URL"

logger = logging.getLogger(__name__)


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


def current_job_context() -> dict[str, str]:
    """The ``run_id`` / ``job_id`` / ``project_id`` currently bound (only set ones)."""
    return {
        key: value
        for key, var in _JOB_CONTEXT_VARS.items()
        if (value := var.get()) is not None
    }


def _inject_correlation_ids(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor that lifts correlation ids onto every event.

    The request id is request-scoped via the ContextVar; ``run_id`` /
    ``job_id`` / ``project_id`` are task-scoped (:func:`bind_job_context`);
    the trace + span ids come from the active OTel span (None when no span is
    active). Values already present on the event always win.
    """
    rid = _REQUEST_ID.get()
    if rid and "request_id" not in event_dict:
        event_dict["request_id"] = rid
    for key, value in current_job_context().items():
        if key not in event_dict:
            event_dict[key] = value
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            if "trace_id" not in event_dict:
                event_dict["trace_id"] = format(ctx.trace_id, "032x")
            if "span_id" not in event_dict:
                event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:  # noqa: BLE001, S110 - trace enrichment never breaks a log line
        pass
    return event_dict


class CorrelationFilter(logging.Filter):
    """Stamp the bound correlation ids onto stdlib ``LogRecord`` attributes.

    Attached to the OTel ``LoggingHandler`` (and the direct-mode shipper) so
    records leaving the process carry ``request_id`` / ``run_id`` / ``job_id``
    / ``project_id`` as attributes. Never rejects a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        rid = _REQUEST_ID.get()
        if rid and not hasattr(record, "request_id"):
            record.request_id = rid
        for key, value in current_job_context().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


def _configure_otel_logs(service_name: str) -> None:
    """Pipe stdlib logging -> OTel LoggingHandler -> OTLP.

    F21: when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set we route every
    stdlib log record through the OTel Logs SDK's ``LoggingHandler`` so
    the Collector receives canonical OTLP/Logs records, stamped with the
    bound correlation ids by :class:`CorrelationFilter`. When the env
    var is unset the function is a no-op and logs go to stdout via the
    structlog JSONRenderer — Phase 2 offline path is unchanged.
    """
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
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
    handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
    handler.addFilter(CorrelationFilter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def configure_structlog(service_name: str = "redsim") -> None:
    """Wire structlog + optional OTel Logs SDK.

    F21: every event carries ``request_id`` / ``trace_id`` / ``span_id``
    (and the worker's ``run_id`` / ``job_id`` / ``project_id``) when they're
    in scope. When ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, the same events
    also stream to the Collector via the OTel Logs SDK.
    """
    try:
        import structlog
    except ImportError:  # pragma: no cover
        return
    _configure_otel_logs(service_name)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
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


@contextmanager
def bind_job_context(
    *,
    run_id: str | None,
    job_id: str | None,
    project_id: str | None,
) -> Iterator[None]:
    """Bind ``run_id`` / ``job_id`` / ``project_id`` for the enclosed block.

    Used by the worker's ``task_context`` around a task body so every log
    line (structlog or stdlib, via :class:`CorrelationFilter`) and the
    direct-mode shipper carry the job's identity. Restores the previous
    values on exit; ``None`` values are simply not bound.
    """
    values = {"run_id": run_id, "job_id": job_id, "project_id": project_id}
    tokens: list[tuple[ContextVar[str | None], Token[str | None]]] = []
    bound_structlog: list[str] = []
    for key, value in values.items():
        if value is None:
            continue
        tokens.append((_JOB_CONTEXT_VARS[key], _JOB_CONTEXT_VARS[key].set(value)))
    try:
        import structlog

        present = {k: v for k, v in values.items() if v is not None}
        if present:
            structlog.contextvars.bind_contextvars(**present)
            bound_structlog = list(present)
    except Exception:  # noqa: BLE001 - structlog is optional
        bound_structlog = []
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)
        if bound_structlog:
            try:
                import structlog

                structlog.contextvars.unbind_contextvars(*bound_structlog)
            except Exception:  # noqa: BLE001, S110 - telemetry never raises
                pass


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


# ---- Spans -----------------------------------------------------------------


def _span_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    """Keep only OTel-representable attribute values (drop ``None``)."""
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        if value is None:
            continue
        if isinstance(value, (str, bool, int, float)):
            out[key] = value
        else:
            out[key] = str(value)
    return out


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[Any]:
    """Open an OTel span named ``name`` with ``attrs``; no-op without the SDK.

    Yields the span object (or ``None``). The bound job context is added as
    attributes automatically so a span can always be joined to its run.
    """
    try:
        from opentelemetry import trace
    except ImportError:  # pragma: no cover - SDK is an optional extra
        yield None
        return
    attributes = _span_attributes({**current_job_context(), **attrs})
    try:
        tracer = trace.get_tracer("redsim")
        cm = tracer.start_as_current_span(name, attributes=attributes)
    except Exception:  # noqa: BLE001 - telemetry never breaks the caller
        yield None
        return
    with cm as active:
        yield active


@contextmanager
def stage_span(name: str, **attrs: Any) -> Iterator[Any]:
    """Per-stage span for the ML campaign (``ml.stage.<name>``).

    Opens an OTel span carrying ``stage=<name>`` plus ``attrs`` and observes
    the stage's wall-clock seconds on ``redsim_ml_stage_seconds{stage}``.
    Both halves are best-effort: telemetry never raises into the stage.
    """
    started = time.monotonic()
    with span(f"ml.stage.{name}", stage=name, **attrs) as active:
        try:
            yield active
        finally:
            elapsed = time.monotonic() - started
            try:
                get_metrics()["redsim_ml_stage_seconds"].labels(stage=name).observe(elapsed)
            except Exception:  # noqa: BLE001, S110 - metrics never break the stage
                pass


def record_campaign_outcome(status: str) -> None:
    """Increment ``redsim_ml_campaigns_total{status}`` (never raises)."""
    try:
        get_metrics()["redsim_ml_campaigns_total"].labels(status=status).inc()
    except Exception:  # noqa: BLE001, S110
        pass


# ---- Prometheus metrics ----------------------------------------------------


class _NoopMetric:
    """Stand-in for Counter/Gauge/Histogram when prometheus_client is absent."""

    def labels(self, *args: Any, **kwargs: Any) -> _NoopMetric:
        return self

    def inc(self, *args: Any, **kwargs: Any) -> None:
        pass

    def set(self, *args: Any, **kwargs: Any) -> None:
        pass

    def observe(self, *args: Any, **kwargs: Any) -> None:
        pass


# Kept for callers that imported the old name.
_NoopCounter = _NoopMetric

#: Product metric names (all registered by :func:`get_metrics`).
#: ``redsim_jobs_active`` and the two ``redsim_ml_*`` gauges after it are set from
#: one sample of the jobs table by ``redsim.services.ml_capacity.sample_gauges``
#: (the continuation dispatcher and the 60 s beat backstop; register BULK-22).
METRIC_NAMES: tuple[str, ...] = (
    "redsim_scans_total",
    "redsim_fix_success_total",
    "redsim_verify_status_total",
    "redsim_jobs_active",
    "redsim_rate_limited_total",
    "redsim_ml_campaigns_total",
    "redsim_ml_stage_seconds",
    "redsim_ml_deferred_runs",
    "redsim_ml_daily_budget_used",
)

#: Histogram buckets for ``redsim_ml_stage_seconds``: sub-second sample/clean
#: passes up to the 1800 s Celery soft limit.
_STAGE_SECONDS_BUCKETS = (0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1200, 1800)


def _make_counters() -> dict[str, Any]:
    try:
        from prometheus_client import Counter, Gauge, Histogram
    except ImportError:  # pragma: no cover
        return {name: _NoopMetric() for name in METRIC_NAMES}
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
        "redsim_ml_campaigns_total": Counter(
            "redsim_ml_campaigns_total",
            "ML campaign jobs reaching a terminal status",
            ["status"],
        ),
        "redsim_ml_stage_seconds": Histogram(
            "redsim_ml_stage_seconds",
            "Wall-clock seconds per ML campaign stage",
            ["stage"],
            buckets=_STAGE_SECONDS_BUCKETS,
        ),
        "redsim_ml_deferred_runs": Gauge(
            "redsim_ml_deferred_runs",
            "ML campaign jobs admitted but waiting for a project concurrency slot",
            ["project"],
        ),
        "redsim_ml_daily_budget_used": Gauge(
            "redsim_ml_daily_budget_used",
            "ML run admissions (attack.run + verify.replay) since 00:00 UTC per project",
            ["project"],
        ),
    }


def set_capacity_gauges(
    *,
    jobs_active: int,
    deferred_by_project: MutableMapping[str, int] | dict[str, int],
    budget_used_by_project: MutableMapping[str, int] | dict[str, int],
) -> None:
    """Set ``redsim_jobs_active`` and the per-project capacity gauges from one sample (never raises).

    The sample comes from the jobs table (``redsim.services.ml_capacity.sample_gauges``),
    never from broker inspection. Per-project labels are unbounded in a large
    tenancy; acceptable for the deployment sizes this tool targets (BULK-22 risk note).
    """
    try:
        metrics = get_metrics()
        metrics["redsim_jobs_active"].set(int(jobs_active))
        for project, value in deferred_by_project.items():
            metrics["redsim_ml_deferred_runs"].labels(project=str(project)).set(int(value))
        for project, value in budget_used_by_project.items():
            metrics["redsim_ml_daily_budget_used"].labels(project=str(project)).set(int(value))
    except Exception:  # noqa: BLE001, S110 - metrics never break the caller
        pass


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


# ---- Direct-mode log shipper (redsim-log-ingest) ---------------------------


class LogIngestShipper(logging.Handler):
    """Ship stdlib log records to ``POST {url}/ingest`` in small batches.

    The default compose profile has no Collector; the API and worker post
    directly to ``redsim-log-ingest`` (``docs/architecture/observability.md``).
    This handler is that direct path: records are buffered and flushed when
    ``batch_size`` is reached or every ``flush_seconds`` from a daemon thread.

    Failure posture: a batch that cannot be delivered is dropped and counted
    in :attr:`dropped`; the handler never raises, never retries, and never
    logs (which would recurse into itself). Messages pass through the audit
    redactor so a token that leaked into a log line is scrubbed before it
    leaves the process. ``token_provider`` supplies the bearer worker token
    when the ingest service enforces one.
    """

    def __init__(
        self,
        url: str,
        *,
        service: str,
        batch_size: int = 100,
        flush_seconds: float = 2.0,
        token_provider: Callable[[], str | None] | None = None,
        client: Any = None,
    ) -> None:
        super().__init__(level=logging.INFO)
        import httpx

        self.service = service
        self.batch_size = max(1, int(batch_size))
        self.flush_seconds = max(0.1, float(flush_seconds))
        self.dropped = 0
        self.shipped = 0
        self._token_provider = token_provider
        self._client = client or httpx.Client(
            base_url=url.rstrip("/"), timeout=5.0,
        )
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="redsim-log-shipper", daemon=True,
        )
        self.addFilter(CorrelationFilter())
        self._thread.start()

    # -- logging.Handler ---------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(("httpx", "httpcore", __name__)):
            # Our own transport's logs would recurse into the shipper.
            return
        try:
            row = self._row(record)
        except Exception:  # noqa: BLE001 - a bad record is dropped, never raised
            self.dropped += 1
            return
        with self._lock:
            self._buffer.append(row)
            full = len(self._buffer) >= self.batch_size
        if full:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            batch, self._buffer = self._buffer, []
        headers: dict[str, str] = {}
        try:
            token = self._token_provider() if self._token_provider else None
            if token:
                headers["Authorization"] = f"Bearer {token}"
            response = self._client.post(
                "/ingest", json={"records": batch}, headers=headers,
            )
            if 200 <= response.status_code < 300:
                self.shipped += len(batch)
            else:
                self.dropped += len(batch)
        except Exception:  # noqa: BLE001 - delivery is best-effort
            self.dropped += len(batch)

    def close(self) -> None:
        self._stop.set()
        try:
            self.flush()
        finally:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001, S110
                pass
            super().close()

    # -- internals -----------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.wait(self.flush_seconds):
            self.flush()

    def _row(self, record: logging.LogRecord) -> dict[str, Any]:
        from redsim.audit.redact import redact_audit_detail

        message = redact_audit_detail(record.getMessage())
        row: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "severity": record.levelname.lower(),
            "service": self.service,
            "message": message,
            "attrs": {"logger": record.name},
        }
        for key in ("run_id", "job_id", "project_id", "request_id"):
            value = getattr(record, key, None)
            if value is not None:
                row[key] = str(value)
        return row


_SHIPPER: LogIngestShipper | None = None


def _worker_token_provider(service_name: str) -> Callable[[], str | None] | None:
    """Mint a worker service token per flush when a signing key is configured.

    The ingest service enforces its worker token only when
    ``REDSIM_WORKER_SIGNING_KEY`` is set; without one it is open and no
    header is sent. Returns ``None`` when the API auth module is not
    importable (minimal worker image).
    """
    try:
        from redsim.api.auth import issue_worker_token
        from redsim.api.settings import load_settings
    except Exception:  # noqa: BLE001 - api extra absent
        return None
    settings = load_settings()
    if not settings.worker_signing_key:
        return None
    worker_id = f"{service_name}-{os.getpid()}"

    def _mint() -> str | None:
        try:
            return issue_worker_token(worker_id, settings=settings)
        except Exception:  # noqa: BLE001
            return None

    return _mint


def configure_log_shipper(
    service_name: str = "redsim",
    *,
    url: str | None = None,
) -> LogIngestShipper | None:
    """Attach the direct-mode shipper to the root logger when configured.

    Default-off: with neither ``url`` nor ``REDSIM_LOG_INGEST_URL`` set this
    returns ``None`` and touches nothing. Idempotent per process — a second
    call returns the handler already attached.
    """
    global _SHIPPER
    target = url or os.environ.get(LOG_INGEST_URL_ENV, "").strip()
    if not target:
        return None
    if _SHIPPER is not None:
        return _SHIPPER
    try:
        batch = int(os.environ.get("REDSIM_LOG_INGEST_BATCH_SIZE", "100"))
        flush = float(os.environ.get("REDSIM_LOG_INGEST_FLUSH_SECONDS", "2"))
        shipper = LogIngestShipper(
            target, service=service_name, batch_size=batch, flush_seconds=flush,
            token_provider=_worker_token_provider(service_name),
        )
    except Exception:  # noqa: BLE001 - shipping is optional; never break startup
        logger.warning("log-ingest shipper not started", exc_info=True)
        return None
    root = logging.getLogger()
    root.addHandler(shipper)
    if root.level > logging.INFO:
        # Root defaults to WARNING; INFO lines are the ones worth mirroring.
        root.setLevel(logging.INFO)
    _SHIPPER = shipper
    return shipper


_WORKER_OBS_PID: int | None = None


def configure_worker_observability(service_name: str | None = None) -> None:
    """One-shot worker init: OTel tracer, structlog, direct log shipper.

    Connected to Celery's ``worker_init`` / ``worker_process_init`` in
    ``redsim.workers.celery_app`` so each pool process gets its own exporter
    threads (post-fork). Idempotent per process id; every piece is env-gated
    and no-ops when unconfigured.
    """
    global _WORKER_OBS_PID
    if _WORKER_OBS_PID == os.getpid():
        return
    _WORKER_OBS_PID = os.getpid()
    name = service_name or os.environ.get("OTEL_SERVICE_NAME") or "redsim-worker"
    configure_otel(service_name=name)
    configure_structlog(service_name=name)
    configure_log_shipper(service_name=name)


__all__ = [
    "LOG_INGEST_URL_ENV",
    "METRIC_NAMES",
    "CorrelationFilter",
    "LogIngestShipper",
    "bind_job_context",
    "configure_log_shipper",
    "configure_otel",
    "configure_structlog",
    "configure_worker_observability",
    "current_job_context",
    "current_request_id",
    "get_metrics",
    "metrics_handler",
    "record_campaign_outcome",
    "request_id_middleware",
    "set_capacity_gauges",
    "set_request_id",
    "span",
    "stage_span",
]
