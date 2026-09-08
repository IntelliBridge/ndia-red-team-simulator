"""FastAPI app for redsim-log-ingest.

Two ingress paths land on the same ``LogIngestWriter``:

- ``POST /ingest`` — JSON batch from the default-profile direct path
  (api / worker post here when no Collector is up).
- ``POST /v1/logs`` — OTLP/Logs over **JSON** (the
  ``otlphttp/redsim-ingest`` exporter in the Collector config maps to
  this). Parses the OTLP-JSON envelope without pulling in the
  protobuf SDK.

The protobuf gRPC endpoint is out of scope for v0.4.1; the
Collector's ``otlphttp`` exporter is what the compose profile points
at. A gRPC adapter can layer on later without changing the writer.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from redsim.log_ingest.writer import (
    LogIngestRow,
    LogIngestWriter,
    severity_from_otlp,
    ts_from_unix_nano,
)

if TYPE_CHECKING:
    from redsim.api.auth import CurrentUser
    from redsim.api.settings import APISettings
    from redsim.log_ingest.writer import SessionFactory


def _build_session_factory() -> SessionFactory | None:
    db_url = os.environ.get("REDSIM_DB_URL")
    if not db_url:
        return None
    from redsim.db.session import get_session, init_engine
    init_engine(db_url)
    return get_session


def create_app(
    writer: LogIngestWriter | None = None,
    settings: APISettings | None = None,
) -> FastAPI:
    from redsim.api.auth import _verify_worker_token
    from redsim.api.settings import load_settings

    config = settings if settings is not None else load_settings()

    app = FastAPI(
        title="redsim-log-ingest",
        version="0.4.1-dev",
        docs_url="/docs",
        redoc_url=None,
    )
    if writer is None:
        writer = LogIngestWriter(session_factory=_build_session_factory())
    app.state.writer = writer

    def _authenticate(request: Request) -> CurrentUser | None:
        """Verify the worker token guarding the write surface.

        Enforced only when a worker signing key is configured, mirroring
        the API's graceful-degradation posture (``redsim.api.auth``): with
        no key the service stays open for the offline/local profile; once
        a key is set the host-exposed POST routes require a valid worker
        token, closing the asymmetry vs the admin-gated ``GET /v1/logs``.
        """
        if not config.worker_signing_key:
            return None
        header = request.headers.get("authorization", "")
        token = (
            header.split(" ", 1)[1].strip()
            if header.lower().startswith("bearer ")
            else ""
        )
        principal = (
            _verify_worker_token(token, config) if token.startswith("worker:") else None
        )
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="valid worker token required",
            )
        return principal

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "buffered": writer.buffered(),
            "inserted_total": writer.inserted_total,
        }

    @app.get("/metrics")
    def metrics() -> PlainTextResponse:
        body = "\n".join(
            [
                "# HELP redsim_log_ingest_buffered Rows pending flush.",
                "# TYPE redsim_log_ingest_buffered gauge",
                f"redsim_log_ingest_buffered {writer.buffered()}",
                "# HELP redsim_log_ingest_inserted_total Rows written since process start.",
                "# TYPE redsim_log_ingest_inserted_total counter",
                f"redsim_log_ingest_inserted_total {writer.inserted_total}",
                "# HELP redsim_log_ingest_last_flush_ms Duration of last batch insert.",
                "# TYPE redsim_log_ingest_last_flush_ms gauge",
                f"redsim_log_ingest_last_flush_ms {writer.last_flush_ms:.3f}",
                "",
            ]
        )
        return PlainTextResponse(content=body)

    @app.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_native(request: Request) -> dict[str, Any]:
        """Direct path used by API / worker on the default profile.

        Body shape: ``{"records": [{"ts": "...", "severity": "...",
        "service": "...", "message": "...", "attrs": {...}}, ...]}``.
        """
        principal = _authenticate(request)
        payload = await request.json()
        records = payload.get("records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expected {'records': [...]}",
            )
        rows = [_row_from_native(r, principal=principal) for r in records]
        writer.append_many(rows)
        return {"accepted": len(rows), "buffered": writer.buffered()}

    @app.post("/v1/logs", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_otlp(request: Request) -> dict[str, Any]:
        """OTLP/Logs over HTTP (JSON encoding).

        The Collector's ``otlphttp/redsim-ingest`` exporter POSTs here
        with the OTLP-JSON envelope:

            { "resourceLogs": [
                { "resource": {"attributes": [...]},
                  "scopeLogs": [
                    { "logRecords": [
                        {"timeUnixNano": "...", "severityNumber": ...,
                         "severityText": "...", "body": {...},
                         "attributes": [...], "traceId": "...",
                         "spanId": "..."}
                      ] } ] } ] }
        """
        principal = _authenticate(request)
        payload = await request.json()
        rows = _rows_from_otlp(payload, principal=principal)
        writer.append_many(rows)
        return {"accepted": len(rows), "buffered": writer.buffered()}

    @app.on_event("shutdown")
    def _shutdown() -> None:
        writer.close()

    return app


# ----- payload adapters ----------------------------------------------------


def _stamp_provenance(
    attrs: dict[str, Any], principal: CurrentUser | None
) -> dict[str, Any]:
    """Record the authenticated shipper as tamper-evident provenance.

    The write surface relays multi-tenant logs, so per-row ``actor`` /
    ``run_id`` stay as the producer set them; the verified principal is
    recorded separately under ``_ingested_by`` so a body-supplied ``actor``
    can always be checked against who actually authenticated the batch.
    """
    if principal is None:
        return attrs
    return {**attrs, "_ingested_by": principal.sub}


def _row_from_native(
    record: dict[str, Any], *, principal: CurrentUser | None = None
) -> LogIngestRow:
    from datetime import datetime, timezone

    ts_raw = record.get("ts")
    if isinstance(ts_raw, str):
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    elif isinstance(ts_raw, (int, float)):
        ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
    else:
        ts = datetime.now(timezone.utc)
    return LogIngestRow(
        ts=ts,
        severity=str(record.get("severity", "info")),
        service=str(record.get("service", "unknown")),
        message=str(record.get("message", "")),
        run_id=record.get("run_id"),
        job_id=record.get("job_id"),
        project_id=record.get("project_id"),
        actor=record.get("actor"),
        request_id=record.get("request_id"),
        trace_id=record.get("trace_id"),
        span_id=record.get("span_id"),
        attrs=_stamp_provenance(record.get("attrs", {}) or {}, principal),
    )


def _kv_list_to_dict(kvs: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Convert an OTLP ``KeyValue`` array into a plain dict."""
    out: dict[str, Any] = {}
    for kv in kvs or []:
        key = kv.get("key")
        if not isinstance(key, str):
            # OTLP KeyValue.key is spec'd as a string; a missing/non-string
            # key can't be a JSON attr key, so drop the malformed entry.
            continue
        out[key] = _kv_value(kv.get("value", {}))
    return out


def _kv_value(value: dict[str, Any]) -> Any:
    """Decode a single OTLP ``AnyValue`` to a plain Python value.

    OTLP value union: stringValue, intValue, boolValue, doubleValue,
    arrayValue, kvlistValue, bytesValue. Returns the first that's set, or
    None for an empty / unrecognized value. This is the single decoder both
    the attribute-map and array-element paths share, so nested kvlist/array
    values decode identically wherever they appear.
    """
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "kvlistValue" in value:
        return _kv_list_to_dict(value["kvlistValue"].get("values"))
    if "arrayValue" in value:
        return [_kv_value(v) for v in value["arrayValue"].get("values", [])]
    return None


def _rows_from_otlp(
    payload: dict[str, Any], *, principal: CurrentUser | None = None
) -> list[LogIngestRow]:
    rows: list[LogIngestRow] = []
    for rl in payload.get("resourceLogs", []) or []:
        resource_attrs = _kv_list_to_dict(
            (rl.get("resource") or {}).get("attributes")
        )
        service = str(resource_attrs.get("service.name", "unknown"))
        for sl in rl.get("scopeLogs", []) or []:
            for lr in sl.get("logRecords", []) or []:
                attrs = _kv_list_to_dict(lr.get("attributes"))
                body = lr.get("body") or {}
                if isinstance(body, dict) and "stringValue" in body:
                    message = body["stringValue"]
                else:
                    message = str(body)
                ts_nano = lr.get("timeUnixNano")
                if isinstance(ts_nano, str):
                    try:
                        ts_nano = int(ts_nano)
                    except ValueError:
                        ts_nano = None
                rows.append(
                    LogIngestRow(
                        ts=ts_from_unix_nano(ts_nano),
                        severity=severity_from_otlp(
                            lr.get("severityNumber"),
                            lr.get("severityText"),
                        ),
                        service=service,
                        message=message,
                        run_id=_str_or_none(attrs.pop("run_id", None)),
                        job_id=_str_or_none(attrs.pop("job_id", None)),
                        project_id=_str_or_none(attrs.pop("project_id", None)),
                        actor=_str_or_none(attrs.pop("actor", None)),
                        request_id=_str_or_none(attrs.pop("request_id", None)),
                        trace_id=_str_or_none(lr.get("traceId")),
                        span_id=_str_or_none(lr.get("spanId")),
                        attrs=_stamp_provenance(attrs, principal),
                    )
                )
    return rows


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s if s else None


# Allow ``uvicorn redsim.log_ingest.server:app`` to work directly.
app = create_app()
