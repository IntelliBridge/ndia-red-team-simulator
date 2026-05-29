"""FastAPI app for aegis-log-ingest.

Two ingress paths land on the same ``LogIngestWriter``:

- ``POST /ingest`` — JSON batch from the default-profile direct path
  (api / worker post here when no Collector is up).
- ``POST /v1/logs`` — OTLP/Logs over **JSON** (the
  ``otlphttp/aegis-ingest`` exporter in the Collector config maps to
  this). Parses the OTLP-JSON envelope without pulling in the
  protobuf SDK.

The protobuf gRPC endpoint is out of scope for v0.4.1; the
Collector's ``otlphttp`` exporter is what the compose profile points
at. A gRPC adapter can layer on later without changing the writer.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from aegis.log_ingest.writer import (
    LogIngestRow,
    LogIngestWriter,
    severity_from_otlp,
    ts_from_unix_nano,
)


def _build_session_factory():
    db_url = os.environ.get("AEGIS_DB_URL")
    if not db_url:
        return None
    from aegis.db.session import get_session, init_engine
    init_engine(db_url)
    return get_session


def create_app(writer: LogIngestWriter | None = None) -> FastAPI:
    app = FastAPI(
        title="aegis-log-ingest",
        version="0.4.1-dev",
        docs_url="/docs",
        redoc_url=None,
    )
    if writer is None:
        writer = LogIngestWriter(session_factory=_build_session_factory())
    app.state.writer = writer

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
                "# HELP aegis_log_ingest_buffered Rows pending flush.",
                "# TYPE aegis_log_ingest_buffered gauge",
                f"aegis_log_ingest_buffered {writer.buffered()}",
                "# HELP aegis_log_ingest_inserted_total Rows written since process start.",
                "# TYPE aegis_log_ingest_inserted_total counter",
                f"aegis_log_ingest_inserted_total {writer.inserted_total}",
                "# HELP aegis_log_ingest_last_flush_ms Duration of last batch insert.",
                "# TYPE aegis_log_ingest_last_flush_ms gauge",
                f"aegis_log_ingest_last_flush_ms {writer.last_flush_ms:.3f}",
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
        payload = await request.json()
        records = payload.get("records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expected {'records': [...]}",
            )
        rows = [_row_from_native(r) for r in records]
        writer.append_many(rows)
        return {"accepted": len(rows), "buffered": writer.buffered()}

    @app.post("/v1/logs", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_otlp(request: Request) -> dict[str, Any]:
        """OTLP/Logs over HTTP (JSON encoding).

        The Collector's ``otlphttp/aegis-ingest`` exporter POSTs here
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
        payload = await request.json()
        rows = _rows_from_otlp(payload)
        writer.append_many(rows)
        return {"accepted": len(rows), "buffered": writer.buffered()}

    @app.on_event("shutdown")
    def _shutdown() -> None:
        writer.close()

    return app


# ----- payload adapters ----------------------------------------------------


def _row_from_native(record: dict[str, Any]) -> LogIngestRow:
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
        attrs=record.get("attrs", {}) or {},
    )


def _kv_list_to_dict(kvs: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Convert an OTLP ``KeyValue`` array into a plain dict."""
    out: dict[str, Any] = {}
    for kv in kvs or []:
        key = kv.get("key")
        value = kv.get("value", {})
        # OTLP value union: stringValue, intValue, boolValue, doubleValue,
        # arrayValue, kvlistValue, bytesValue. Pull the first that's set.
        if "stringValue" in value:
            out[key] = value["stringValue"]
        elif "intValue" in value:
            out[key] = int(value["intValue"])
        elif "boolValue" in value:
            out[key] = bool(value["boolValue"])
        elif "doubleValue" in value:
            out[key] = float(value["doubleValue"])
        elif "kvlistValue" in value:
            out[key] = _kv_list_to_dict(value["kvlistValue"].get("values"))
        elif "arrayValue" in value:
            out[key] = [_kv_value(v) for v in value["arrayValue"].get("values", [])]
        else:
            out[key] = None
    return out


def _kv_value(value: dict[str, Any]) -> Any:
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    return None


def _rows_from_otlp(payload: dict[str, Any]) -> list[LogIngestRow]:
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
                        attrs=attrs,
                    )
                )
    return rows


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s if s else None


# Allow ``uvicorn aegis.log_ingest.server:app`` to work directly.
app = create_app()
