"""Batched Postgres writer for the application_logs mirror.

Keeps a small in-memory deque that flushes whenever it hits the size
threshold OR the time threshold (whichever first). Exposed counters
(`buffered`, `inserted_total`, `dropped_oversize`) feed the /metrics
endpoint so an operator can spot ingest lag.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class LogIngestRow:
    """One row about to land in ``application_logs``.

    Mirrors the columns 1:1; ``attrs`` is freeform JSON for whatever
    structured fields didn't deserve a dedicated column. ``ts`` is a
    timezone-aware datetime; passing a naive datetime is a bug we'd
    rather surface immediately.
    """
    ts: datetime
    severity: str
    service: str
    message: str
    run_id: str | None = None
    job_id: str | None = None
    project_id: str | None = None
    actor: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError("LogIngestRow.ts must be timezone-aware")
        # Cap message + attrs at sensible sizes. The Collector pipeline
        # already truncates; this is the second line of defence so a
        # rogue caller can't fill the table with multi-megabyte rows.
        if len(self.message) > 16 * 1024:
            self.message = self.message[: 16 * 1024] + "…[truncated]"
        if len(json.dumps(self.attrs, default=str)) > 64 * 1024:
            self.attrs = {"_truncated": True}


_DEFAULT_BATCH = 500
_DEFAULT_FLUSH_SECONDS = 2.0


class LogIngestWriter:
    """Thread-safe batching writer.

    Use as a singleton; both the HTTP and gRPC handlers append to the
    same instance. ``close()`` flushes any pending rows.
    """

    def __init__(
        self,
        *,
        session_factory=None,
        batch_size: int = _DEFAULT_BATCH,
        flush_seconds: float = _DEFAULT_FLUSH_SECONDS,
    ) -> None:
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self._queue: deque[LogIngestRow] = deque()
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._session_factory = session_factory
        # Counters surfaced via /metrics.
        self.inserted_total: int = 0
        self.dropped_oversize: int = 0
        self.last_flush_ms: float = 0.0

    def append(self, row: LogIngestRow) -> None:
        with self._lock:
            self._queue.append(row)
        if self._should_flush():
            self.flush()

    def append_many(self, rows: list[LogIngestRow]) -> None:
        with self._lock:
            self._queue.extend(rows)
        if self._should_flush():
            self.flush()

    def buffered(self) -> int:
        with self._lock:
            return len(self._queue)

    def _should_flush(self) -> bool:
        # Lock-free heuristic; the actual flush re-checks under lock.
        return (
            len(self._queue) >= self.batch_size
            or time.monotonic() - self._last_flush >= self.flush_seconds
        )

    def flush(self) -> int:
        """Drain the queue into Postgres. Returns rows written.

        When no session factory is configured (the in-process unit-test
        path), returns 0 and leaves the queue intact so the test can
        inspect ``buffered()`` directly.
        """
        with self._lock:
            if not self._queue:
                self._last_flush = time.monotonic()
                return 0
            if self._session_factory is None:
                return 0
            batch = list(self._queue)
            self._queue.clear()
            self._last_flush = time.monotonic()

        start = time.monotonic()
        n = self._insert(batch)
        self.last_flush_ms = (time.monotonic() - start) * 1000.0
        self.inserted_total += n
        return n

    def _insert(self, rows: list[LogIngestRow]) -> int:
        from aegis.db.models import ApplicationLog
        with self._session_factory() as sess:
            objs = [
                ApplicationLog(
                    ts=r.ts, severity=r.severity, service=r.service,
                    message=r.message, run_id=r.run_id, job_id=r.job_id,
                    project_id=r.project_id, actor=r.actor,
                    request_id=r.request_id, trace_id=r.trace_id,
                    span_id=r.span_id, attrs=r.attrs,
                )
                for r in rows
            ]
            sess.add_all(objs)
            sess.commit()
            return len(objs)

    def close(self) -> None:
        self.flush()


_SEVERITY_MAP = {
    1: "trace", 2: "trace", 3: "trace", 4: "trace",
    5: "debug", 6: "debug", 7: "debug", 8: "debug",
    9: "info", 10: "info", 11: "info", 12: "info",
    13: "warn", 14: "warn", 15: "warn", 16: "warn",
    17: "error", 18: "error", 19: "error", 20: "error",
    21: "fatal", 22: "fatal", 23: "fatal", 24: "fatal",
}


def severity_from_otlp(severity_number: int | None,
                        severity_text: str | None) -> str:
    """Map an OTLP severity_number to our text label.

    ``severity_text`` from the producer wins when present; we fall back
    to the numeric bucket table OTLP defines, defaulting to ``info``.
    """
    if severity_text:
        s = severity_text.lower().strip()
        if s in {"trace", "debug", "info", "warn", "warning",
                 "error", "fatal", "critical"}:
            return "warn" if s == "warning" else s
    if severity_number is not None:
        return _SEVERITY_MAP.get(int(severity_number), "info")
    return "info"


def ts_from_unix_nano(ts_nano: int | None) -> datetime:
    if ts_nano is None or ts_nano <= 0:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(ts_nano / 1_000_000_000, tz=timezone.utc)
