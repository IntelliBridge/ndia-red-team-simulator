"""Token-bucket rate-limit middleware (in-memory; Redis backend pluggable)."""

from __future__ import annotations

import threading
import time
from typing import Callable


class _Bucket:
    def __init__(self, capacity: int, refill_per_min: int):
        self.capacity = capacity
        self.refill_per_sec = refill_per_min / 60.0
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.tokens = min(self.capacity,
                              self.tokens + elapsed * self.refill_per_sec)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


_BUCKETS: dict[str, _Bucket] = {}
_BUCKET_LOCK = threading.Lock()


def _bucket(key: str, capacity: int, refill_per_min: int) -> _Bucket:
    with _BUCKET_LOCK:
        if key not in _BUCKETS:
            _BUCKETS[key] = _Bucket(capacity, refill_per_min)
        return _BUCKETS[key]


def rate_limit_middleware(user_per_min: int = 30,
                          project_per_min: int = 120) -> Callable:
    """Return an ASGI middleware closure."""
    from fastapi import Request
    from fastapi.responses import JSONResponse

    write_paths = (
        "/v1/scans", "/v1/findings/", "/v1/runs/", "/v1/targets",
        "/v1/tools/",
    )

    async def middleware(request: "Request", call_next):
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return await call_next(request)
        path = request.url.path
        if not any(path.startswith(p) for p in write_paths):
            return await call_next(request)

        user_id = request.headers.get("X-Aegis-User", "anonymous")
        project_id = request.query_params.get("project") or "default"

        user_bucket = _bucket(f"u:{user_id}", user_per_min, user_per_min)
        project_bucket = _bucket(f"p:{project_id}",
                                 project_per_min, project_per_min)
        if not user_bucket.take():
            return JSONResponse(
                status_code=429,
                content={"detail": "user rate limit exceeded"},
                headers={"Retry-After": "60"},
            )
        if not project_bucket.take():
            return JSONResponse(
                status_code=429,
                content={"detail": "project rate limit exceeded"},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)

    return middleware
