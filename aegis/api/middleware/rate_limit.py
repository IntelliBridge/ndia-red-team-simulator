"""Token-bucket rate-limit middleware (in-memory; Redis backend pluggable)."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.responses import Response

    from aegis.api.settings import APISettings


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


# Throttle every mutating request under ``/v1`` except the liveness probe.
# Gating on method + prefix (rather than a hand-maintained list of write
# paths) keeps new write routes throttled by default instead of silently
# un-limited as routes are added. (The GitHub-webhook ingress that used to be
# exempted here was removed with the pentest domain; no unauthenticated
# prefix is pre-exempted.)
_THROTTLED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_THROTTLE_EXCLUDE = ("/v1/health",)


def _is_throttled(method: str, path: str) -> bool:
    return (
        method in _THROTTLED_METHODS
        and path.startswith("/v1")
        and not path.startswith(_THROTTLE_EXCLUDE)
    )


def _principal_key(request: "Request", settings: "APISettings | None") -> str:
    """Bucket key identifying the caller.

    Resolves the caller to its authenticated subject the same way the
    route handlers do (bearer token, then session cookie); unauthenticated
    or unresolvable callers fall back to their client IP. Keying off the
    verified principal closes the spoof where any client could set an
    arbitrary ``X-Aegis-User`` header to dodge or poison a bucket.
    """
    if settings is not None:
        from aegis.api.auth import _resolve_from_cookie, _resolve_from_token
        try:
            auth = request.headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
                return f"sub:{_resolve_from_token(token, settings).sub}"
            cookie = request.cookies.get(settings.api_session_cookie_name)
            if cookie:
                return f"sub:{_resolve_from_cookie(cookie, settings).sub}"
        except Exception:
            pass
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


def rate_limit_middleware(user_per_min: int = 30,
                          project_per_min: int = 120,
                          settings: "APISettings | None" = None) -> Callable:
    """Return an ASGI middleware closure."""
    from fastapi.responses import JSONResponse

    async def middleware(request: "Request",
                         call_next: "RequestResponseEndpoint") -> "Response":
        if not _is_throttled(request.method, request.url.path):
            return await call_next(request)

        principal = _principal_key(request, settings)
        user_bucket = _bucket(f"u:{principal}", user_per_min, user_per_min)
        # The project comes from a client-supplied query param, so a global
        # ``p:{project}`` key would let any caller drain another tenant's shared
        # bucket by passing ``?project=<victim>`` (cross-tenant DoS). Scope the
        # key by principal too: a per-(principal, project) cap that a client
        # can't turn against projects it doesn't own.
        project_id = request.query_params.get("project") or "default"
        project_bucket = _bucket(f"p:{principal}:{project_id}",
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
