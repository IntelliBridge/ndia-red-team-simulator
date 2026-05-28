"""CSRF double-submit protection for cookie-authenticated mutations.

Phase 4 v0.4.0 F14b. When the caller authenticates via the
``aegis_api_session`` cookie, every mutation (POST / PUT / PATCH /
DELETE) must include an ``X-Aegis-CSRF`` header whose value matches
the ``aegis_csrf`` cookie. Bearer-token callers (CLI, CI) are exempt —
CSRF only matters when the browser sends credentials automatically.

WebSocket handshakes are out of scope here; they get separate
``Origin`` validation in F14c. Read-only methods are also out of scope.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from aegis.api.settings import APISettings


_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _has_bearer(request: Request) -> bool:
    auth = request.headers.get("authorization", "")
    return auth.lower().startswith("bearer ")


def _has_session_cookie(request: Request, settings: APISettings) -> bool:
    return bool(request.cookies.get(settings.api_session_cookie_name))


def issue_csrf_token() -> str:
    """Return a fresh, opaque CSRF token suitable for the double-submit cookie."""
    return secrets.token_urlsafe(32)


def csrf_middleware(
    settings: APISettings,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    """Return an ASGI middleware that enforces double-submit CSRF.

    The check fires only when (a) the request method mutates state and
    (b) the request carries an ``aegis_api_session`` cookie and (c)
    there is no ``Authorization: Bearer …`` header. A mismatched or
    missing ``X-Aegis-CSRF`` header is rejected with 403.
    """
    cookie_name = settings.api_csrf_cookie_name
    header_name = settings.api_csrf_header_name

    async def _csrf(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method not in _MUTATING_METHODS:
            return await call_next(request)
        if _has_bearer(request):
            return await call_next(request)
        if not _has_session_cookie(request, settings):
            return await call_next(request)

        cookie_token = request.cookies.get(cookie_name)
        header_token = request.headers.get(header_name)
        if not cookie_token or not header_token or not secrets.compare_digest(
                cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or mismatched"},
            )
        return await call_next(request)

    return _csrf
