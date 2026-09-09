"""``Idempotency-Key`` on the mutating ML routes (spec 17.3 Idempotency, 6.3; F004 US1).

Register rows REVIEW_REPORTS-31 and -32, plan 12 wave B2. A pure ASGI middleware
so the request body can be read once for the digest and replayed to the route
unchanged. Without the header it is a pass-through; with it:

* the request identity is ``(project, principal, key)``: the ``idempotency_keys``
  primary key is ``(project_id, key)`` (migration 0011) and the stored ``key`` is
  ``sha256(principal_sub | header value)``, so the same header from a different
  principal is a different identity and the raw header value is never stored;
* the project is resolved from the path the way the route will resolve it
  (a model's, finding's or run's project; ``project_id`` in a JSON body or
  ``?project=`` for the collection routes); when it cannot be resolved the
  request passes through and the route answers its own 404/422;
* a miss reserves the row (``response_status = 0``) before the route runs; a
  ``2xx`` JSON response is stored on the row and later identical requests are
  answered from it with ``Idempotency-Replayed: true`` and without re-running
  admission (no second Run, Job or audit row); a non-2xx response, a non-JSON
  body or an exception releases the reservation so a retry re-runs admission;
* a hit whose route or canonical request digest differs answers
  ``409 idempotency_key_reused``; a hit whose reservation is still open answers
  ``409 idempotency_conflict``;
* rows older than :data:`IDEMPOTENCY_TTL` (24 h) are treated as absent (and
  replaced); the reaper's sweep is the durable cleanup.

The middleware never imports an ML library and touches the database only when
the header is present.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Awaitable, Callable, MutableMapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import redsim.api.errors as _errors
from redsim.api.errors import PARAMS_OUT_OF_RANGE, error_detail

if TYPE_CHECKING:
    from redsim.api.auth import CurrentUser
    from redsim.api.settings import APISettings

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

HEADER = "Idempotency-Key"
REPLAYED_HEADER = "Idempotency-Replayed"
MIN_KEY_LENGTH = 1
MAX_KEY_LENGTH = 255
#: A stored response body larger than this is not replayed (the row is released).
MAX_STORED_BODY_BYTES = 64 * 1024
IDEMPOTENCY_TTL = timedelta(hours=24)
#: ``response_status`` of a reservation whose route has not answered yet.
RESERVED_STATUS = 0

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: The mutating ML routes (spec 17.4 table): models, findings actions, run follow-ons,
#: batches and datasets. Everything else passes through untouched.
COVERED_PATH = re.compile(r"^/v1/(models|findings|runs|campaigns|datasets)(/|$)")

# Wave B2 ``codes-b2`` names; resolved by name so this module imports on a tree
# where errors.py lags, keeping the structured 409 either way.
IDEMPOTENCY_KEY_REUSED: str = getattr(_errors, "IDEMPOTENCY_KEY_REUSED", "idempotency_key_reused")
IDEMPOTENCY_CONFLICT: str = getattr(_errors, "IDEMPOTENCY_CONFLICT", "idempotency_conflict")

# Path shapes whose project is a row's project. ``(pattern, model attribute name)``.
_PATH_PROJECT: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/v1/models/(?P<id>[^/]+)/"), "Target"),
    (re.compile(r"^/v1/findings/(?P<id>[^/]+)/"), "Finding"),
    (re.compile(r"^/v1/runs/(?P<id>[^/]+)/"), "Run"),
)
#: Paths whose project comes from the body (``project_id``) or ``?project=``.
_BODY_PROJECT_PATHS = frozenset({"/v1/models", "/v1/models/bulk", "/v1/campaigns/batch", "/v1/datasets"})


def stored_key(principal: str, raw_key: str) -> str:
    """The ``idempotency_keys.key`` value: a digest, so the header value itself is never stored."""
    return hashlib.sha256(f"{principal}\n{raw_key}".encode()).hexdigest()


def request_digest(method: str, path: str, query: bytes, body: bytes) -> str:
    """Canonical request identity: method, path, sorted query pairs and the body bytes
    (canonical JSON when the body parses as JSON, so key order does not matter)."""
    pairs = sorted(part for part in query.decode("latin-1").split("&") if part)
    canonical_body: bytes
    try:
        canonical_body = json.dumps(json.loads(body.decode("utf-8")), sort_keys=True,
                                    separators=(",", ":")).encode() if body.strip() else b""
    except (UnicodeDecodeError, ValueError):
        canonical_body = body
    h = hashlib.sha256()
    for part in (method.upper().encode(), path.encode(), "&".join(pairs).encode(), canonical_body):
        h.update(part)
        h.update(b"\x00")
    return h.hexdigest()


def is_covered(method: str, path: str) -> bool:
    return method.upper() in MUTATING_METHODS and COVERED_PATH.match(path) is not None


def _json_response(status_code: int, content: Any, headers: dict[str, str] | None = None) -> Any:
    from starlette.responses import JSONResponse

    return JSONResponse(status_code=status_code, content=content, headers=headers)


def _refusal(code: str, message: str, **fields: Any) -> Any:
    """A structured 409 (or 422) even when ``code`` is not yet in the 17.3 table."""
    if code in _errors.HTTP_STATUS:
        return _json_response(_errors.HTTP_STATUS[code], {"detail": error_detail(code, message, **fields)})
    return _json_response(409, {"detail": {"code": code, "message": message, **fields}})


class IdempotencyMiddleware:
    """ASGI middleware honouring ``Idempotency-Key`` on the covered routes (see module docstring)."""

    def __init__(self, app: ASGIApp, settings: APISettings | None = None) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        from starlette.requests import Request

        request = Request(scope)
        raw_key = request.headers.get(HEADER.lower())
        if not raw_key or not is_covered(request.method, request.url.path):
            await self.app(scope, receive, send)
            return
        if not (MIN_KEY_LENGTH <= len(raw_key) <= MAX_KEY_LENGTH):
            response = _refusal(PARAMS_OUT_OF_RANGE,
                                f"{HEADER} must be {MIN_KEY_LENGTH} to {MAX_KEY_LENGTH} characters", field=HEADER)
            await response(scope, receive, send)
            return

        body = await _read_body(receive)

        async def replay_receive() -> Message:
            return {"type": "http.request", "body": body, "more_body": False}

        principal = self._principal(request)
        project_id = self._project_id(request, body)
        if project_id is None:
            # The route resolves (and refuses) unknown resources itself; nothing to key on.
            await self.app(scope, replay_receive, send)
            return
        key = stored_key(principal, raw_key)
        route = f"{request.method.upper()} {request.url.path}"
        digest = request_digest(request.method, request.url.path, scope.get("query_string", b""), body)

        try:
            verdict = _reserve(project_id, key, route, digest)
        except Exception:  # noqa: BLE001 - a DB outage is a pass-through, never a 500 from the middleware
            logger.warning("idempotency lookup failed; request handled without a key", exc_info=True)
            await self.app(scope, replay_receive, send)
            return
        if verdict.kind == "replay":
            response = _json_response(verdict.status, verdict.body, headers={REPLAYED_HEADER: "true"})
            await response(scope, receive, send)
            return
        if verdict.kind == "reused":
            response = _refusal(IDEMPOTENCY_KEY_REUSED,
                                f"{HEADER} was already used for a different request in this project",
                                field=HEADER)
            await response(scope, receive, send)
            return
        if verdict.kind == "in_flight":
            response = _refusal(IDEMPOTENCY_CONFLICT,
                                f"a request with this {HEADER} is still in flight", field=HEADER)
            await response(scope, receive, send)
            return

        # Reserved: run the route, tee the response, then store or release.
        captured: dict[str, Any] = {"status": None, "headers": [], "chunks": []}

        async def capture_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                captured["status"] = int(message["status"])
                captured["headers"] = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                captured["chunks"].append(bytes(message.get("body", b"")))
            await send(message)

        try:
            await self.app(scope, replay_receive, capture_send)
        except Exception:
            _release(project_id, key)
            raise
        _finish(project_id, key, captured)

    # -- resolution helpers ------------------------------------------------------------

    def _principal(self, request: Any) -> str:
        """The caller's subject: the app's dependency override (tests), else the bearer or cookie."""
        user = _override_user(request)
        if user is None:
            user = _credential_user(request, self.settings)
        return f"sub:{user.sub}" if user is not None else "anonymous"

    def _project_id(self, request: Any, body: bytes) -> str | None:
        path = request.url.path
        for pattern, model_name in _PATH_PROJECT:
            match = pattern.match(path)
            if match is not None:
                return _row_project(model_name, match.group("id"))
        if path.rstrip("/") in _BODY_PROJECT_PATHS:
            project = request.query_params.get("project")
            if project:
                return str(project)
            try:
                payload = json.loads(body.decode("utf-8")) if body.strip() else None
            except (UnicodeDecodeError, ValueError):
                return None
            value = payload.get("project_id") if isinstance(payload, dict) else None
            return str(value) if isinstance(value, str) and value else None
        return None


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(bytes(message.get("body", b"")))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _override_user(request: Any) -> CurrentUser | None:
    """The ``get_current_user`` dependency override when the app carries one (test harnesses)."""
    try:
        from redsim.api.auth import get_current_user

        override = request.app.dependency_overrides.get(get_current_user)
    except Exception:  # noqa: BLE001 - no app or no overrides
        return None
    if override is None:
        return None
    try:
        user = override()
    except TypeError:
        return None
    return user if hasattr(user, "sub") else None


def _credential_user(request: Any, settings: APISettings | None) -> CurrentUser | None:
    if settings is None:
        return None
    from redsim.api.auth import _resolve_from_cookie, _resolve_from_token

    try:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return _resolve_from_token(auth.split(" ", 1)[1].strip(), settings)
        cookie = request.cookies.get(settings.api_session_cookie_name)
        if cookie:
            return _resolve_from_cookie(cookie, settings)
    except Exception:  # noqa: BLE001 - an unreadable credential means no principal
        return None
    return None


def _row_project(model_name: str, row_id: str) -> str | None:
    from redsim.db import models
    from redsim.db.session import get_session

    model = getattr(models, model_name)
    try:
        with get_session() as sess:
            row = sess.get(model, row_id)
            return str(row.project_id) if row is not None else None
    except Exception:  # noqa: BLE001 - no DB, no project: the route decides
        logger.debug("idempotency project lookup failed", exc_info=True)
        return None


# -- storage ---------------------------------------------------------------------------


class _Verdict:
    __slots__ = ("body", "kind", "status")

    def __init__(self, kind: str, status: int = 0, body: Any = None) -> None:
        self.kind, self.status, self.body = kind, status, body


def _expired(created_at: Any) -> bool:
    if not isinstance(created_at, datetime):
        return False
    stamp = created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=UTC)
    return datetime.now(UTC) - stamp > IDEMPOTENCY_TTL


def _reserve(project_id: str, key: str, route: str, digest: str) -> _Verdict:
    """Look the identity up and reserve it on a miss. Returns the verdict for the caller."""
    from sqlalchemy.exc import IntegrityError

    from redsim.db.models import IdempotencyKey
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(IdempotencyKey, (project_id, key))
        if row is not None and _expired(row.created_at):
            sess.delete(row)
            sess.flush()
            row = None
        if row is not None:
            if str(row.route) != route or str(row.request_sha256) != digest:
                return _Verdict("reused")
            if int(row.response_status) == RESERVED_STATUS:
                return _Verdict("in_flight")
            return _Verdict("replay", int(row.response_status), row.response_body)
        sess.add(IdempotencyKey(project_id=project_id, key=key, route=route, request_sha256=digest,
                                response_status=RESERVED_STATUS, response_body=None))
        try:
            sess.flush()
        except IntegrityError:
            sess.rollback()
            return _Verdict("in_flight")
    return _Verdict("reserved")


def _release(project_id: str, key: str) -> None:
    from redsim.db.models import IdempotencyKey
    from redsim.db.session import get_session

    try:
        with get_session() as sess:
            row = sess.get(IdempotencyKey, (project_id, key))
            if row is not None and int(row.response_status) == RESERVED_STATUS:
                sess.delete(row)
    except Exception:  # noqa: BLE001 - a stale reservation expires by TTL
        logger.warning("idempotency reservation release failed", exc_info=True)


def _finish(project_id: str, key: str, captured: dict[str, Any]) -> None:
    """Store a 2xx JSON response on the reservation; release it for anything else."""
    status = captured.get("status")
    body = b"".join(captured.get("chunks", []))
    content_type = ""
    for name, value in captured.get("headers", []):
        if bytes(name).lower() == b"content-type":
            content_type = bytes(value).decode("latin-1").lower()
    storable = (
        isinstance(status, int) and 200 <= status < 300
        and content_type.startswith("application/json") and len(body) <= MAX_STORED_BODY_BYTES
    )
    if not storable:
        _release(project_id, key)
        return
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _release(project_id, key)
        return
    from redsim.db.models import IdempotencyKey
    from redsim.db.session import get_session

    try:
        with get_session() as sess:
            row = sess.get(IdempotencyKey, (project_id, key))
            if row is None:
                return
            row.response_status = int(status)  # type: ignore[arg-type]
            row.response_body = payload
    except Exception:  # noqa: BLE001 - the response was already sent; the reservation expires by TTL
        logger.warning("idempotency response store failed", exc_info=True)


__all__ = [
    "COVERED_PATH",
    "HEADER",
    "IDEMPOTENCY_CONFLICT",
    "IDEMPOTENCY_KEY_REUSED",
    "IDEMPOTENCY_TTL",
    "MAX_KEY_LENGTH",
    "MAX_STORED_BODY_BYTES",
    "MIN_KEY_LENGTH",
    "MUTATING_METHODS",
    "REPLAYED_HEADER",
    "RESERVED_STATUS",
    "IdempotencyMiddleware",
    "is_covered",
    "request_digest",
    "stored_key",
]
