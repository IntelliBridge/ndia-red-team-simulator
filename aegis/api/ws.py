"""WebSocket: /v1/runs/{run_id}/events backed by Redis pub/sub.

Phase 4 v0.4.0 F14c hardens the upgrade path:

- ``Origin`` is validated against the CORS allowlist (when the header
  is present — non-browser callers don't send it).
- Programmatic callers may attach a bearer token via the WebSocket
  subprotocol channel ``Sec-WebSocket-Protocol: aegis.bearer.<token>``
  (RFC 6455). The server echoes the chosen subprotocol back; the
  token itself never appears in the URL or in a query parameter.
- Browser callers use cookie auth — the ``aegis_api_session`` cookie
  rides along with the upgrade by default; the same RS256 verifier
  resolves it.
- Failures close with close code ``1008`` (policy violation) and a
  short reason string.

The legacy ``?token=…`` query-parameter fallback ships out in v0.5.
For now it is still accepted so existing tests / dev tools work,
but it is **not** recommended for production traffic.
"""

from __future__ import annotations

import asyncio
import json
import os

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/runs", tags=["ws"])


_BEARER_SUBPROTOCOL_PREFIX = "aegis.bearer."


def _origin_allowed(origin: str, settings) -> bool:
    """Return True iff ``origin`` is in the configured CORS allowlist.

    Empty origin is allowed so non-browser clients (CLI, CI, recorded
    integration tests) can attach without forging a header. Browser
    upgrades always carry an ``Origin`` header.
    """
    if not origin:
        return True
    allowed = set(settings.cors_origins or [])
    if settings.web_origin:
        allowed.add(settings.web_origin)
    return origin in allowed


def _extract_bearer_subprotocol(websocket: WebSocket) -> tuple[str | None, str | None]:
    """Return ``(token, subprotocol_to_echo)`` from
    ``Sec-WebSocket-Protocol`` when an ``aegis.bearer.<token>`` entry
    is present, else ``(None, None)``.
    """
    raw = websocket.headers.get("sec-websocket-protocol", "")
    if not raw:
        return (None, None)
    for entry in (s.strip() for s in raw.split(",")):
        if entry.startswith(_BEARER_SUBPROTOCOL_PREFIX):
            return (entry[len(_BEARER_SUBPROTOCOL_PREFIX):], entry)
    return (None, None)


async def _resolve_user_for_ws(websocket: WebSocket, settings):
    """Resolve a CurrentUser from the WS upgrade request.

    Resolution order:
    1. ``Sec-WebSocket-Protocol: aegis.bearer.<token>`` (programmatic).
    2. ``Authorization: Bearer …`` header (works for some clients).
    3. ``aegis_api_session`` cookie (browser path, F14a).
    4. ``?token=…`` query parameter (legacy; removed in v0.5).
    """
    from aegis.api.auth import _resolve_from_cookie, _resolve_from_token

    sub_token, _ = _extract_bearer_subprotocol(websocket)
    if sub_token:
        try:
            return _resolve_from_token(sub_token, settings)
        except Exception:
            return None

    auth = websocket.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        try:
            return _resolve_from_token(auth.split(" ", 1)[1].strip(), settings)
        except Exception:
            return None

    cookie_value = websocket.cookies.get(settings.api_session_cookie_name)
    if cookie_value:
        try:
            return _resolve_from_cookie(cookie_value, settings)
        except Exception:
            return None

    legacy_token = websocket.query_params.get("token", "")
    if legacy_token:
        try:
            return _resolve_from_token(legacy_token, settings)
        except Exception:
            return None

    return None


async def _enforce_upgrade_policy(websocket: WebSocket, run_id: str) -> bool:
    """Return True iff the upgrade should proceed; otherwise close 1008.

    The Origin / subprotocol checks happen *before* ``accept()`` when
    possible (a close-without-accept is the cleanest reject). The
    project-access check runs after accept since it touches the DB.
    """
    from aegis.api.settings import load_settings
    settings = load_settings()

    # 1) Origin check (pre-accept).
    origin = websocket.headers.get("origin", "")
    if not _origin_allowed(origin, settings):
        await websocket.close(code=1008, reason="origin not allowed")
        return False

    # 2) If the client offered the bearer subprotocol, echo it back on
    #    accept(); otherwise accept with no subprotocol negotiation.
    _, sub_echo = _extract_bearer_subprotocol(websocket)
    if sub_echo:
        await websocket.accept(subprotocol=sub_echo)
    else:
        await websocket.accept()

    # 3) Auth + membership (post-accept; close(1008) requires accept()).
    user = await _resolve_user_for_ws(websocket, settings)
    if user is None:
        await websocket.close(code=1008, reason="auth required")
        return False

    from aegis.db.models import Run
    from aegis.db.session import get_session
    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            await websocket.close(code=1008, reason="run not found")
            return False
        project_id = run.project_id
    if not user.is_system and project_id not in user.project_memberships:
        await websocket.close(code=1008, reason="no project membership")
        return False
    return True


async def _redis_pubsub_iter(channel: str):
    """Yield messages from Redis pub/sub; falls back to a no-op loop when
    Redis isn't configured (dev convenience)."""
    url = os.environ.get("AEGIS_BROKER_URL")
    if not url:
        # Keep the connection alive so the UI's reconnect logic stays quiet.
        while True:
            await asyncio.sleep(5)
            yield {"type": "heartbeat"}
    try:
        import redis.asyncio as redis_async
    except ImportError:
        while True:
            await asyncio.sleep(5)
            yield {"type": "heartbeat"}

    client = redis_async.from_url(url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                yield json.loads(message["data"])
            except json.JSONDecodeError:
                yield {"type": "raw", "data": message["data"]}
    finally:
        await pubsub.unsubscribe(channel)
        await client.close()


@router.websocket("/{run_id}/events")
async def events_ws(websocket: WebSocket, run_id: str):
    if not await _enforce_upgrade_policy(websocket, run_id):
        return

    channel = f"run:{run_id}:events"
    try:
        async for event in _redis_pubsub_iter(channel):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
