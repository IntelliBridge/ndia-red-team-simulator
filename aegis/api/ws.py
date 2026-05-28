"""WebSocket: /v1/runs/{run_id}/events backed by Redis pub/sub.

Phase 4 v0.3.1 F12: every upgrade resolves the requesting user from
the bearer token (or query token, browser-side; cookie auth is
v0.4.0), looks up the run's project, and rejects with close code
1008 unless the user has membership. ``Origin`` hardening and the
``Sec-WebSocket-Protocol`` subprotocol channel ship in v0.4.0 F14c.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/runs", tags=["ws"])


async def _resolve_user_for_ws(websocket: WebSocket):
    """Resolve a CurrentUser from the WS upgrade request.

    Sources, in order: ``Authorization: Bearer …`` header → ``?token=…``
    query parameter (browser-side until v0.4.0 ships cookie auth). Returns
    ``None`` if no auth is supplied so the caller can close with 1008.
    """
    from aegis.api.auth import _resolve_from_token

    auth = websocket.headers.get("authorization") or ""
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = websocket.query_params.get("token", "")
    if not token:
        return None
    try:
        return _resolve_from_token(token)
    except Exception:
        return None


async def _enforce_project_access_ws(websocket: WebSocket, run_id: str) -> bool:
    """Return True iff the upgrade should proceed. Closes the socket on 403."""
    user = await _resolve_user_for_ws(websocket)
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
    # F12: gate the upgrade behind project-access before accepting.
    # We accept first (per Starlette's contract that close() requires
    # accept()), then close with policy violation if unauthorized.
    await websocket.accept()
    if not await _enforce_project_access_ws(websocket, run_id):
        return

    channel = f"run:{run_id}:events"
    try:
        async for event in _redis_pubsub_iter(channel):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
