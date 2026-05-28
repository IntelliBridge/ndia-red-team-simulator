"""WebSocket: /v1/runs/{run_id}/events backed by Redis pub/sub."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/runs", tags=["ws"])


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
    await websocket.accept()
    channel = f"run:{run_id}:events"
    try:
        async for event in _redis_pubsub_iter(channel):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
