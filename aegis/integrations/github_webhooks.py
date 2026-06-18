"""GitHub webhook receiver with HMAC verification + replay protection."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

router = APIRouter(prefix="/webhooks/github", tags=["github-webhooks"])


_RECENT_DELIVERIES: dict[str, float] = {}
_REPLAY_TTL_SEC = 600


def _expected_signature(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def _verify_signature(body: bytes, signature_header: str | None) -> None:
    secret = os.environ.get("AEGIS_GITHUB_WEBHOOK_SECRET", "").encode()
    if not secret:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="webhook secret not configured")
    if not signature_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="missing X-Hub-Signature-256")
    expected = _expected_signature(secret, body)
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="signature mismatch")


def _check_replay(delivery_id: str | None) -> bool:
    """Return True iff this delivery was already seen recently."""
    if not delivery_id:
        return False
    now = time.time()
    # Prune.
    for k, ts in list(_RECENT_DELIVERIES.items()):
        if now - ts > _REPLAY_TTL_SEC:
            del _RECENT_DELIVERIES[k]
    if delivery_id in _RECENT_DELIVERIES:
        return True
    _RECENT_DELIVERIES[delivery_id] = now
    return False


@router.post("")
async def receive(request: Request) -> dict[str, Any]:
    body = await request.body()
    _verify_signature(body, request.headers.get("X-Hub-Signature-256"))
    delivery_id = request.headers.get("X-GitHub-Delivery")
    if _check_replay(delivery_id):
        return {"detail": "replay (no-op)"}
    event = request.headers.get("X-GitHub-Event", "")
    import json
    payload = json.loads(body or b"{}")

    handler_result: dict[str, Any] = {}
    if event == "pull_request":
        from aegis.integrations.github_handlers import on_pull_request_event
        handler_result = on_pull_request_event(payload)

    return {
        "event": event,
        "delivery_id": delivery_id,
        "action": payload.get("action"),
        "received": True,
        **handler_result,
    }
