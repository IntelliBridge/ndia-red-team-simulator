"""Publish run/job lifecycle events to the Redis channel the WebSocket
endpoint subscribes to.

``redsim.api.ws`` serves ``/v1/runs/{run_id}/events`` by subscribing to the Redis
pub/sub channel ``run:{run_id}:events``. Until now nothing ever published to it,
so the frontend could only *poll* for run status. The worker's ``task_context``
(``redsim.workers.bootstrap``) calls :func:`publish_job_event` on each job state
transition so the UI gets live updates.

Publishing is **best-effort**: a broker hiccup must never fail (or retry) the
job that triggered the event — Postgres remains the source of truth for status,
the event stream is a real-time convenience on top of it. Every failure is
swallowed and logged.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_client: Any = None
_client_url: str | None = None


def _redis_client() -> Any:
    """Return a cached synchronous Redis client, or ``None`` if unavailable.

    Cached per broker URL for the life of the worker process (redis-py clients
    are thread-safe and pool connections). Returns ``None`` when redis isn't
    installed so callers degrade to a no-op rather than raising.
    """
    global _client, _client_url
    url = os.environ.get("REDSIM_BROKER_URL", "redis://localhost:6379/0")
    if _client is not None and _client_url == url:
        return _client
    try:
        import redis
    except ImportError:
        return None
    _client = redis.Redis.from_url(url)
    _client_url = url
    return _client


def publish_job_event(run_id: str, job_id: str, status: str, **extra: Any) -> None:
    """Publish a job-transition event to ``run:{run_id}:events`` (best-effort).

    ``status`` is one of ``running`` / ``succeeded`` / ``failed``. Any extra
    keyword args are merged into the JSON payload. Never raises.
    """
    payload = {"type": "job", "run_id": run_id, "job_id": job_id, "status": status, **extra}
    try:
        client = _redis_client()
        if client is None:
            return
        client.publish(f"run:{run_id}:events", json.dumps(payload))
    except Exception:
        logger.warning(
            "event publish failed (run=%s job=%s status=%s)",
            run_id, job_id, status, exc_info=True,
        )
