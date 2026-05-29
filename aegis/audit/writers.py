"""Audit writer mode helpers (Phase 4 v0.3.1 F7).

Every Aegis caller mode resolves to one ``AuditWriter`` instance:

- **offline** (no ``AEGIS_DB_URL``): ``JsonlAuditWriter`` rooted under
  ``<output_dir>/audit/``.
- **api** / **worker** (``AEGIS_DB_URL`` set): ``PostgresAuditWriter``.
- **test**: ``InMemoryAuditWriter`` — collects events in a list for
  assertions.

This module replaces the flat ``aegis.safety._append_audit`` helper that
shipped with Phase 3. Phase 4 service/api/worker callers should always
pass an explicit ``AuditWriter`` to ``authorize()``; the implicit
default below is a migration shim that goes away once F3 (CLI through
services) + F6 (admission services) wire writers at every call site.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator, Literal

from aegis.audit.chain import (
    AuditEvent,
    AuditWriter,
    JsonlAuditWriter,
    PostgresAuditWriter,
)

Mode = Literal["offline", "api", "worker", "test"]


def open_writer(
    mode: Mode | None = None,
    *,
    output_dir: str | Path | None = None,
    session_factory=None,
) -> AuditWriter:
    """Return the canonical ``AuditWriter`` for ``mode``.

    When ``mode`` is omitted, the active mode is inferred from env:
    ``AEGIS_TEST_AUDIT=memory`` → in-memory; ``AEGIS_DB_URL`` set →
    Postgres; otherwise the offline JSONL backend rooted at
    ``output_dir / audit``.
    """
    if mode is None:
        if os.environ.get("AEGIS_TEST_AUDIT") == "memory":
            mode = "test"
        elif os.environ.get("AEGIS_DB_URL"):
            mode = "api"
        else:
            mode = "offline"

    if mode == "offline":
        if output_dir is None:
            output_dir = os.environ.get("AEGIS_OUTPUT_DIR", "./aegis_output")
        return JsonlAuditWriter(Path(output_dir) / "audit")
    if mode in ("api", "worker"):
        if session_factory is None:
            from aegis.db.session import get_session, init_engine
            init_engine()
            session_factory = get_session
        return PostgresAuditWriter(session_factory=session_factory)
    if mode == "test":
        return InMemoryAuditWriter()
    raise ValueError(f"unknown audit writer mode: {mode!r}")


class InMemoryAuditWriter:
    """Test-only writer that collects events into ``self.events`` for
    assertions. Implements the ``AuditWriter`` Protocol.
    """

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._chains: dict[str, list[dict[str, Any]]] = {}

    def _chain_id(self, project_id: str | None, run_id: str | None) -> str:
        if run_id:
            return f"run:{run_id}"
        if project_id:
            return f"project:{project_id}"
        return "system"

    def append(self, *, action: str, actor: str, target: str | None,
               allowlist_check: str, override: bool, success: bool,
               detail: dict[str, Any],
               run_id: str | None = None,
               project_id: str | None = None) -> AuditEvent:
        from datetime import datetime, timezone
        chain_id = self._chain_id(project_id, run_id)
        seq = len(self._chains.get(chain_id, [])) + 1
        event = AuditEvent(
            chain_id=chain_id, seq=seq,
            ts=datetime.now(timezone.utc).isoformat(),
            actor=actor, action=action, target=target,
            allowlist_check=allowlist_check, override=override,
            success=success, detail=dict(detail or {}),
            run_id=run_id, project_id=project_id,
        )
        self.events.append(event)
        self._chains.setdefault(chain_id, []).append(event.to_record())
        return event

    def read_chain(self, chain_id: str) -> Iterator[dict[str, Any]]:
        return iter(self._chains.get(chain_id, []))

    def iter_chain_ids(self) -> Iterator[str]:
        return iter(self._chains.keys())
