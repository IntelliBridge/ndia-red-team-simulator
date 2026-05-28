"""Central authorization gate, target allowlist, and audit emission.

Phase 4 v0.3.1 F7: the flat ``_append_audit`` helper is gone. Every audit
event goes through an ``AuditWriter`` (``aegis.audit.chain``) — the chain
is now the only backend. When ``authorize()`` is called without an
explicit ``writer`` but with a ``run_path``, the safety layer constructs
the offline ``JsonlAuditWriter`` on demand; this is the migration shim
that F3 (CLI-through-services) + F6 (admission services) will retire by
threading an explicit writer at every call site. After F6, calling
``authorize()`` with neither ``writer`` nor ``run_path`` will raise.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class AuthorizationError(Exception):
    """Raised when an active operation is rejected by the safety gate."""


_LOOPBACK_HOSTS = {"localhost", "host.docker.internal"}


def _extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target.split(":", 1)[0]).strip("[]")


def is_target_allowed(target: str, allowlist: list[str]) -> bool:
    """Return True if target's host is in the allowlist (exact match or CIDR membership)."""
    host = _extract_host(target)
    for allowed in allowlist:
        if host == allowed:
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(allowed, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_loopback(target: str) -> bool:
    host = _extract_host(target)
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _resolve_writer(writer, run_path: Path | None):
    """Return an ``AuditWriter`` for ``authorize()``.

    Explicit ``writer`` always wins. Otherwise, when ``run_path`` is
    supplied we construct a ``JsonlAuditWriter`` in single-file mode at
    ``<run_path>/audit.jsonl`` — matching the Phase 2 / Phase 3 location
    so existing callers (CLI, demo, tests) keep finding the chain where
    they expect it. F3 + F6 will move every call site to pass an
    explicit writer; this fallback goes away in v0.3.1's release-gate
    cleanup.

    When neither ``writer`` nor ``run_path`` is supplied, ``authorize()``
    returns to a NO-OP path — preserved so tests that don't care about
    audit don't break. Removed after F3+F6.
    """
    if writer is not None:
        return writer
    if run_path is None:
        return _NullWriter()
    from aegis.audit.chain import JsonlAuditWriter
    return JsonlAuditWriter(run_path, single_file="audit.jsonl")


class _NullWriter:
    """No-op writer used when no audit destination is configured. The
    Phase 4 plan removes the no-writer path after F3+F6; until then,
    keeping it ensures tests that call ``authorize()`` without setting
    up a writer don't silently break."""
    def append(self, **kwargs) -> None:  # noqa: D401 — match Protocol
        return None
    def read_chain(self, chain_id: str):
        return iter(())
    def iter_chain_ids(self):
        return iter(())


def authorize(
    action: str,
    target: str | None,
    *,
    allowlist: list[str],
    run_path: Path | None = None,
    override_authorized: bool = False,
    detail: dict[str, Any] | None = None,
    actor: str | None = None,
    writer=None,
    run_id: str | None = None,
    project_id: str | None = None,
) -> None:
    """Authorize an active operation and emit a single audit event.

    Resolution: ``writer`` if supplied; else a ``JsonlAuditWriter`` rooted
    at ``run_path.parent.parent/audit`` if ``run_path`` is supplied; else
    a null writer (Phase 4 transitional — to be removed by F3+F6).

    The audit event always goes through the ``AuditWriter`` Protocol —
    the legacy ``_append_audit`` flat-JSONL helper is gone.
    """
    detail = dict(detail or {})
    if actor is not None and "actor" not in detail:
        detail["actor"] = actor
    actor_str = actor or "cli:anonymous"
    resolved_writer = _resolve_writer(writer, run_path)

    def _emit(allowlist_check: str, override: bool, success: bool) -> None:
        resolved_writer.append(
            action=action, actor=actor_str, target=target,
            allowlist_check=allowlist_check,
            override=override, success=success, detail=detail,
            run_id=run_id, project_id=project_id,
        )

    if target is None:
        _emit("n/a", override_authorized, True)
        return

    allowed = is_target_allowed(target, allowlist)
    if not allowed and not override_authorized:
        _emit("fail", False, False)
        raise AuthorizationError(
            f"Target '{target}' is not in the allowlist {allowlist}. "
            f"Add it to target_allowlist in aegis.yaml or pass "
            f"--i-understand-this-target-is-authorized."
        )

    _emit("pass" if allowed else "override",
          override_authorized and not allowed, True)
