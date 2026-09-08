"""Central authorization gate, target allowlist, and audit emission.

Every audit event goes through an ``AuditWriter`` (``aegis.audit.chain``)
— the chain is the only backend; the flat ``_append_audit`` helper is
gone. ``authorize()`` resolves its writer one of two ways:

- **Explicit** (``writer=``): request-scoped callers — the admission
  services and worker tasks — pass the writer ``resolve_writer`` selected
  (Postgres or JSONL). Every API write route takes this path.
- **run_path-derived** (``run_path=``): offline / execution-half callers
  (the CLI, ``start_scan`` / ``verify``) pass the run directory; the safety layer opens a single-file
  ``JsonlAuditWriter`` at ``<run_path>/audit.jsonl``.

Passing neither is a programmer error and raises ``ValueError`` — there
is no silent no-op audit path.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from aegis.audit.chain import AuditWriter


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


def _resolve_writer(writer: AuditWriter | None, run_path: Path | None) -> AuditWriter:
    """Return an ``AuditWriter`` for ``authorize()``.

    Explicit ``writer`` wins. Otherwise a ``run_path`` yields a single-file
    ``JsonlAuditWriter`` at ``<run_path>/audit.jsonl`` — the location
    offline callers (CLI, tests) expect. Passing neither is a
    programmer error: there is no silent no-op audit destination.
    """
    if writer is not None:
        return writer
    if run_path is None:
        raise ValueError(
            "authorize() requires an audit destination: pass an explicit "
            "writer= (request-scoped callers) or run_path= (offline callers)."
        )
    from aegis.audit.chain import JsonlAuditWriter
    return JsonlAuditWriter(run_path, single_file="audit.jsonl")


def authorize(
    action: str,
    target: str | None,
    *,
    allowlist: list[str],
    run_path: Path | None = None,
    override_authorized: bool = False,
    detail: dict[str, Any] | None = None,
    actor: str | None = None,
    writer: AuditWriter | None = None,
    run_id: str | None = None,
    project_id: str | None = None,
) -> None:
    """Authorize an active operation and emit a single audit event.

    Resolution: ``writer`` if supplied; else a single-file
    ``JsonlAuditWriter`` at ``<run_path>/audit.jsonl`` if ``run_path`` is
    supplied; passing neither raises ``ValueError`` (see
    ``_resolve_writer``).

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
