"""Central authorization gate, target allowlist, and audit log for Aegis."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
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


@dataclass
class AuditEvent:
    ts: str
    action: str
    target: str | None
    allowlist_check: str  # "pass" | "fail" | "n/a"
    override: bool
    success: bool
    detail: dict[str, Any]


def _append_audit(run_path: Path, event: AuditEvent) -> None:
    audit_path = run_path / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": event.ts,
        "action": event.action,
        "target": event.target,
        "allowlist_check": event.allowlist_check,
        "override": event.override,
        "success": event.success,
        "detail": event.detail,
    }
    with open(audit_path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


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
    """Authorize an active operation.

    Phase 2 behaviour (when ``writer`` is None) is unchanged: an entry is
    appended to ``<run_path>/audit.jsonl`` as a flat record. The Phase 3
    hash-chained writer (``aegis.audit.chain.AuditWriter``) can be injected
    via ``writer``; when present, audit events go through the chain and the
    flat JSONL is skipped.
    """
    detail = dict(detail or {})
    if actor is not None and "actor" not in detail:
        detail["actor"] = actor
    actor_str = actor or "cli:anonymous"
    ts = datetime.now(timezone.utc).isoformat()

    def _emit(allowlist_check: str, override: bool, success: bool) -> None:
        if writer is not None:
            writer.append(
                action=action, actor=actor_str, target=target,
                allowlist_check=allowlist_check,
                override=override, success=success, detail=detail,
                run_id=run_id, project_id=project_id,
            )
            return
        if run_path is not None:
            _append_audit(
                run_path,
                AuditEvent(ts, action, target, allowlist_check,
                           override, success, detail),
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
