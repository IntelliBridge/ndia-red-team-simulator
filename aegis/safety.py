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
) -> None:
    """Authorize an active operation.

    - When `target` is None, the action is host-independent (e.g., local patch apply).
    - Hosts in the allowlist always pass.
    - Hosts outside the allowlist require `override_authorized=True`
      (mapped from `--i-understand-this-target-is-authorized`).

    Emits an audit record to `run_path/audit.jsonl` when run_path is supplied.
    """
    detail = detail or {}
    ts = datetime.now(timezone.utc).isoformat()

    if target is None:
        if run_path is not None:
            _append_audit(
                run_path,
                AuditEvent(ts, action, None, "n/a", override_authorized, True, detail),
            )
        return

    allowed = is_target_allowed(target, allowlist)
    if not allowed and not override_authorized:
        if run_path is not None:
            _append_audit(
                run_path,
                AuditEvent(ts, action, target, "fail", False, False, detail),
            )
        raise AuthorizationError(
            f"Target '{target}' is not in the allowlist {allowlist}. "
            f"Add it to target_allowlist in aegis.yaml or pass "
            f"--i-understand-this-target-is-authorized."
        )

    if run_path is not None:
        _append_audit(
            run_path,
            AuditEvent(
                ts,
                action,
                target,
                "pass" if allowed else "override",
                override_authorized and not allowed,
                True,
                detail,
            ),
        )
