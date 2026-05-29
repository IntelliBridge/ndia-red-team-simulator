"""Forensic audit-row builders.

Phase 4 v0.3.1 F8: tool / agent / scanner invocations must record
forensic detail (digests, refs, params) without putting raw stdout or
stderr into the audit row itself. Large output goes to the blob store;
the audit row carries only the descriptor.

This module owns the canonical shape of those detail dicts so the
description doesn't drift across call sites.
"""

from __future__ import annotations

import hashlib
from typing import Any

# Hard cap on audit-row attribute payload size in bytes. Oversize ``attrs``
# spill to the blob store with only the digest + ref in the audit row.
MAX_AUDIT_ATTRS_BYTES = 64 * 1024


def _sha256(data: str | bytes) -> str:
    """Stable sha256 hex over a str / bytes payload."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def tool_detail(
    *,
    tool: str,
    params: dict[str, Any],
    return_code: int,
    duration_ms: int,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    artifact_refs: list[dict[str, Any]] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build the canonical ``detail`` dict for a tool-invocation audit row.

    ``stdout`` / ``stderr`` are reduced to sha256 digests + lengths;
    callers that want full output keep it in the blob store and reference
    it via ``artifact_refs`` (``[{"sha256": ..., "location": ..., "kind": ...}]``).
    """
    detail: dict[str, Any] = {
        "tool": tool,
        "params": _redact_params(params or {}),
        "return_code": return_code,
        "duration_ms": duration_ms,
    }
    if stdout is not None:
        s = stdout if isinstance(stdout, (bytes, str)) else str(stdout)
        detail["stdout_sha256"] = _sha256(s)
        detail["stdout_bytes"] = len(s.encode() if isinstance(s, str) else s)
    if stderr is not None:
        s = stderr if isinstance(stderr, (bytes, str)) else str(stderr)
        detail["stderr_sha256"] = _sha256(s)
        detail["stderr_bytes"] = len(s.encode() if isinstance(s, str) else s)
    if artifact_refs:
        detail["artifact_refs"] = artifact_refs
    if request_id:
        detail["request_id"] = request_id
    return detail


def _redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Lightweight redaction of obvious sensitive fields in tool params.

    The audit chain already runs ``redact_audit_detail`` (recursive
    secret-key scrub) at write-time; this function only normalises
    common scanner-side names (e.g. nmap's ``--script-args``) and
    truncates extremely long values so the audit row stays compact.
    """
    out: dict[str, Any] = {}
    for k, v in params.items():
        if isinstance(v, str) and len(v) > 1024:
            out[k] = v[:1024] + f"...<truncated {len(v) - 1024} bytes>"
        else:
            out[k] = v
    return out
