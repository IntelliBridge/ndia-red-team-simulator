"""Centralized redaction of audit-event detail payloads.

Strips credentials, tokens, and other sensitive material before the chain
writer commits the event. All audit writers route detail through this; any
other consumer that surfaces detail should do the same.
"""

from __future__ import annotations

import re
from typing import Any


_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "session", "session_token", "authorization",
    "auth", "cookie", "set-cookie", "proxy-authorization",
}

_SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key",
}

# Common token / key signatures. Conservative: prefer false positives.
_TOKEN_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                 # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),                 # AWS temp creds
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),              # GitHub PAT
    re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),              # GitHub OAuth
    re.compile(r"\bghu_[A-Za-z0-9]{36}\b"),              # GitHub user-to-server
    re.compile(r"\bghs_[A-Za-z0-9]{36}\b"),              # GitHub server-to-server
    re.compile(r"\bghr_[A-Za-z0-9]{76}\b"),              # GitHub refresh
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),     # Slack
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),              # OpenAI-style
]


def _is_sensitive_key(key: str) -> bool:
    k = key.lower().replace("-", "_")
    if k in _SENSITIVE_KEYS:
        return True
    return any(s in k for s in ("token", "secret", "password", "api_key", "apikey"))


def _redact_str(value: str) -> str:
    out = value
    for pat in _TOKEN_PATTERNS:
        out = pat.sub("<REDACTED>", out)
    return out


def _redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADER_NAMES:
            out[k] = "<REDACTED>"
        else:
            out[k] = v
    return out


def redact_audit_detail(detail: Any) -> Any:
    """Walk the detail payload and redact sensitive material in place."""
    if isinstance(detail, dict):
        cleaned: dict[str, Any] = {}
        for k, v in detail.items():
            if _is_sensitive_key(k):
                cleaned[k] = "<REDACTED>"
            elif k.lower() == "headers" and isinstance(v, dict):
                cleaned[k] = _redact_headers(v)
            else:
                cleaned[k] = redact_audit_detail(v)
        return cleaned
    if isinstance(detail, list):
        return [redact_audit_detail(item) for item in detail]
    if isinstance(detail, str):
        return _redact_str(detail)
    return detail
