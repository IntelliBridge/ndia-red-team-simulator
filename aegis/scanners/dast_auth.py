"""Shared authenticated-DAST helpers for the ZAP / Nuclei adapters.

Translates the worker-resolved auth dict (the
``aegis.services.auth_profiles.resolve_auth_for_scan`` contract:
``{"kind": ..., "config": {...}, "secret": ...}``) into a single HTTP
header the scanner replays on every request.

SECRET HANDLING: the plaintext secret only ever lives in the returned
header *value*. Callers must keep that value out of recorded command
strings, logs, persisted artifacts, and audit detail — redact it with
``REDACTED`` anywhere a command is recorded. ``DastAuthError`` messages
are always secret-free (they may name the kind, the login URL, and the
failure class; never the secret itself).
"""

from __future__ import annotations

from typing import Any

REDACTED = "***"

_FORM_LOGIN_TIMEOUT = 30.0


class DastAuthError(Exception):
    """Auth material could not be turned into a usable header.

    Raised with secret-free messages only — safe to persist on a
    ``ScanResult.error`` / job error column.
    """


def form_login_cookie_header(config: dict[str, Any], secret: str) -> str:
    """POST the login form and fold the ``Set-Cookie`` response into a header.

    Returns the ``Cookie`` header *value* (``name=value; name2=value2``)
    built from the cookies the login endpoint set. Redirects are not
    followed: session cookies almost always ride on the login response
    itself (often a 302). Raises ``DastAuthError`` when the request
    fails, the server rejects the login, or no cookies come back.
    """
    import httpx

    login_url = config.get("login_url")
    if not login_url:
        raise DastAuthError("form auth config missing login_url")
    data = {
        config.get("username_field", "username"): config.get("username", ""),
        config.get("password_field", "password"): secret,
    }
    try:
        resp = httpx.post(login_url, data=data,
                          follow_redirects=False,
                          timeout=_FORM_LOGIN_TIMEOUT)
    except httpx.HTTPError as exc:
        raise DastAuthError(
            f"form login request to {login_url} failed: {type(exc).__name__}"
        ) from exc
    if resp.status_code >= 400:
        raise DastAuthError(
            f"form login to {login_url} returned HTTP {resp.status_code}"
        )
    cookies = dict(resp.cookies)
    if not cookies:
        raise DastAuthError(
            f"form login to {login_url} set no session cookies"
        )
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def auth_header(auth: dict[str, Any]) -> tuple[str, str]:
    """Map the resolved auth dict to a single ``(header_name, value)`` pair.

    * ``bearer`` → ``("Authorization", "Bearer <secret>")``
    * ``header`` → ``(config["header_name"], <secret>)``
    * ``cookie`` → ``("Cookie", "<cookie_name>=<secret>")``
    * ``form``   → pre-flight login POST, then ``("Cookie", <captured>)``

    The returned value contains the plaintext secret — never record it.
    """
    kind = auth.get("kind")
    config = auth.get("config") or {}
    secret = auth.get("secret") or ""
    if kind == "bearer":
        return "Authorization", f"Bearer {secret}"
    if kind == "header":
        name = config.get("header_name")
        if not name:
            raise DastAuthError("header auth config missing header_name")
        return str(name), secret
    if kind == "cookie":
        name = config.get("cookie_name")
        if not name:
            raise DastAuthError("cookie auth config missing cookie_name")
        return "Cookie", f"{name}={secret}"
    if kind == "form":
        return "Cookie", form_login_cookie_header(config, secret)
    raise DastAuthError(f"unsupported auth kind: {kind!r}")
