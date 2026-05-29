"""OIDC + dev-mode authentication."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException, Request, status

from aegis.api.settings import APISettings, load_settings


@dataclass
class CurrentUser:
    sub: str
    email: str
    display_name: str = ""
    project_memberships: dict[str, str] = field(default_factory=dict)
    is_system: bool = False


@lru_cache(maxsize=1)
def _jwks_cache(jwks_url: str) -> dict[str, Any]:
    # Cached for the process lifetime; rotated by restart. For Phase 3 dev
    # this is acceptable.
    with httpx.Client(timeout=5.0) as client:
        resp = client.get(jwks_url)
        resp.raise_for_status()
        return resp.json()


def _verify_jwt(token: str, settings: APISettings) -> dict[str, Any]:
    # We deliberately don't pull in PyJWT just for verification — authlib
    # is in `[api]` extras and handles JWKS validation cleanly.
    from authlib.jose import JoseError, jwt
    if not settings.oidc_jwks_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC not configured: AEGIS_OIDC_JWKS_URL missing",
        )
    jwks = _jwks_cache(settings.oidc_jwks_url)
    try:
        claims = jwt.decode(token, jwks)
        claims.validate(now=int(time.time()))
    except JoseError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"invalid token: {exc}") from exc
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud_ok = aud == settings.oidc_audience
    elif isinstance(aud, list):
        aud_ok = settings.oidc_audience in aud
    else:
        aud_ok = False
    if not aud_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="audience mismatch")
    return dict(claims)


# ----- worker service-account tokens (FW v0.3.1) ----------------------------

def _hmac_sign(secret: str, payload: str) -> str:
    from hashlib import sha256
    from hmac import new as hmac_new
    return hmac_new(secret.encode(), payload.encode(), sha256).hexdigest()


def issue_worker_token(
    worker_id: str,
    *,
    settings: APISettings | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """Mint a time-bound worker service-account token.

    Format: ``worker:v<key_version>.<worker_id>.<exp_ts>.<sig>`` where
    ``sig = HMAC-SHA256(current_signing_key, "v<ver>.<worker_id>.<exp_ts>")``.

    The API verifies the signature against the current key first; if
    that fails it tries the previous key while the overlap window is
    open (``AEGIS_WORKER_KEY_OVERLAP_SECONDS``). Maps to actor
    ``service:worker:<worker_id>`` for audit.
    """
    if settings is None:
        settings = load_settings()
    if not settings.worker_signing_key:
        raise RuntimeError(
            "AEGIS_WORKER_SIGNING_KEY is not set; cannot mint worker tokens"
        )
    ttl = ttl_seconds if ttl_seconds is not None else settings.worker_token_ttl_seconds
    exp = int(time.time()) + ttl
    version = settings.worker_signing_key_version
    payload = f"v{version}.{worker_id}.{exp}"
    sig = _hmac_sign(settings.worker_signing_key, payload)
    return f"worker:{payload}.{sig}"


def _parse_worker_token(token: str) -> tuple[int, str, int, str] | None:
    """Return ``(version, worker_id, exp_ts, sig)`` or ``None`` if malformed.

    Accepts both the new v0.3.1 ``worker:v<n>.<id>.<exp>.<sig>`` format
    and the legacy ``worker:<hex-sig>`` format (Phase 3 demo) so a
    rolling restart isn't a hard cutover.
    """
    rest = token[len("worker:"):]
    parts = rest.split(".")
    if len(parts) == 4 and parts[0].startswith("v"):
        try:
            version = int(parts[0][1:])
            worker_id = parts[1]
            exp = int(parts[2])
            sig = parts[3]
            return version, worker_id, exp, sig
        except ValueError:
            return None
    return None


def _verify_worker_token(token: str, settings: APISettings) -> CurrentUser | None:
    """Validate a worker service-account token.

    Resolution order:

    1. Try the current ``AEGIS_WORKER_SIGNING_KEY`` against ``v<version>``.
    2. If the supplied version is one less than the current and a
       ``AEGIS_WORKER_SIGNING_KEY_PREVIOUS`` is configured, try that key
       while inside the overlap window.
    3. Otherwise reject.
    """
    from hmac import compare_digest

    parsed = _parse_worker_token(token)
    if parsed is None:
        # Legacy static-HMAC path (Phase 3): preserved for a single
        # release-cut overlap; remove once every worker emits v1+ tokens.
        if not settings.worker_signing_key:
            return None
        sig = token[len("worker:"):]
        expected = _hmac_sign(settings.worker_signing_key, "aegis-worker")
        if compare_digest(sig, expected):
            return CurrentUser(
                sub="service:worker:legacy",
                email="worker@aegis.local",
                project_memberships={"default": "admin"},
                is_system=True,
            )
        return None

    version, worker_id, exp, sig = parsed
    now = int(time.time())
    if exp < now:
        return None

    payload = f"v{version}.{worker_id}.{exp}"

    if (settings.worker_signing_key
            and version == settings.worker_signing_key_version):
        expected = _hmac_sign(settings.worker_signing_key, payload)
        if compare_digest(sig, expected):
            return CurrentUser(
                sub=f"service:worker:{worker_id}",
                email=f"worker-{worker_id}@aegis.local",
                project_memberships={"default": "admin"},
                is_system=True,
            )

    if (settings.worker_signing_key_previous
            and version == settings.worker_signing_key_version - 1
            and exp - now <= settings.worker_token_ttl_seconds + settings.worker_key_overlap_seconds):
        expected = _hmac_sign(settings.worker_signing_key_previous, payload)
        if compare_digest(sig, expected):
            return CurrentUser(
                sub=f"service:worker:{worker_id}",
                email=f"worker-{worker_id}@aegis.local",
                project_memberships={"default": "admin"},
                is_system=True,
            )

    return None


def _dev_user(token: str) -> CurrentUser:
    # token format: "dev:<email>"
    _, _, email = token.partition(":")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="dev token missing email after ':'")
    return CurrentUser(
        sub=f"dev:{email}", email=email, display_name=email,
        project_memberships={"default": "admin"},
        is_system=False,
    )


def _resolve_from_token(token: str, settings: APISettings | None = None) -> CurrentUser:
    """Resolve a bearer token to a ``CurrentUser``.

    Extracted from ``get_current_user`` so contexts without a FastAPI
    dependency-injection scope (e.g. the WebSocket upgrade handler in
    F12) can share the same auth logic. Raises ``HTTPException`` on
    invalid / unauthorized tokens — WS callers should catch it and
    close with policy violation.
    """
    if settings is None:
        settings = load_settings()
    token = (token or "").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="empty token")

    if settings.auth_mode == "dev":
        if settings.is_prod:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="dev auth disabled in production",
            )
        if token.startswith("dev:"):
            return _dev_user(token)

    if token.startswith("worker:") and settings.worker_signing_key:
        user = _verify_worker_token(token, settings)
        if user is not None:
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid or expired worker token")

    claims = _verify_jwt(token, settings)
    sub = claims.get("sub") or claims.get("preferred_username") or "anonymous"
    email = claims.get("email") or sub
    roles_map = claims.get("aegis_project_roles") or {}
    if not isinstance(roles_map, dict):
        roles_map = {}
    return CurrentUser(
        sub=str(sub), email=str(email),
        display_name=claims.get("name") or "",
        project_memberships={str(k): str(v) for k, v in roles_map.items()},
    )


def _resolve_from_cookie(cookie_value: str, settings: APISettings) -> CurrentUser:
    """Resolve a session cookie value to a ``CurrentUser`` (F14a).

    Raises ``HTTPException(401)`` on missing keys, malformed payload,
    or expired tokens.
    """
    from aegis.api.session_cookie import SessionCookieError, verify_session_cookie
    try:
        claims = verify_session_cookie(cookie_value, settings)
    except SessionCookieError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=str(exc)) from exc
    return CurrentUser(
        sub=claims.sub, email=claims.email,
        display_name=claims.display_name,
        project_memberships=claims.project_memberships,
    )


def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    settings: APISettings = Depends(load_settings),
) -> CurrentUser:
    """Resolve the caller from header → cookie.

    F14a: when ``Authorization: Bearer …`` is present, that always wins
    (CLI / CI / programmatic). Otherwise, fall back to the configured
    Aegis session cookie minted by the NextAuth callback.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return _resolve_from_token(token, settings)

    cookie_value = request.cookies.get(settings.api_session_cookie_name)
    if cookie_value:
        return _resolve_from_cookie(cookie_value, settings)

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="authentication required")
