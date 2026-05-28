"""OIDC + dev-mode authentication."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException, status

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
    from authlib.jose import jwt, JoseError
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


def get_current_user(
    authorization: str | None = Header(default=None),
    settings: APISettings = Depends(load_settings),
) -> CurrentUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Bearer token required")
    token = authorization.split(" ", 1)[1].strip()

    if settings.auth_mode == "dev":
        if settings.is_prod:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="dev auth disabled in production",
            )
        if token.startswith("dev:"):
            return _dev_user(token)

    if token.startswith("worker:") and settings.worker_signing_key:
        # ``worker:<hmac>`` — the worker bootstrap signs with the shared key.
        from hmac import compare_digest, new as hmac_new
        from hashlib import sha256
        sig = token.split(":", 1)[1]
        expected = hmac_new(settings.worker_signing_key.encode(),
                            b"aegis-worker", sha256).hexdigest()
        if compare_digest(sig, expected):
            return CurrentUser(
                sub="system:worker", email="worker@aegis.local",
                project_memberships={"default": "admin"},
                is_system=True,
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid worker token")

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
