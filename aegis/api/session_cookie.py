"""Aegis-signed API session cookie (Phase 4 v0.4.0 F14a).

NextAuth owns the browser session. After Keycloak login, the NextAuth
callback mints an additional cookie — ``aegis_api_session`` — signed
with an Aegis-managed RSA key. FastAPI verifies that cookie against
the Aegis public key on every request; we do **not** try to verify
NextAuth's own session JWT (it's signed with ``NEXTAUTH_SECRET``,
which FastAPI doesn't have).

The CLI / CI bearer-token path is unchanged. Cookie auth is only
used by browsers; ``Authorization: Bearer ...`` wins when both are
present.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

from authlib.jose import JoseError, jwt

from aegis.api.settings import APISettings


class SessionCookieError(Exception):
    """Raised when a session cookie is missing, malformed, or invalid."""


@dataclass
class SessionClaims:
    sub: str
    email: str
    display_name: str
    project_memberships: dict[str, str]
    iat: int
    exp: int
    jti: str


def _ensure_key(value: str | None, *, label: str) -> str:
    if not value:
        raise SessionCookieError(
            f"{label} is not configured. Set the Aegis API session keypair "
            "env vars (AEGIS_API_SESSION_PRIVATE_KEY / "
            "AEGIS_API_SESSION_PUBLIC_KEY) before serving cookie auth."
        )
    return value


def mint_session_cookie(
    *,
    sub: str,
    email: str,
    display_name: str = "",
    project_memberships: dict[str, str] | None = None,
    settings: APISettings,
    ttl_seconds: int | None = None,
) -> str:
    """Sign a JWT for the API session cookie.

    Returns the encoded JWT; the caller is responsible for setting it
    as an httpOnly + secure (in prod) + sameSite=Lax cookie on the
    appropriate response.
    """
    private = _ensure_key(settings.api_session_private_key,
                          label="AEGIS_API_SESSION_PRIVATE_KEY")
    ttl = ttl_seconds if ttl_seconds is not None else settings.api_session_ttl_seconds
    now = int(time.time())
    payload = {
        "iss": "aegis-api-session",
        "aud": "aegis-api",
        "sub": sub,
        "email": email,
        "name": display_name,
        "aegis_project_roles": project_memberships or {},
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    header = {"alg": "RS256", "kid": settings.api_session_key_id}
    token = jwt.encode(header, payload, private)
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return cast(str, token)


def _decode_with_key(value: str, public_key: str) -> Any:
    """Decode + time-validate ``value`` against a single public key.

    Returns the authlib claims object; raises ``JoseError`` if the
    signature does not verify or the token is expired/not-yet-valid.
    """
    claims = jwt.decode(value, public_key)
    claims.validate(now=int(time.time()))
    return claims


def verify_session_cookie(value: str, settings: APISettings) -> SessionClaims:
    """Verify the JWT against the Aegis public key.

    Tries the current ``AEGIS_API_SESSION_PUBLIC_KEY`` first, then the
    previous key (``AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS``) if one is
    configured, so cookies minted just before a key rotation keep
    verifying through the overlap window. Minting always uses the
    current key. Mirrors the worker-token signing-key overlap.

    Raises ``SessionCookieError`` if the cookie is missing keys, expired,
    or signed by a key that is neither the current nor the previous one.
    """
    public = _ensure_key(settings.api_session_public_key,
                         label="AEGIS_API_SESSION_PUBLIC_KEY")
    candidates = [public]
    if settings.api_session_public_key_previous:
        candidates.append(settings.api_session_public_key_previous)

    claims = None
    last_error: JoseError | None = None
    for key in candidates:
        try:
            claims = _decode_with_key(value, key)
            break
        except JoseError as exc:
            last_error = exc
    if claims is None:
        raise SessionCookieError(
            f"invalid session cookie: {last_error}"
        ) from last_error

    aud = claims.get("aud")
    if aud != "aegis-api":
        raise SessionCookieError("session cookie audience mismatch")
    iss = claims.get("iss")
    if iss != "aegis-api-session":
        raise SessionCookieError("session cookie issuer mismatch")

    memberships_raw = claims.get("aegis_project_roles") or {}
    if not isinstance(memberships_raw, dict):
        memberships_raw = {}
    return SessionClaims(
        sub=str(claims.get("sub") or ""),
        email=str(claims.get("email") or ""),
        display_name=str(claims.get("name") or ""),
        project_memberships={str(k): str(v) for k, v in memberships_raw.items()},
        iat=int(claims.get("iat", 0)),
        exp=int(claims.get("exp", 0)),
        jti=str(claims.get("jti") or ""),
    )


def generate_keypair() -> tuple[str, str]:
    """Return a fresh (private_pem, public_pem) RSA keypair.

    Used by the test helpers and by ``aegis api-session-keys generate``
    bootstrap (lands in v0.4.0 ops scripts). Production keys are
    rotated out-of-band; this exists so tests don't ship a hard-coded
    private key.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem
