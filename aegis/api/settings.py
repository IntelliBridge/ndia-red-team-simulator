"""API settings (Pydantic BaseSettings shape, env-driven)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [s.strip() for s in raw.split(",") if s.strip()]


@dataclass
class APISettings:
    env: str = field(default_factory=lambda: os.environ.get("AEGIS_ENV", "dev"))
    auth_mode: str = field(
        default_factory=lambda: os.environ.get("AEGIS_AUTH_MODE", "dev")
    )
    db_url: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_DB_URL")
    )
    oidc_issuer: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_OIDC_ISSUER")
    )
    oidc_audience: str = field(
        default_factory=lambda: os.environ.get("AEGIS_OIDC_AUDIENCE", "aegis")
    )
    oidc_jwks_url: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_OIDC_JWKS_URL")
    )
    # Aegis-side cookie session key (F14a). The NextAuth callback signs;
    # FastAPI verifies. RS256, separate from Keycloak's JWKS and from
    # NEXTAUTH_SECRET. The private side is only required where minting
    # happens (the same process if we're test-minting; the NextAuth
    # callback in production); the public side is what FastAPI needs.
    api_session_private_key: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_API_SESSION_PRIVATE_KEY")
    )
    api_session_public_key: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_API_SESSION_PUBLIC_KEY")
    )
    api_session_key_id: str = field(
        default_factory=lambda: os.environ.get(
            "AEGIS_API_SESSION_KEY_ID", "aegis-api-session-v1"
        )
    )
    api_session_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AEGIS_API_SESSION_TTL_SECONDS", "900")
        )
    )
    api_session_cookie_name: str = field(
        default_factory=lambda: os.environ.get(
            "AEGIS_API_SESSION_COOKIE", "aegis_api_session"
        )
    )
    api_csrf_cookie_name: str = field(
        default_factory=lambda: os.environ.get(
            "AEGIS_CSRF_COOKIE", "aegis_csrf"
        )
    )
    api_csrf_header_name: str = field(
        default_factory=lambda: os.environ.get(
            "AEGIS_CSRF_HEADER", "X-Aegis-CSRF"
        )
    )
    web_origin: str = field(
        default_factory=lambda: os.environ.get(
            "AEGIS_WEB_ORIGIN", "http://localhost:3000"
        )
    )

    worker_signing_key: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_WORKER_SIGNING_KEY")
    )
    worker_signing_key_previous: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_WORKER_SIGNING_KEY_PREVIOUS")
    )
    worker_signing_key_version: int = field(
        default_factory=lambda: int(
            os.environ.get("AEGIS_WORKER_SIGNING_KEY_VERSION", "1")
        )
    )
    worker_key_overlap_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AEGIS_WORKER_KEY_OVERLAP_SECONDS", "300")
        )
    )
    worker_token_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AEGIS_WORKER_TOKEN_TTL_SECONDS", "300")
        )
    )
    cors_origins: list[str] = field(
        default_factory=lambda: _env_list("AEGIS_CORS_ORIGINS",
                                          ["http://localhost:3000"])
    )
    blob_backend: str = field(
        default_factory=lambda: os.environ.get("AEGIS_BLOB_BACKEND", "fs")
    )
    output_dir: str = field(
        default_factory=lambda: os.environ.get("AEGIS_OUTPUT_DIR",
                                               "./aegis_output")
    )
    rate_limit_per_user_per_min: int = field(
        default_factory=lambda: int(os.environ.get("AEGIS_RL_USER_PER_MIN", "30"))
    )
    rate_limit_per_project_per_min: int = field(
        default_factory=lambda: int(os.environ.get("AEGIS_RL_PROJECT_PER_MIN", "120"))
    )

    @property
    def is_prod(self) -> bool:
        return self.env.lower() == "prod"


def load_settings() -> APISettings:
    return APISettings()
