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
    worker_signing_key: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_WORKER_SIGNING_KEY")
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
