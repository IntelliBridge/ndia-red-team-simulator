"""`aegis status` — prints active backends and connectivity."""

from __future__ import annotations

import os
import sys

from aegis.config import AegisConfig

_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _kv(label: str, value: str, *, color: str = "") -> None:
    if color:
        print(f"  {label:<18} {color}{value}{_RESET}")
    else:
        print(f"  {label:<18} {value}")


def cmd_status(_args, config: AegisConfig) -> None:
    api_url = os.environ.get("AEGIS_API_URL", "")
    mode = os.environ.get("AEGIS_MODE", "filesystem")
    db_url = os.environ.get("AEGIS_DB_URL", "")
    blob_backend = os.environ.get("AEGIS_BLOB_BACKEND", "fs")
    oidc_issuer = os.environ.get("AEGIS_OIDC_ISSUER", "")
    auth_mode = os.environ.get("AEGIS_AUTH_MODE", "dev")
    env = os.environ.get("AEGIS_ENV", "dev")

    state_backend = "postgres" if db_url else "filesystem"
    audit_backend = "postgres-chain" if db_url else "jsonl"

    print(f"{_BOLD}Aegis status{_RESET}")
    _kv("mode", mode, color=_GREEN if mode == "filesystem" else _YELLOW)
    _kv("env", env)
    _kv("state backend", state_backend)
    _kv("audit backend", audit_backend)
    _kv("blob backend", blob_backend)
    _kv("api url", api_url or "(not set)")
    _kv("db url", db_url or "(not set)")
    _kv("oidc issuer", oidc_issuer or "(not set)")
    _kv("auth mode", auth_mode, color=_YELLOW if auth_mode == "dev" else "")
    _kv("model (default)", config.model)
    _kv("strix path", config.strix_path)
    _kv("cai path", config.cai_path)
    _kv("kali url", config.mcp_kali_url)
    _kv("target allowlist", ", ".join(config.target_allowlist))

    if api_url and mode != "api":
        print()
        print(f"{_YELLOW}~{_RESET} AEGIS_API_URL is set but AEGIS_MODE is "
              f"'{mode}'. Set AEGIS_MODE=api or use --api to route through "
              f"the server.")
    sys.exit(0)
