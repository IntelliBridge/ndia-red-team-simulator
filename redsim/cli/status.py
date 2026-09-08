"""`redsim status` — prints active backends and connectivity."""

from __future__ import annotations

import argparse
import os
import sys

from redsim.config import RedsimConfig

_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _kv(label: str, value: str, *, color: str = "") -> None:
    if color:
        print(f"  {label:<18} {color}{value}{_RESET}")
    else:
        print(f"  {label:<18} {value}")


def cmd_status(_args: argparse.Namespace, config: RedsimConfig) -> None:
    api_url = os.environ.get("REDSIM_API_URL", "")
    mode = os.environ.get("REDSIM_MODE", "filesystem")
    db_url = os.environ.get("REDSIM_DB_URL", "")
    blob_backend = os.environ.get("REDSIM_BLOB_BACKEND", "fs")
    oidc_issuer = os.environ.get("REDSIM_OIDC_ISSUER", "")
    auth_mode = os.environ.get("REDSIM_AUTH_MODE", "dev")
    env = os.environ.get("REDSIM_ENV", "dev")

    state_backend = "postgres" if db_url else "filesystem"
    audit_backend = "postgres-chain" if db_url else "jsonl"

    print(f"{_BOLD}Redsim status{_RESET}")
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
    _kv("target allowlist", ", ".join(config.target_allowlist))

    if api_url and mode != "api":
        print()
        print(f"{_YELLOW}~{_RESET} REDSIM_API_URL is set but REDSIM_MODE is "
              f"'{mode}'. Set REDSIM_MODE=api or use --api to route through "
              f"the server.")

    # F4: when in api mode, also probe /health so the user sees whether
    # the configured API is actually reachable from this shell.
    if mode == "api":
        print()
        if not api_url:
            _kv("api health", "REDSIM_API_URL is unset", color=_YELLOW)
        else:
            from redsim.cli.api_client import ApiClient, load_token
            health = ApiClient(base_url=api_url, token=load_token()).health()
            if health is None:
                _kv("api health", "unreachable", color=_YELLOW)
            else:
                ok = health.get("status") == "ok" or health.get("ok") is True
                _kv("api health", "healthy" if ok else str(health),
                    color=_GREEN if ok else _YELLOW)

    sys.exit(0)
