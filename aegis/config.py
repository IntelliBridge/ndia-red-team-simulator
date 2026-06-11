"""Aegis configuration loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AegisConfig:
    strix_path: str = "./project_repos/strix"
    cai_path: str = "./project_repos/cai"
    vulnfixer_path: str = "./project_repos/vulnerability-fixer"
    bumblebee_path: str = "./project_repos/bumblebee"
    mcp_kali_url: str = "http://127.0.0.1:5000"
    output_dir: str = "./aegis_output"
    model: str = "gemini/gemini-2.5-flash"
    target_allowlist: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "localhost", "host.docker.internal"]
    )
    target_pack: str = "juice-shop"
    default_repo: str | None = None
    enable_pr: bool = False
    juice_shop_image_tag: str = "bkimminich/juice-shop:v17.3.0"
    strix_command: str | None = None
    strix_scan_mode: str = "standard"
    # Strix code-scope default (v0.10.0): auto | diff | full. `auto` lets Strix
    # pick PR diff-scope in CI/headless runs; per-scan ScanOptions can override.
    strix_scope_mode: str = "auto"
    deepsec_path: str = "./project_repos/deepsec"
    # The AI "process" stage is opt-in and costs money: it only runs when
    # this flag is set AND an AI Gateway / model key is in the environment
    # AND the budget cap below is > 0. Default off keeps `scan` regex-only.
    deepsec_ai_process: bool = False
    deepsec_budget_usd: float = 5.0
    # Stale-job reaper: a job left ``status="running"`` longer than this many
    # seconds is presumed crashed (the redelivery guard never re-runs it) and
    # is flipped to ``failed`` by ``aegis.reap_stale_jobs`` on the beat schedule.
    job_max_runtime_seconds: int = 3600
    # Bidirectional ticket-sync (Jira / ServiceNow / Linear). Default "none"
    # is a no-op — nothing reaches an external tracker until an operator sets
    # this AND the matching creds. The engines read these from the environment
    # directly (``AEGIS_TICKET_PROVIDER`` + per-provider vars); the fields are
    # mirrored here for discoverability and so ``resolve_ticket_provider`` can
    # fall back to config when the env var is unset.
    ticket_provider: str = "none"   # none|jira|servicenow|linear
    jira_url: str | None = None
    jira_user: str | None = None
    jira_token: str | None = None
    jira_project_key: str | None = None
    servicenow_instance: str | None = None
    servicenow_token: str | None = None
    linear_api_key: str | None = None
    linear_team_id: str | None = None
    # Cloud-target ownership verification. ``verify_secret`` (env
    # ``AEGIS_VERIFY_SECRET``) is the HMAC-style salt mixed into the
    # per-target DNS TXT token so an operator can't forge a value for a
    # target they don't own; a dev default is used when unset. Never logged.
    verify_secret: str | None = None
    # Backport / release-train awareness for generated fix PRs. ``release_trains``
    # (env ``AEGIS_RELEASE_TRAINS``) maps a release-train name to the branch a
    # fix PR should target — JSON (``{"2024.1": "release/2024.1"}``) or the
    # compact ``name=branch,name=branch`` form. Unset / unmatched falls back to
    # ``"main"`` so all current callers keep targeting main unchanged.
    release_trains: str | None = None


def load_config(path: str | None = None) -> AegisConfig:
    """Load configuration from a YAML file and return an AegisConfig.

    Resolution order for the config file path:
      1. Explicit ``path`` argument
      2. ``AEGIS_CONFIG`` environment variable
      3. ``aegis.yaml`` in the current working directory
    """
    if path is None:
        path = os.environ.get("AEGIS_CONFIG", "aegis.yaml")

    config_path = Path(path)

    if not config_path.exists():
        # No config file found — return defaults.
        return AegisConfig()

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    return AegisConfig(**{k: v for k, v in raw.items() if k in AegisConfig.__dataclass_fields__})
