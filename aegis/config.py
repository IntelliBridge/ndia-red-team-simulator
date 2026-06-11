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
    # Air-gapped installs can't reach github.com/gitlab.com for the vendored
    # submodules. When ``AEGIS_OFFLINE_VENDOR_HOST`` is set (e.g.
    # ``git.internal.example.com``) the submodule URLs are rewritten to that
    # internal mirror, preserving the ``<org>/<repo>.git`` path. See
    # ``aegis.vendor`` for the pure rewrite helpers and
    # ``scripts/vendor-submodules.sh`` for the git plumbing.
    offline_vendor_host: str | None = None


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

    if config_path.exists():
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f) or {}
        config = AegisConfig(
            **{k: v for k, v in raw.items() if k in AegisConfig.__dataclass_fields__}
        )
    else:
        # No config file found — start from defaults.
        config = AegisConfig()

    # Environment overlay: ``AEGIS_OFFLINE_VENDOR_HOST`` points the vendored
    # submodules at an internal mirror for air-gapped installs. It overrides
    # any YAML value so operators can flip it per-shell without editing files.
    env_host = os.environ.get("AEGIS_OFFLINE_VENDOR_HOST")
    if env_host:
        config.offline_vendor_host = env_host

    return config
