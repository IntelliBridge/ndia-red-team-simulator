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
    # LLM guardrails (aegis.llm.guardrails). Master switch plus per-layer
    # toggles; all fail-safe and secret-free in logs. ``llm_injection_block_risk``
    # is the risk tier ("low"|"medium"|"high") at/above which an injected input
    # is *blocked*; "off" detects + logs but never blocks.
    llm_guardrails_enabled: bool = True
    llm_scrub_diff_pii: bool = True
    llm_detect_injection: bool = True
    llm_filter_output: bool = True
    llm_injection_block_risk: str = "high"


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
        # No config file found — return defaults (still env-overlaid).
        return _apply_env_overrides(AegisConfig())

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    config = AegisConfig(
        **{k: v for k, v in raw.items() if k in AegisConfig.__dataclass_fields__}
    )
    return _apply_env_overrides(config)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _apply_env_overrides(config: AegisConfig) -> AegisConfig:
    """Overlay ``AEGIS_LLM_*`` environment variables onto the LLM-guardrail
    fields. Env wins over YAML so an operator can flip a guard at runtime
    without editing the config file (the established override precedence)."""
    config.llm_guardrails_enabled = _env_bool(
        "AEGIS_LLM_GUARDRAILS", config.llm_guardrails_enabled
    )
    config.llm_scrub_diff_pii = _env_bool(
        "AEGIS_LLM_SCRUB_DIFF", config.llm_scrub_diff_pii
    )
    config.llm_detect_injection = _env_bool(
        "AEGIS_LLM_DETECT_INJECTION", config.llm_detect_injection
    )
    config.llm_filter_output = _env_bool(
        "AEGIS_LLM_FILTER_OUTPUT", config.llm_filter_output
    )
    block_risk = os.environ.get("AEGIS_LLM_INJECTION_BLOCK_RISK")
    if block_risk is not None:
        config.llm_injection_block_risk = block_risk.strip().lower()
    return config
