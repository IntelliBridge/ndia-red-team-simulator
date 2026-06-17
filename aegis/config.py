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
    # WORM (Write-Once-Read-Many) audit export. These mirror the AEGIS_WORM_*
    # env vars (read at runtime by aegis.storage.worm; S3 creds resolve from
    # AEGIS_S3_* like S3BlobStore) and are surfaced here purely for
    # discoverability/documentation — the storage client does NOT read them
    # off the config object. The target bucket must have Object Lock enabled
    # at creation for retention to take effect.
    worm_export_enabled: bool = False
    worm_bucket: str = "aegis-worm"
    worm_retention_days: int = 2555
    worm_lock_mode: str = "COMPLIANCE"
    worm_export_interval_seconds: int = 86400
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
    # Fernet key for encrypting DAST auth-profile secrets at rest
    # (``auth_profiles.secret_ciphertext``). Sourced from the environment
    # (``AEGIS_AUTH_PROFILES_KEY``) — keep key material out of aegis.yaml.
    # Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    auth_profiles_key: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_AUTH_PROFILES_KEY")
    )
    # Pluggable authorization policy engine for the role gate
    # (``aegis.api.policy.check``). ``static`` (default) keeps the built-in
    # role-rank table; ``opa`` / ``cedar`` delegate to an external policy
    # service over REST. The engine reads these via the matching env vars
    # (``AEGIS_POLICY_ENGINE`` / ``AEGIS_OPA_URL`` / ``AEGIS_OPA_PATH`` /
    # ``AEGIS_CEDAR_URL``) — mirroring the storage/audit backend selectors;
    # these fields keep the contract discoverable. External engines fail
    # closed (deny) on any connection error or malformed response.
    policy_engine: str = "static"
    opa_url: str | None = None
    opa_path: str | None = None
    cedar_url: str | None = None
    # Supply-chain: optional Ed25519 signature enforcement for third-party
    # marketplace plugins. Off by default → the entry-point loader is unchanged.
    # When enabled (env ``AEGIS_PLUGINS_REQUIRE_SIGNATURE=1`` or this flag), only
    # plugins whose distribution carries a valid signature from a trusted key are
    # registered. ``plugins_trusted_keys`` / ``plugins_sig_dir`` mirror the
    # ``AEGIS_PLUGINS_TRUSTED_KEYS`` / ``AEGIS_PLUGINS_SIG_DIR`` env vars (the
    # verifier reads env directly; these fields keep the contract discoverable).
    plugins_require_signature: bool = False
    plugins_trusted_keys: str | None = None
    plugins_sig_dir: str | None = None
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
