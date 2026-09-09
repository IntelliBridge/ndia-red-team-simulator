"""Redsim configuration loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class RedsimConfig:
    output_dir: str = "./redsim_output"
    # Legacy router fallback for tasks absent from ``task_models``
    # (``redsim.llm.router.route``). Every LLM call goes through the Pythia
    # gateway (D5): this provider-style id is never used for the Pythia-only
    # tasks (spec 10.8), the committed ``redsim.yaml`` and ``redsim init`` no
    # longer write the key, and ``redsim doctor`` no longer derives a provider
    # API key from it — ``PYTHIA_API_KEY`` is the only LLM credential.
    model: str = "gemini/gemini-2.5-flash"
    target_allowlist: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "localhost", "host.docker.internal"]
    )
    # Stale-job reaper: a job left ``status="running"`` longer than this many
    # seconds is presumed crashed (the redelivery guard never re-runs it) and
    # is flipped to ``failed`` by ``redsim.reap_stale_jobs`` on the beat schedule.
    job_max_runtime_seconds: int = 3600
    # Air-gapped installs point at an internal package/artifact mirror instead
    # of the public internet. When ``REDSIM_OFFLINE_VENDOR_HOST`` is set (e.g.
    # ``git.internal.example.com``) it is surfaced by ``redsim doctor`` and the
    # evidence pack as a generic air-gapped-mirror setting.
    offline_vendor_host: str | None = None
    # WORM (Write-Once-Read-Many) audit export. These mirror the REDSIM_WORM_*
    # env vars (read at runtime by redsim.storage.worm; S3 creds resolve from
    # REDSIM_S3_* like S3BlobStore) and are surfaced here purely for
    # discoverability/documentation — the storage client does NOT read them
    # off the config object. The target bucket must have Object Lock enabled
    # at creation for retention to take effect.
    worm_export_enabled: bool = False
    worm_bucket: str = "redsim-worm"
    worm_retention_days: int = 2555
    worm_lock_mode: str = "COMPLIANCE"
    worm_export_interval_seconds: int = 86400
    # Fernet key for encrypting DAST auth-profile secrets at rest
    # (``auth_profiles.secret_ciphertext``). Sourced from the environment
    # (``REDSIM_AUTH_PROFILES_KEY``) — keep key material out of redsim.yaml.
    # Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    auth_profiles_key: str | None = field(
        default_factory=lambda: os.environ.get("REDSIM_AUTH_PROFILES_KEY")
    )
    # Previous Fernet key, kept valid for decryption through a key
    # rotation (``REDSIM_AUTH_PROFILES_KEY_PREVIOUS``). When set, secrets
    # are encrypted with the current key but decryptable with either, so
    # ciphertext written under the old key keeps resolving until it has
    # been re-encrypted. Mirrors the worker / session signing-key overlap.
    auth_profiles_key_previous: str | None = field(
        default_factory=lambda: os.environ.get("REDSIM_AUTH_PROFILES_KEY_PREVIOUS")
    )
    # Pluggable authorization policy engine for the role gate
    # (``redsim.api.policy.check``). ``static`` (default) keeps the built-in
    # role-rank table; ``opa`` / ``cedar`` delegate to an external policy
    # service over REST. The engine reads these via the matching env vars
    # (``REDSIM_POLICY_ENGINE`` / ``REDSIM_OPA_URL`` / ``REDSIM_OPA_PATH`` /
    # ``REDSIM_CEDAR_URL``) — mirroring the storage/audit backend selectors;
    # these fields keep the contract discoverable. External engines fail
    # closed (deny) on any connection error or malformed response.
    policy_engine: str = "static"
    opa_url: str | None = None
    opa_path: str | None = None
    cedar_url: str | None = None
    # Supply-chain: optional Ed25519 signature enforcement for third-party
    # marketplace plugins. Off by default → the entry-point loader is unchanged.
    # When enabled (env ``REDSIM_PLUGINS_REQUIRE_SIGNATURE=1`` or this flag), only
    # plugins whose distribution carries a valid signature from a trusted key are
    # registered. ``plugins_trusted_keys`` / ``plugins_sig_dir`` mirror the
    # ``REDSIM_PLUGINS_TRUSTED_KEYS`` / ``REDSIM_PLUGINS_SIG_DIR`` env vars (the
    # verifier reads env directly; these fields keep the contract discoverable).
    plugins_require_signature: bool = False
    plugins_trusted_keys: str | None = None
    plugins_sig_dir: str | None = None
    # Sandbox third-party plugin scanners (default on): a discovered plugin's
    # ``scan()`` runs out-of-process under resource rlimits + a wall-clock
    # timeout, network-off by default. Disable with env ``REDSIM_PLUGINS_SANDBOX=0``
    # (or this flag) for trusted first-party plugins. Per-run resource caps and
    # the network opt-in are env-only (``REDSIM_PLUGIN_SANDBOX_*`` /
    # ``REDSIM_PLUGIN_SANDBOX_NETWORK``); the verifier/sandbox read env directly,
    # these fields keep the contract discoverable.
    plugins_sandbox: bool = True
    # LLM guardrails (redsim.llm.guardrails). Master switch plus per-layer
    # toggles; all fail-safe and secret-free in logs. ``llm_injection_block_risk``
    # is the risk tier ("low"|"medium"|"high") at/above which an injected input
    # is *blocked*; "off" detects + logs but never blocks.
    llm_guardrails_enabled: bool = True
    llm_scrub_diff_pii: bool = True
    llm_detect_injection: bool = True
    llm_filter_output: bool = True
    llm_injection_block_risk: str = "high"
    # Fail-closed LLM budget enforcement. ``route()`` only enforces a budget
    # when a ``budget_checker`` is supplied; a DB-backed run (``project_id``
    # set) that reaches the LLM invocation *without* one would otherwise route
    # uncapped. When strict, that case is DENIED rather than silently routed —
    # so a budget cap can never be skipped by a missing wiring. The offline /
    # filesystem path (``project_id is None``) is intentionally unenforced and
    # unaffected. Defaults True in prod (``REDSIM_ENV=prod``), False otherwise;
    # override with ``REDSIM_LLM_BUDGET_STRICT`` (the established env precedence).
    llm_budget_strict: bool = field(
        default_factory=lambda: os.environ.get("REDSIM_ENV", "dev").lower() == "prod"
    )
    # Per-task model routing (``redsim.llm.router.route``): ``{task: model id}``.
    # A task absent from the map falls back to ``model``, except the Pythia-only
    # tasks (``ml.harden_narrative``), which are refused rather than routed to
    # the provider-style default. ``_apply_env_overrides`` seeds
    # ``ml.harden_narrative`` from ``REDSIM_ML_LLM_MODEL`` (spec 10.8, 16.3)
    # when the YAML did not map it; the env never overrides an explicit entry.
    task_models: dict[str, str] = field(default_factory=dict)


#: Router task name of the adversarial-ML hardening narrative (spec 5.12, 10.8).
ML_HARDEN_NARRATIVE_TASK = "ml.harden_narrative"
#: Canonical name of the Pythia model-id variable (mirrors ``redsim.llm.pythia.MODEL_ENV``).
ML_LLM_MODEL_ENV = "REDSIM_ML_LLM_MODEL"


def load_config(path: str | None = None) -> RedsimConfig:
    """Load configuration from a YAML file and return an RedsimConfig.

    Resolution order for the config file path:
      1. Explicit ``path`` argument
      2. ``REDSIM_CONFIG`` environment variable
      3. ``redsim.yaml`` in the current working directory
    """
    if path is None:
        path = os.environ.get("REDSIM_CONFIG", "redsim.yaml")

    config_path = Path(path)

    if config_path.exists():
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f) or {}
        config = RedsimConfig(
            **{k: v for k, v in raw.items() if k in RedsimConfig.__dataclass_fields__}
        )
    else:
        # No config file found — start from defaults.
        config = RedsimConfig()

    # Environment overlay: ``REDSIM_OFFLINE_VENDOR_HOST`` names the internal
    # package mirror for air-gapped installs. It overrides any YAML value so
    # operators can flip it per-shell without editing files.
    env_host = os.environ.get("REDSIM_OFFLINE_VENDOR_HOST")
    if env_host:
        config.offline_vendor_host = env_host

    return _apply_env_overrides(config)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _apply_env_overrides(config: RedsimConfig) -> RedsimConfig:
    """Overlay ``REDSIM_LLM_*`` environment variables onto the LLM-guardrail
    fields. Env wins over YAML so an operator can flip a guard at runtime
    without editing the config file (the established override precedence)."""
    # ``REDSIM_TARGET_ALLOWLIST`` (comma-separated hosts) replaces the YAML
    # list. The container images ship no redsim.yaml, so this is how a
    # deployment names the hosts the egress check admits, e.g. the Pythia
    # gateway an LLM target registration points at (register LLM-26).
    allowlist = os.environ.get("REDSIM_TARGET_ALLOWLIST")
    if allowlist is not None:
        hosts = [h.strip() for h in allowlist.split(",") if h.strip()]
        if hosts:
            config.target_allowlist = hosts
    config.llm_guardrails_enabled = _env_bool(
        "REDSIM_LLM_GUARDRAILS", config.llm_guardrails_enabled
    )
    config.llm_scrub_diff_pii = _env_bool(
        "REDSIM_LLM_SCRUB_DIFF", config.llm_scrub_diff_pii
    )
    config.llm_detect_injection = _env_bool(
        "REDSIM_LLM_DETECT_INJECTION", config.llm_detect_injection
    )
    config.llm_filter_output = _env_bool(
        "REDSIM_LLM_FILTER_OUTPUT", config.llm_filter_output
    )
    block_risk = os.environ.get("REDSIM_LLM_INJECTION_BLOCK_RISK")
    if block_risk is not None:
        config.llm_injection_block_risk = block_risk.strip().lower()
    config.llm_budget_strict = _env_bool(
        "REDSIM_LLM_BUDGET_STRICT", config.llm_budget_strict
    )
    # Seed the Pythia narrative task from REDSIM_ML_LLM_MODEL (additive: an
    # explicit YAML mapping wins, and an unset variable leaves the task
    # unmapped so the router refuses it instead of using ``model``).
    if not isinstance(config.task_models, dict):
        config.task_models = {}
    narrative_model = os.environ.get(ML_LLM_MODEL_ENV, "").strip()
    if narrative_model and not config.task_models.get(ML_HARDEN_NARRATIVE_TASK):
        config.task_models[ML_HARDEN_NARRATIVE_TASK] = narrative_model
    return config
