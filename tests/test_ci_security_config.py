"""Regression guards for the CI self-scanning config (cluster C2).

The ``sast`` and ``deps`` jobs in ``.github/workflows/redsim-ci.yml`` only
gate effectively while their backing config files stay present and well
formed. These checks mirror the ``otel-config`` CI job's "validate the
committed config" pattern: pure-Python, offline, no security tool required
(so they run in the lean unit env). They assert the *shape* of the gate —
that the jobs exist after ``helm-lint``, run the documented commands, and
that the baseline ignore files parse — not that the scanners themselves pass
(that is the job of the scanners in CI).
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path
from typing import Any, cast

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "redsim-ci.yml"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
BANDIT_INI = REPO_ROOT / ".bandit"
SEMGREP_RULES = REPO_ROOT / ".semgrep.yml"
PIP_AUDIT_IGNORES = REPO_ROOT / ".github" / "pip-audit-ignores.txt"
TRIVYIGNORE = REPO_ROOT / ".trivyignore"


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return cast("dict[str, Any]", yaml.safe_load(fh))


def _workflow_jobs() -> dict[str, Any]:
    return cast("dict[str, Any]", _load_yaml(WORKFLOW)["jobs"])


def _job_run_text(job: dict) -> str:
    """Concatenate every ``run:`` and ``uses:`` string in a job's steps."""
    chunks: list[str] = []
    for step in job.get("steps", []):
        if "run" in step:
            chunks.append(str(step["run"]))
        if "uses" in step:
            chunks.append(str(step["uses"]))
    return "\n".join(chunks)


class TestSastJob:
    def test_sast_job_exists_after_helm_lint(self) -> None:
        jobs = list(_workflow_jobs().keys())
        assert "sast" in jobs
        assert jobs.index("helm-lint") < jobs.index("sast")

    def test_semgrep_uses_required_configs_at_error(self) -> None:
        run = _job_run_text(_workflow_jobs()["sast"])
        assert "semgrep" in run
        # Both registry packs named in the C2 spec, plus the repo rules.
        assert "p/python" in run
        assert "p/security-audit" in run
        assert ".semgrep.yml" in run
        # ERROR-only and fail-on-finding.
        assert "--severity ERROR" in run
        assert "--error" in run

    def test_bandit_uses_documented_flags_and_baseline(self) -> None:
        run = _job_run_text(_workflow_jobs()["sast"])
        # -r redsim -ll -ii is the exact threshold the C2 spec calls for.
        assert "bandit -r redsim -ll -ii" in run
        # bandit does not auto-discover .bandit; the ini must be passed.
        assert "--ini .bandit" in run

    def test_sast_installs_security_extra(self) -> None:
        run = _job_run_text(_workflow_jobs()["sast"])
        assert 'pip install -e ".[security]"' in run


class TestDepsJob:
    def test_deps_job_exists_after_helm_lint(self) -> None:
        jobs = list(_workflow_jobs().keys())
        assert "deps" in jobs
        assert jobs.index("helm-lint") < jobs.index("deps")

    def test_pip_audit_runs_on_resolved_env(self) -> None:
        job = _workflow_jobs()["deps"]
        run = _job_run_text(job)
        # Resolved runtime env, not the lean base.
        assert 'pip install -e ".[api,worker,security]"' in run
        assert "pip-audit" in run
        # Editable local package has no PyPI advisory record.
        assert "--skip-editable" in run

    def test_trivy_fs_high_critical(self) -> None:
        steps = _workflow_jobs()["deps"]["steps"]
        run_blob = "\n".join(str(s.get("run", "")) for s in steps)
        # Trivy is installed directly (curl|sh) and invoked as `trivy fs`: the
        # aquasecurity/trivy-action releases reference a removed internal
        # setup-trivy tag that fails action resolution, so we avoid the action.
        assert "trivy fs" in run_blob
        assert "HIGH,CRITICAL" in run_blob
        assert "--exit-code 1" in run_blob          # gate, not advisory
        assert "--ignorefile .trivyignore" in run_blob
        # And specifically NOT via the broken action.
        uses_blob = "\n".join(str(s.get("uses", "")) for s in steps)
        assert "trivy-action" not in uses_blob


class TestDependabot:
    def test_all_four_ecosystems_covered(self) -> None:
        cfg = _load_yaml(DEPENDABOT)
        assert cfg["version"] == 2
        by_eco = {}
        for upd in cfg["updates"]:
            by_eco[upd["package-ecosystem"]] = upd.get("directory") or upd.get(
                "directories"
            )
        assert by_eco["pip"] == "/"
        assert by_eco["npm"] == "/web"
        assert by_eco["github-actions"] == "/"
        # docker globs the deploy Dockerfiles via `directories`.
        assert by_eco["docker"] == ["/deploy"]


class TestBaselineConfigsParse:
    def test_bandit_ini_skips_only_documented_b310(self) -> None:
        cp = configparser.ConfigParser()
        cp.read(BANDIT_INI)
        skips = {s.strip() for s in cp.get("bandit", "skips").split(",") if s.strip()}
        # Exactly the one documented baseline skip — nothing snuck in.
        assert skips == {"B310"}

    def test_semgrep_rules_are_error_severity(self) -> None:
        rules = _load_yaml(SEMGREP_RULES)["rules"]
        assert rules, "expected at least one repo-specific rule"
        assert all(r["severity"] == "ERROR" for r in rules)
        ids = {r["id"] for r in rules}
        # The shell=True ban is the load-bearing one for a security product.
        assert "redsim-no-subprocess-shell-true" in ids

    @staticmethod
    def _active_lines(path: Path) -> list[str]:
        return [
            ln.split("#", 1)[0].strip()
            for ln in path.read_text().splitlines()
            if ln.split("#", 1)[0].strip()
        ]

    def test_pip_audit_baseline_is_empty(self) -> None:
        # No Python advisories are suppressed: every active line would hide a
        # finding, so the pip-audit baseline must contain none.
        assert PIP_AUDIT_IGNORES.exists(), f"{PIP_AUDIT_IGNORES} must exist"
        active = self._active_lines(PIP_AUDIT_IGNORES)
        assert active == [], f"pip-audit baseline must be empty, got {active}"

    def test_trivyignore_only_tracked_advisory_ids(self) -> None:
        # .trivyignore baselines the Next.js advisories whose only fix is a
        # major (14->15) framework upgrade — a tracked follow-up, not blanket
        # suppression. Guard that every active entry is a real advisory ID so
        # nothing broader can be slipped in.
        assert TRIVYIGNORE.exists(), f"{TRIVYIGNORE} must exist"
        active = self._active_lines(TRIVYIGNORE)
        assert all(a.startswith(("CVE-", "GHSA-")) for a in active), active


# ---------------------------------------------------------------------------
# Configuration hygiene (gap register G-CONFIG, spec 20.3 / 10.8, D5)
# ---------------------------------------------------------------------------

ENV_EXAMPLE = REPO_ROOT / ".env.example"
REDSIM_YAML = REPO_ROOT / "redsim.yaml"

#: The only ``*_API_KEY`` allowed anywhere in the configuration surface.
PYTHIA_KEY = "PYTHIA_API_KEY"

#: Provider-key names the pre-D5 scaffold documented; none may come back.
PROVIDER_KEYS = ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                 "AZURE_API_KEY", "AZURE_OPENAI_API_KEY")

#: Pythia support variables (spec 20.3 table, docs/ops/pythia.md).
PYTHIA_VARS = ("PYTHIA_BASE_URL", "PYTHIA_API_KEY", "PYTHIA_PERSONA", "PYTHIA_TIMEOUT_S", "REDSIM_ENV_FILE")

#: Adversarial-ML variables of spec 20.3, plus the build-time Kaggle token.
ML_VARS = (
    "REDSIM_ML_LLM_MODEL",
    "REDSIM_DISABLE_LLM",
    "REDSIM_ML_ASSETS_DIR",
    "REDSIM_ML_WORK_DIR",
    "REDSIM_ML_KEEP_WORK_DIR",
    "REDSIM_ML_SANDBOX_TIMEOUT_S",
    "REDSIM_ML_SANDBOX_CPU_SECONDS",
    "REDSIM_ML_SANDBOX_MEMORY_MB",
    "REDSIM_ML_SANDBOX_FILESIZE_MB",
    "REDSIM_ML_SANDBOX_THREADS",
    "REDSIM_ML_DATASET_CACHE",
    "REDSIM_ML_UPLOAD_MAX_MB",
    "REDSIM_ML_MAX_ADV_ARTIFACT_MB",
    "KAGGLE_API_TOKEN",
)

#: Spec 9.4 / 20.3 defaults every sandbox ceiling comment must state.
SANDBOX_DEFAULTS = {
    "REDSIM_ML_SANDBOX_TIMEOUT_S": "1200",
    "REDSIM_ML_SANDBOX_CPU_SECONDS": "900",
    "REDSIM_ML_SANDBOX_MEMORY_MB": "4096",
    "REDSIM_ML_SANDBOX_FILESIZE_MB": "1024",
    "REDSIM_ML_SANDBOX_THREADS": "2",
}


def _env_example_lines() -> list[str]:
    return ENV_EXAMPLE.read_text().splitlines()


def _env_example_assignments() -> dict[str, str]:
    """``KEY -> value`` for every non-comment ``KEY=VALUE`` line (last assignment wins)."""
    out: dict[str, str] = {}
    for raw in _env_example_lines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def _comment_above(var: str) -> str:
    """The comment line immediately above ``var``'s assignment ('' when there is none)."""
    lines = _env_example_lines()
    for idx, raw in enumerate(lines):
        if raw.startswith(f"{var}="):
            previous = lines[idx - 1].strip() if idx else ""
            return previous if previous.startswith("#") else ""
    return ""


def test_env_example_no_provider_keys_and_lists_ml_vars() -> None:
    text = ENV_EXAMPLE.read_text()
    assigned = _env_example_assignments()

    # The only LLM credential is the Pythia key (D5).
    api_keys = {k for k in assigned if k.endswith("_API_KEY")}
    assert api_keys == {PYTHIA_KEY}, api_keys
    for name in PROVIDER_KEYS:
        assert name not in text, f"{name} must not be documented"
    assert "litellm" not in text.lower()

    # Every spec 20.3 ML variable and every Pythia support variable is listed,
    # with an EMPTY value and a one-line comment directly above it.
    for var in PYTHIA_VARS + ML_VARS:
        assert var in assigned, f"{var} missing from .env.example"
        assert assigned[var] == "", f"{var} must be documented with an empty value, got {assigned[var]!r}"
        assert _comment_above(var), f"{var} needs a one-line comment directly above it"
    # The sandbox ceilings state their defaults.
    for var, default in SANDBOX_DEFAULTS.items():
        assert default in _comment_above(var), f"{var} comment must state its default {default}"
    # Each variable is assigned exactly once.
    keys = [ln.split("=", 1)[0] for ln in _env_example_lines() if ln and not ln.startswith("#") and "=" in ln]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, dupes


def test_redsim_yaml_has_no_provider_model() -> None:
    from redsim.config import load_config

    text = REDSIM_YAML.read_text()
    data = _load_yaml(REDSIM_YAML)
    assert "model" not in data, "redsim.yaml must not carry the litellm / provider-style default model"
    lowered = text.lower()
    for token in ("gemini", "openai", "anthropic", "litellm"):
        assert token not in lowered, token
    # The comments may point at the Pythia key; no other *_API_KEY may appear.
    assert set(re.findall(r"\b[A-Z0-9_]*_API_KEY\b", text)) <= {PYTHIA_KEY}
    for name in PROVIDER_KEYS:
        assert name not in text
    cfg = load_config(path=str(REDSIM_YAML))
    assert cfg.output_dir == "./redsim_output"
    assert "127.0.0.1" in cfg.target_allowlist
    assert isinstance(cfg.task_models, dict)


def test_init_template_has_no_provider_model_or_secrets(tmp_path: Path) -> None:
    from redsim.cli.init import TEMPLATE_FIELDS, render_template
    from redsim.config import RedsimConfig, load_config

    # A secret exported in the shell must never be written into the template.
    cfg = RedsimConfig(auth_profiles_key="SECRET-FERNET-VALUE", auth_profiles_key_previous="OLD-SECRET")
    text = render_template(cfg)
    parsed = yaml.safe_load(text)
    assert set(parsed) == set(TEMPLATE_FIELDS) | {"task_models"}
    assert "model" not in parsed
    for token in ("SECRET-FERNET-VALUE", "OLD-SECRET", "auth_profiles_key", "gemini", "litellm", "None"):
        assert token not in text, token
    for name in PROVIDER_KEYS:
        assert name not in text
    assert parsed["output_dir"] == "./redsim_output"
    assert parsed["target_allowlist"] == RedsimConfig().target_allowlist
    assert parsed["task_models"] == {}

    # The template round-trips through the loader.
    target = tmp_path / "redsim.yaml"
    target.write_text(text)
    loaded = load_config(path=str(target))
    assert loaded.output_dir == "./redsim_output"
    assert loaded.job_max_runtime_seconds == RedsimConfig().job_max_runtime_seconds
