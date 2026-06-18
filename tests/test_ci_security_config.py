"""Regression guards for the CI self-scanning config (cluster C2).

The ``sast`` and ``deps`` jobs in ``.github/workflows/aegis-ci.yml`` only
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
from pathlib import Path
from typing import Any, cast

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "aegis-ci.yml"
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
        # -r aegis -ll -ii is the exact threshold the C2 spec calls for.
        assert "bandit -r aegis -ll -ii" in run
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
        assert "aegis-no-subprocess-shell-true" in ids

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
