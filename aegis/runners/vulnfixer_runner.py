"""Agentic remediation runner — drives the vendored vulnerability-fixer.

Phase 4 v0.8.0 C4: the vendored ``vulnerability-fixer`` ships an autonomous
OpenHands loop (``RemediationService.remediateVulnerability``) that clones a
repo, edits it, commits, pushes, and **opens a PR on its own**. That autonomy
is the engine's value, so Aegis drives it in two modes behind the same
human-in-the-loop gate every remediation passes through:

- **propose** (default): the engine runs against a *local* working copy in
  ``--emit-diff --no-push --no-pr`` mode and we capture a single unified diff.
  No token is passed and push/PR are disabled, so the engine *cannot* reach a
  remote. The diff is the reviewable proposal (status ``pending_apply``).
- **open_pr** (explicit opt-in, approver-gated upstream in ``fixes.py``): the
  engine pushes a branch and opens a pull request itself. **The PR review is
  the human gate** — a reviewer approves before merge — so letting the engine
  open it does not bypass human-in-the-loop; it *is* the loop. The GitHub token
  flows only through the subprocess environment (inherited ``GITHUB_TOKEN``),
  **never** through argv. We capture the resulting ``pr_url`` / ``branch``.

Offline contract: this is a soft-degrading subprocess adapter. Missing Node,
a missing integration driver, a missing token in PR mode, a timeout, a non-zero
exit, or no parseable result all return ``success=False`` with an ``error`` —
never a raise. The driver is provided by the deploy image; it is absent on the
offline test path, so the default behaviour there is a clean degrade.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from aegis.config import AegisConfig, load_config
from aegis.remediate.cai_runner import RemediationResult
from aegis.remediate.patch_workflow import diff_sha256, extract_unified_diff
from aegis.schema import AegisFinding

# The deploy image exposes a driver under the vendored tree. It must honour
# --emit-diff (unified diff to stdout) + --no-push + --no-pr in propose mode,
# and --open-pr in PR mode (printing a final "AEGIS_RESULT {json}" line with
# pr_url/branch). The vendored tree ships no CLI bin, so on the offline path
# this path does not exist and the runner degrades cleanly.
_DRIVER_REL = ("scripts", "aegis_remediate.mjs")

#: The driver prints its machine-readable PR result on this marker line.
_RESULT_MARKER = "AEGIS_RESULT "


def _driver_path(config: AegisConfig) -> Path:
    return Path(config.vulnfixer_path, *_DRIVER_REL)


def _parse_engine_result(stdout: str) -> dict | None:
    """Last ``AEGIS_RESULT {json}`` line the driver emits in PR mode."""
    for line in reversed((stdout or "").splitlines()):
        s = line.strip()
        if s.startswith(_RESULT_MARKER):
            try:
                return json.loads(s[len(_RESULT_MARKER):])
            except json.JSONDecodeError:
                return None
    return None


def _build_command(
    driver: Path, finding: AegisFinding, repo_path: str, *, open_pr: bool,
) -> list[str]:
    """Engine invocation. In propose mode push/PR are disabled and no token is
    passed, so the engine can only emit a diff. In PR mode the engine pushes and
    opens the PR itself; the token is supplied via the environment, never argv.
    """
    cmd = [
        "node", str(driver),
        "--repo", str(repo_path),
        "--cve", finding.cve or finding.id,
        "--package", finding.package_name or "",
        "--current-version", finding.installed_version or "",
        "--fixed-version", finding.fixed_version or "",
        "--severity", finding.severity,
    ]
    if open_pr:
        cmd.append("--open-pr")
    else:
        cmd += ["--emit-diff", "--no-push", "--no-pr"]
    return cmd


def run_agentic_fix(
    finding: AegisFinding,
    *,
    repo_path: str | None = None,
    open_pr: bool = False,
    config: AegisConfig | None = None,
    timeout: int = 900,
) -> RemediationResult:
    """Drive the vuln-fixer engine.

    Default (``open_pr=False``): diff-only, never push, never PR — returns a
    ``RemediationResult`` carrying the unified ``diff``. With ``open_pr=True``
    the engine opens the pull request itself (the PR review is the human gate)
    and the result carries ``plan={"pr_url": ..., "branch": ...}``. Soft-degrades
    to ``success=False`` with an ``error`` whenever the engine cannot run.
    """
    if config is None:
        config = load_config()

    fail = lambda msg: RemediationResult(  # noqa: E731 - terse local helper
        success=False, action="code_patch", finding_id=finding.id,
        output="", error=msg, source="vulnfixer",
    )

    if not repo_path:
        return fail("agentic remediation requires a repo working tree (--repo)")

    if shutil.which("node") is None:
        return fail("node is not available — agentic remediation degrades")

    driver = _driver_path(config)
    if not driver.exists():
        return fail(f"vuln-fixer driver not found at {driver}")

    # PR mode needs a GitHub token. It flows only through the inherited process
    # environment (subprocess inherits os.environ) — never the argv — so it can
    # never leak into the audit/log of the command line.
    if open_pr and not os.environ.get("GITHUB_TOKEN"):
        return fail("agentic PR mode requires GITHUB_TOKEN in the environment")

    cmd = _build_command(driver, finding, repo_path, open_pr=open_pr)
    try:
        proc = subprocess.run(
            cmd, cwd=str(config.vulnfixer_path),
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return fail(f"vuln-fixer engine failed to run: {exc}")

    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()[:500]
        return fail(f"vuln-fixer engine exited {proc.returncode}: {detail}")

    if open_pr:
        result = _parse_engine_result(proc.stdout)
        if not result or not result.get("pr_url"):
            return fail("vuln-fixer engine opened no PR (no AEGIS_RESULT pr_url)")
        return RemediationResult(
            success=True, action="code_patch", finding_id=finding.id,
            output=proc.stdout, source="vulnfixer",
            plan={"pr_url": result.get("pr_url"), "branch": result.get("branch")},
        )

    diff = extract_unified_diff(proc.stdout)
    if diff is None:
        return fail("vuln-fixer engine produced no parseable unified diff")

    return RemediationResult(
        success=True, action="code_patch", finding_id=finding.id,
        output=proc.stdout, diff=diff, diff_sha256_hex=diff_sha256(diff),
        source="vulnfixer",
    )
