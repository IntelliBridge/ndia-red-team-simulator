"""Fix orchestration service.

Phase 4 v0.3.1 F6 split:

- **Admission** (``create_fix_job``): authorize the fix request, create
  the ``Job`` row, emit a chained audit event, enqueue the worker
  task. Called from the API. Returns a ``JobHandle``.
- **Execution** (``generate_fix``): the long-running CAI / patch /
  PR work. Called from Celery workers and the offline CLI.

``generate_fix`` keeps its v0.3.0 signature so existing CLI / test
parity holds in v0.3.1; F11 will rename it to ``execute_fix_job`` and
move the worker task body to call it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from aegis.config import AegisConfig
from aegis.remediate.cai_runner import run_code_fix, run_live_hardening
from aegis.remediate.deps_workflow import build_version_bump_diff
from aegis.remediate.patch_workflow import (
    apply_patch,
    commit_patch,
    open_pull_request,
)
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.services.scans import JobHandle
from aegis.state import RunState

Strategy = Literal["patch", "live", "deps"]


def create_fix_job(
    *,
    finding_id: str,
    strategy: Strategy = "patch",
    apply: bool = False,
    open_pr: bool = False,
    repo: str | None = None,
    project_id: str,
    run_id: str,
    actor: str,
    config: AegisConfig,
    audit_writer,
    enqueue: bool = True,
) -> JobHandle:
    """Admission boundary for ``fix.generate`` / ``fix.apply``.

    F6 contract: emit the audit row (``fix.apply`` when ``apply`` is
    true, ``fix.generate`` otherwise), persist the Job, enqueue the
    worker. Target authorisation happens at execution time — the
    audit row here is the request-time record.
    """
    action = "fix.apply" if apply else "fix.generate"
    authorize(
        action, None,
        allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer,
        project_id=project_id, run_id=run_id,
        detail={"actor": actor, "finding_id": finding_id,
                "strategy": strategy, "apply": apply,
                "open_pr": open_pr, "repo": repo},
    )

    from aegis.db.models import Job
    from aegis.db.session import get_session

    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="fix.generate", status="queued", created_by=actor,
            detail={"finding_id": finding_id, "strategy": strategy,
                    "apply": apply, "open_pr": open_pr, "repo": repo},
        ))
        sess.flush()

    if enqueue:
        try:
            from aegis.workers.tasks.fix import fix_generate
            fix_generate.delay(job_id)
        except Exception:
            pass

    return JobHandle(run_id=run_id, job_id=job_id)


@dataclass
class FixOutcome:
    success: bool
    strategy: Strategy
    finding_id: str
    diff_path: str | None = None
    diff_sha256: str | None = None
    branch: str | None = None
    commit_hash: str | None = None
    pr_url: str | None = None
    source: str = "cai"          # "cai" | "golden_fixture" | "deterministic_bump"
    status: str = "open"         # finding status after the operation
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def _write_diff(run_state: RunState, finding_id: str, diff: str) -> Path:
    patches_dir = run_state.run_path / "artifacts" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    target = patches_dir / f"{finding_id}.diff"
    target.write_text(diff)
    return target


def generate_fix(
    *,
    run_state: RunState,
    finding: AegisFinding,
    strategy: Strategy,
    repo: str | None,
    apply: bool = False,
    open_pr: bool = False,
    branch: str | None = None,
    allow_dirty: bool = False,
    push: bool = True,
    use_golden_patch: bool = False,
    actor: str,
    config: AegisConfig,
    override_authorized: bool = False,
    gh_client=None,
) -> FixOutcome:
    """Generate (and optionally commit / PR) a remediation for ``finding``."""

    if strategy == "patch":
        return _generate_patch_fix(
            run_state=run_state, finding=finding, repo=repo,
            apply=apply, open_pr=open_pr, branch=branch,
            allow_dirty=allow_dirty, push=push,
            use_golden_patch=use_golden_patch,
            actor=actor, config=config, gh_client=gh_client,
        )
    if strategy == "live":
        return _generate_live_fix(
            run_state=run_state, finding=finding, actor=actor,
            config=config, override_authorized=override_authorized,
        )
    if strategy == "deps":
        return _generate_deps_fix(
            run_state=run_state, finding=finding, repo=repo,
            apply=apply, open_pr=open_pr, branch=branch,
            allow_dirty=allow_dirty, push=push, actor=actor,
            config=config, gh_client=gh_client,
        )
    return FixOutcome(success=False, strategy=strategy,
                      finding_id=finding.id,
                      error=f"unknown strategy: {strategy}")


def _generate_patch_fix(
    *,
    run_state: RunState,
    finding: AegisFinding,
    repo: str | None,
    apply: bool,
    open_pr: bool,
    branch: str | None,
    allow_dirty: bool,
    push: bool,
    use_golden_patch: bool,
    actor: str,
    config: AegisConfig,
    gh_client,
) -> FixOutcome:
    result = run_code_fix(finding, repo_path=repo,
                          use_golden_patch=use_golden_patch)
    if not result.success or not result.diff:
        return FixOutcome(
            success=False, strategy="patch",
            finding_id=finding.id,
            source=result.source,
            status="failed",
            error=result.error or "no diff produced",
        )

    if repo is None:
        return FixOutcome(
            success=True, strategy="patch",
            finding_id=finding.id,
            diff_sha256=result.diff_sha256_hex,
            source=result.source, status="pending_apply",
            detail={"reason": "no --repo provided; diff not persisted"},
        )

    authorize(
        "patch.apply", None,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        detail={"actor": actor, "finding_id": finding.id, "repo": repo,
                "diff_sha256": result.diff_sha256_hex,
                "source": result.source, "dry_run": not apply},
    )
    diff_path = _write_diff(run_state, finding.id, result.diff)

    if not apply:
        check = apply_patch(repo, result.diff, dry_run=True)
        return FixOutcome(
            success=check.success, strategy="patch",
            finding_id=finding.id,
            diff_path=str(diff_path),
            diff_sha256=result.diff_sha256_hex,
            source=result.source,
            status="pending_apply" if check.success else "failed",
            detail={"dry_run": True, "check_stderr": check.stderr},
        )

    commit_result = commit_patch(
        repo, finding, result.diff,
        branch=branch, allow_dirty=allow_dirty,
    )
    if not commit_result.success:
        return FixOutcome(
            success=False, strategy="patch",
            finding_id=finding.id,
            diff_path=str(diff_path),
            diff_sha256=commit_result.diff_sha256,
            branch=commit_result.branch,
            source=result.source, status="failed",
            error=commit_result.error,
            detail={"ref_before": commit_result.ref_before},
        )

    pr_url = None
    if open_pr:
        ok, url_or_err = open_pull_request(
            repo, commit_result.branch,
            title=f"Aegis fix: {finding.title} ({finding.id})",
            body=(f"Source: {result.source}\n"
                  f"diff sha256: {commit_result.diff_sha256}\n"),
            push=push,
        )
        pr_url = url_or_err if ok else None
    run_state.append_remediation_log(
        finding.id, action="patch_commit",
        result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                f"ref_before={commit_result.ref_before} "
                f"diff_sha256={commit_result.diff_sha256}"),
        success=True,
    )
    return FixOutcome(
        success=True, strategy="patch",
        finding_id=finding.id,
        diff_path=str(diff_path),
        diff_sha256=commit_result.diff_sha256,
        branch=commit_result.branch,
        commit_hash=commit_result.commit_hash,
        pr_url=pr_url, source=result.source, status="fixed",
    )


def _generate_live_fix(
    *,
    run_state: RunState,
    finding: AegisFinding,
    actor: str,
    config: AegisConfig,
    override_authorized: bool,
) -> FixOutcome:
    authorize(
        "cai.live_hardening", finding.target,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        override_authorized=override_authorized,
        detail={"actor": actor, "finding_id": finding.id},
    )
    result = run_live_hardening(finding)
    return FixOutcome(
        success=result.success, strategy="live",
        finding_id=finding.id,
        status="fixed" if result.success else "failed",
        error=result.error,
    )


def _generate_deps_fix(
    *,
    run_state: RunState,
    finding: AegisFinding,
    repo: str | None,
    apply: bool,
    open_pr: bool,
    branch: str | None,
    allow_dirty: bool,
    push: bool,
    actor: str,
    config: AegisConfig,
    gh_client,
) -> FixOutcome:
    if repo is None:
        return FixOutcome(success=False, strategy="deps",
                          finding_id=finding.id, status="failed",
                          error="--repo required for --deps")
    if finding.finding_type != "dependency":
        return FixOutcome(success=False, strategy="deps",
                          finding_id=finding.id, status="failed",
                          error=f"finding_type must be 'dependency', got {finding.finding_type}")
    bump = build_version_bump_diff(finding, repo)
    if bump.diff is None:
        return FixOutcome(success=False, strategy="deps",
                          finding_id=finding.id, status="failed",
                          error=f"could not synthesize bump: {bump.error}")
    authorize(
        "deps.bump", None,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        detail={"actor": actor, "finding_id": finding.id, "repo": repo,
                "package": finding.package_name,
                "from": finding.installed_version,
                "to": finding.fixed_version,
                "manifest": bump.rel_path},
    )
    diff_path = _write_diff(run_state, finding.id, bump.diff)
    if not apply:
        check = apply_patch(repo, bump.diff, dry_run=True)
        return FixOutcome(
            success=check.success, strategy="deps",
            finding_id=finding.id, diff_path=str(diff_path),
            source="deterministic_bump",
            status="pending_apply" if check.success else "failed",
            detail={"dry_run": True, "manifest": bump.rel_path},
        )
    commit_result = commit_patch(repo, finding, bump.diff,
                                 branch=branch, allow_dirty=allow_dirty)
    if not commit_result.success:
        return FixOutcome(
            success=False, strategy="deps",
            finding_id=finding.id, diff_path=str(diff_path),
            source="deterministic_bump", status="failed",
            error=commit_result.error,
        )
    pr_url = None
    if open_pr:
        ok, url_or_err = open_pull_request(
            repo, commit_result.branch,
            title=f"Aegis deps: bump {finding.package_name} to {finding.fixed_version}",
            body=f"CVE: {finding.cve or finding.id}\nmanifest: {bump.rel_path}\n",
            push=push,
        )
        pr_url = url_or_err if ok else None
    run_state.append_remediation_log(
        finding.id, action="deps_bump",
        result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                f"manifest={bump.rel_path} diff_sha256={commit_result.diff_sha256}"),
        success=True,
    )
    return FixOutcome(
        success=True, strategy="deps",
        finding_id=finding.id, diff_path=str(diff_path),
        diff_sha256=commit_result.diff_sha256,
        branch=commit_result.branch,
        commit_hash=commit_result.commit_hash,
        pr_url=pr_url, source="deterministic_bump", status="fixed",
        detail={"manifest": bump.rel_path},
    )
