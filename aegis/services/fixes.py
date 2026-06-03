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

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

from aegis.config import AegisConfig
from aegis.effects import build_action_plan
from aegis.remediate.cai_runner import run_code_fix, run_live_hardening
from aegis.remediate.deps_workflow import build_version_bump_diff
from aegis.remediate.patch_workflow import (
    apply_patch,
    commit_patch,
    open_pull_request,
)
from aegis.runners.vulnfixer_runner import run_agentic_fix
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.services.scans import JobHandle

if TYPE_CHECKING:
    from aegis.audit.chain import AuditWriter
    from aegis.remediate.patch_workflow import CommitResult
    from aegis.state import RunStateAPI

logger = logging.getLogger(__name__)

# "agentic" drives the vendored vuln-fixer engine (autonomous OpenHands loop);
# it shares the patch strategy's apply/open_pr gate. "live" hardens a running
# target via the blue-team agent and is gated on apply (it is state-changing).
Strategy = Literal["patch", "live", "deps", "agentic"]
FixStatus = Literal["open", "failed", "pending_apply", "pending_approval", "fixed"]
FixSource = Literal["cai", "golden_fixture", "deterministic_bump", "vulnfixer"]


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
    audit_writer: AuditWriter,
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
            # Broker unreachable: row stays queued, picked up next start.
            logger.warning("enqueue failed for job %s", job_id, exc_info=True)

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
    source: FixSource = "cai"
    status: FixStatus = "open"   # finding status after the operation
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def _write_diff(run_state: RunStateAPI, finding_id: str, diff: str) -> Path:
    patches_dir = run_state.run_path / "artifacts" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    target = patches_dir / f"{finding_id}.diff"
    target.write_text(diff)
    return target


def _finalize_apply(
    run_state: RunStateAPI,
    finding: AegisFinding,
    commit_result: CommitResult,
    *,
    strategy: Strategy,
    source: FixSource,
    diff_path: Path,
    log_action: str,
    log_result: str,
    repo: str | None = None,
    open_pr: bool = False,
    push: bool = True,
    pr_title: str = "",
    pr_body: str = "",
    extra_detail: dict[str, Any] | None = None,
) -> FixOutcome:
    """Shared success tail of the apply-path fixes (patch / agentic / deps).

    Opens the optional PR, appends the success remediation-log line, and
    builds the ``status="fixed"`` outcome. The strategies differ only in the
    PR title/body, the log action+result, the source label, and any extra
    detail — all passed in; the branch/commit/diff bookkeeping is identical.
    """
    pr_url = None
    if open_pr and repo is not None:
        ok, url_or_err = open_pull_request(
            repo, commit_result.branch,
            title=pr_title, body=pr_body, push=push,
        )
        pr_url = url_or_err if ok else None
    run_state.append_remediation_log(
        finding.id, action=log_action, result=log_result, success=True,
    )
    return FixOutcome(
        success=True, strategy=strategy, finding_id=finding.id,
        diff_path=str(diff_path), diff_sha256=commit_result.diff_sha256,
        branch=commit_result.branch, commit_hash=commit_result.commit_hash,
        pr_url=pr_url, source=source, status="fixed",
        detail=extra_detail or {},
    )


def _dry_run_outcome(
    repo: str,
    diff: str,
    *,
    strategy: Strategy,
    finding: AegisFinding,
    diff_path: Path,
    source: FixSource,
    diff_sha256: str | None = None,
    extra_detail: dict[str, Any] | None = None,
) -> FixOutcome:
    """Shared propose-path tail of the apply-path fixes (patch / agentic / deps).

    ``apply_patch(..., dry_run=True)`` checks the diff applies cleanly without
    touching the tree: success → ``pending_apply``, failure → ``failed``. The
    strategies differ only in the strategy/source labels, the optional diff
    hash, and any extra detail (e.g. the deps manifest path).
    """
    check = apply_patch(repo, diff, dry_run=True)
    detail: dict[str, Any] = {"dry_run": True, "check_stderr": check.stderr}
    if extra_detail:
        detail.update(extra_detail)
    return FixOutcome(
        success=check.success, strategy=strategy, finding_id=finding.id,
        diff_path=str(diff_path), diff_sha256=diff_sha256, source=source,
        status="pending_apply" if check.success else "failed",
        detail=detail,
    )


def _commit_failure_outcome(
    commit_result: CommitResult,
    *,
    strategy: Strategy,
    finding: AegisFinding,
    source: FixSource,
    diff_path: Path,
) -> FixOutcome:
    """Shared commit-failure tail of the apply-path fixes.

    ``commit_patch`` rolled back to ``ref_before``; surface the branch, diff
    hash, and pre-commit ref so the caller can diagnose the failed commit.
    """
    return FixOutcome(
        success=False, strategy=strategy, finding_id=finding.id,
        diff_path=str(diff_path), diff_sha256=commit_result.diff_sha256,
        branch=commit_result.branch, source=source, status="failed",
        error=commit_result.error,
        detail={"ref_before": commit_result.ref_before},
    )


def generate_fix(
    *,
    run_state: RunStateAPI,
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
    if strategy == "agentic":
        return _generate_agentic_fix(
            run_state=run_state, finding=finding, repo=repo,
            apply=apply, open_pr=open_pr, branch=branch,
            allow_dirty=allow_dirty, actor=actor, config=config,
        )
    if strategy == "live":
        return _generate_live_fix(
            run_state=run_state, finding=finding, actor=actor,
            config=config, apply=apply, override_authorized=override_authorized,
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
    run_state: RunStateAPI,
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
        return _dry_run_outcome(
            repo, result.diff, strategy="patch", finding=finding,
            diff_path=diff_path, source=result.source,
            diff_sha256=result.diff_sha256_hex,
        )

    commit_result = commit_patch(
        repo, finding, result.diff,
        branch=branch, allow_dirty=allow_dirty,
    )
    if not commit_result.success:
        return _commit_failure_outcome(
            commit_result, strategy="patch", finding=finding,
            source=result.source, diff_path=diff_path,
        )

    return _finalize_apply(
        run_state, finding, commit_result,
        strategy="patch", source=result.source, diff_path=diff_path,
        log_action="patch_commit",
        log_result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                    f"ref_before={commit_result.ref_before} "
                    f"diff_sha256={commit_result.diff_sha256}"),
        repo=repo, open_pr=open_pr, push=push,
        pr_title=f"Aegis fix: {finding.title} ({finding.id})",
        pr_body=(f"Source: {result.source}\n"
                 f"diff sha256: {commit_result.diff_sha256}\n"),
    )


def _generate_live_fix(
    *,
    run_state: RunStateAPI,
    finding: AegisFinding,
    actor: str,
    config: AegisConfig,
    apply: bool,
    override_authorized: bool,
) -> FixOutcome:
    # Live hardening mutates a running target (an ``active`` effect). Without
    # the apply opt-in (approver-gated at the route) we return a reviewable
    # hardening plan and never invoke the blue-team agent — propose → approve →
    # act, the same gate the active agents and Kali tools pass through.
    if not apply:
        return FixOutcome(
            success=True, strategy="live", finding_id=finding.id,
            source="cai", status="pending_approval",
            detail={"plan": build_action_plan(
                name="blueteam_agent", domain="defensive", effect="active",
                target=finding.target, intent=f"harden against {finding.id}")},
        )
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


def _generate_agentic_fix(
    *,
    run_state: RunStateAPI,
    finding: AegisFinding,
    repo: str | None,
    apply: bool,
    open_pr: bool,
    branch: str | None,
    allow_dirty: bool,
    actor: str,
    config: AegisConfig,
) -> FixOutcome:
    """Drive the vendored vuln-fixer engine behind the apply/open_pr gate.

    - **propose** (``apply=False``): the engine emits a diff only; we persist it
      and dry-run-check it → ``pending_apply``. Nothing is pushed.
    - **apply, no PR**: the engine's diff is committed *locally* (rollback-safe
      via ``commit_patch``) → ``fixed``.
    - **open_pr** (requires ``apply=True`` — approver-gated at the route): the
      engine opens the pull request itself; the PR review is the human gate. We
      record the ``pr_url`` / ``branch`` → ``fixed``. ``open_pr`` without
      ``apply`` is not approved to act, so it falls through to propose.
    """
    if repo is None:
        # The engine needs a working tree to read/patch, so without a repo
        # there is no diff to even propose — fail fast rather than handing a
        # None repo to run_agentic_fix / apply_patch / commit_patch.
        return FixOutcome(
            success=False, strategy="agentic", finding_id=finding.id,
            status="failed",
            error="--repo required for agentic fix (engine needs a working tree)",
        )
    if open_pr and apply:
        # The engine pushes a branch and opens the human-reviewed PR itself.
        authorize(
            "agentic.open_pr", None,
            allowlist=config.target_allowlist,
            run_path=run_state.run_path,
            detail={"actor": actor, "finding_id": finding.id, "repo": repo},
        )
        result = run_agentic_fix(finding, repo_path=repo, open_pr=True,
                                 config=config)
        if not result.success:
            return FixOutcome(
                success=False, strategy="agentic", finding_id=finding.id,
                source=result.source, status="failed", error=result.error,
            )
        plan = result.plan or {}
        run_state.append_remediation_log(
            finding.id, action="agentic_pr",
            result=f"pr_url={plan.get('pr_url')} branch={plan.get('branch')}",
            success=True,
        )
        return FixOutcome(
            success=True, strategy="agentic", finding_id=finding.id,
            branch=plan.get("branch"), pr_url=plan.get("pr_url"),
            source=result.source, status="fixed",
            detail={"engine_opened_pr": True},
        )

    # Propose / local-apply both start from a diff-only engine run.
    result = run_agentic_fix(finding, repo_path=repo, open_pr=False, config=config)
    if not result.success or not result.diff:
        return FixOutcome(
            success=False, strategy="agentic", finding_id=finding.id,
            source=result.source, status="failed",
            error=result.error or "no diff produced",
        )
    authorize(
        "agentic.apply", None,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        detail={"actor": actor, "finding_id": finding.id, "repo": repo,
                "diff_sha256": result.diff_sha256_hex, "dry_run": not apply},
    )
    diff_path = _write_diff(run_state, finding.id, result.diff)
    if not apply:
        return _dry_run_outcome(
            repo, result.diff, strategy="agentic", finding=finding,
            diff_path=diff_path, source=result.source,
            diff_sha256=result.diff_sha256_hex,
        )
    commit_result = commit_patch(repo, finding, result.diff,
                                 branch=branch, allow_dirty=allow_dirty)
    if not commit_result.success:
        return _commit_failure_outcome(
            commit_result, strategy="agentic", finding=finding,
            source=result.source, diff_path=diff_path,
        )
    return _finalize_apply(
        run_state, finding, commit_result,
        strategy="agentic", source=result.source, diff_path=diff_path,
        log_action="agentic_commit",
        log_result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                    f"ref_before={commit_result.ref_before} "
                    f"diff_sha256={commit_result.diff_sha256}"),
    )


def _generate_deps_fix(
    *,
    run_state: RunStateAPI,
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
        return _dry_run_outcome(
            repo, bump.diff, strategy="deps", finding=finding,
            diff_path=diff_path, source="deterministic_bump",
            extra_detail={"manifest": bump.rel_path},
        )
    commit_result = commit_patch(repo, finding, bump.diff,
                                 branch=branch, allow_dirty=allow_dirty)
    if not commit_result.success:
        return _commit_failure_outcome(
            commit_result, strategy="deps", finding=finding,
            source="deterministic_bump", diff_path=diff_path,
        )
    return _finalize_apply(
        run_state, finding, commit_result,
        strategy="deps", source="deterministic_bump", diff_path=diff_path,
        log_action="deps_bump",
        log_result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                    f"manifest={bump.rel_path} diff_sha256={commit_result.diff_sha256}"),
        repo=repo, open_pr=open_pr, push=push,
        pr_title=f"Aegis deps: bump {finding.package_name} to {finding.fixed_version}",
        pr_body=f"CVE: {finding.cve or finding.id}\nmanifest: {bump.rel_path}\n",
        extra_detail={"manifest": bump.rel_path},
    )
