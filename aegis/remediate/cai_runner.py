"""CAI agent wrappers for remediation, plus a golden-patch fallback path.

Phase 4 v0.3.1 F10: the sys.path / CAI import dance lives in one place
(``aegis.integrations.cai_loader.load_cai``); per-task model selection
goes through ``aegis.llm.router.route`` so a project's task model
overrides and budget caps land before we touch the runner.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from aegis.integrations.cai_loader import load_cai
from aegis.llm.guardrails import guard_input, guard_output
from aegis.llm.router import BudgetChecker, BudgetExceeded
from aegis.llm.router import route as route_model
from aegis.remediate.patch_workflow import (
    _ref_before,
    apply_patch,
    diff_sha256,
    extract_unified_diff,
    is_repo_dirty,
    load_golden_patch,
    restore_tree,
)
from aegis.remediate.test_runner import (
    DEFAULT_TEST_TIMEOUT_SECONDS,
    parse_test_command,
    run_project_tests,
)
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.config import AegisConfig

logger = logging.getLogger(__name__)

RemediationAction = Literal["code_patch", "live_hardening"]
RemediationSource = Literal["cai", "golden_fixture", "vulnfixer"]


def _stringify_agent_result(result: Any) -> str:
    """Return the most useful printable value from a CAI result object."""
    if result is None:
        return "No output from agent"
    for attr in ("final_output", "value", "output"):
        value = getattr(result, attr, None)
        if value is not None:
            return str(value)
    return str(result)


@dataclass
class RemediationResult:
    success: bool
    action: RemediationAction
    finding_id: str
    output: str
    error: str | None = None
    diff: str | None = None
    diff_sha256_hex: str | None = None
    source: RemediationSource = "cai"
    plan: dict[str, Any] | None = None
    # Iterative fix→test→retry bookkeeping (C13). ``iterations`` is how many
    # agent attempts were made; ``tests_passed`` is the verdict of the final
    # project-test run (``None`` when no test command was configured / run).
    iterations: int = 1
    tests_passed: bool | None = None
    test_runs: list[dict[str, Any]] = field(default_factory=list)


def build_code_fix_prompt(
    finding: AegisFinding, *, test_feedback: str | None = None
) -> str:
    """Build a prompt for CAI CodeAgent to generate a code fix.

    When ``test_feedback`` is supplied (an iterative retry after the project
    test command failed on the previous patch), the failing test output is
    appended so the agent can correct its diff. The feedback is operator/test
    -tool output, not untrusted finding content, but it still flows through the
    same input guardrail at the call site before reaching the agent.
    """
    lines = [
        f"## Security Finding: {finding.title}",
        "",
        f"**Severity:** {finding.severity.upper()}",
    ]
    if finding.cwe:
        lines[2] += f" | **CWE:** {finding.cwe}"
    if finding.cvss:
        lines[2] += f" | **CVSS:** {finding.cvss}"
    if finding.target:
        lines.append(f"**Target:** {finding.target}")
    if finding.endpoint:
        lines.append(f"**Endpoint:** {finding.method or 'GET'} {finding.endpoint}")

    lines.extend(["", "### Description", finding.description or "No description provided."])

    if finding.impact:
        lines.extend(["", "### Impact", finding.impact])

    if finding.poc_script_code:
        lines.extend(["", "### Proof of Concept", "```", finding.poc_script_code, "```"])

    if finding.code_locations:
        for loc in finding.code_locations:
            lines.extend([
                "", "### Vulnerable Code",
                f"**File:** {loc.file} (lines {loc.start_line}-{loc.end_line})",
                "```", loc.snippet or "", "```",
            ])
            if loc.fix_after:
                lines.extend(["", "### Suggested Fix", "```", loc.fix_after, "```"])

    if finding.remediation_steps:
        lines.extend(["", "### Remediation Steps", finding.remediation_steps])

    if test_feedback:
        lines.extend([
            "",
            "### Previous Attempt Failed the Project Test Suite",
            "Your last patch was applied but the project's test command failed.",
            "Read the failing output below and produce a corrected diff.",
            "```",
            test_feedback,
            "```",
        ])

    lines.extend([
        "",
        "### Task",
        "Apply the suggested fix to the codebase.",
        "Respond with EXACTLY ONE unified diff inside a ```diff fenced block.",
        "Do not include any commentary outside the fenced block.",
    ])
    return "\n".join(lines)


def build_hardening_prompt(finding: AegisFinding) -> str:
    """Build a prompt for CAI BlueteamAgent to harden a live target."""
    lines = [
        f"## Security Finding to Remediate: {finding.title}",
        "",
        f"**Severity:** {finding.severity.upper()} | **Target:** {finding.target or 'unknown'}",
    ]
    if finding.endpoint:
        lines.append(f"**Endpoint:** {finding.method or 'GET'} {finding.endpoint}")

    lines.extend(["", "### Description", finding.description or ""])

    if finding.remediation_steps:
        lines.extend(["", "### Recommended Remediation", finding.remediation_steps])

    lines.extend([
        "", "### Task",
        "Harden the target system to mitigate this vulnerability.",
        "- Maintain full availability of all services.",
        "- Apply non-disruptive changes only.",
        "- Document all changes made.",
    ])
    return "\n".join(lines)


def _use_golden_patch(finding: AegisFinding) -> RemediationResult | None:
    diff = load_golden_patch(finding.id)
    if diff is None:
        return None
    return RemediationResult(
        success=True,
        action="code_patch",
        finding_id=finding.id,
        output=f"Golden patch fixture used for {finding.id}.",
        diff=diff,
        diff_sha256_hex=diff_sha256(diff),
        source="golden_fixture",
    )


def _usage_from_result(result: Any) -> tuple[int, int]:
    """Best-effort ``(prompt_tokens, completion_tokens)`` from a CAI result.

    The CAI ``RunResult`` exposes per-call token usage on
    ``raw_responses[].usage`` (``input_tokens`` / ``output_tokens``); we sum
    across the run. Cost is not carried on the result object (CAI tracks it on
    a separate global tracker), so we never fabricate it — the caller records
    ``cost_cents=0``. Any shape mismatch degrades to ``(0, 0)``.
    """
    prompt_tokens = completion_tokens = 0
    for resp in getattr(result, "raw_responses", None) or []:
        usage = getattr(resp, "usage", None)
        if usage is None:
            continue
        prompt_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        completion_tokens += int(getattr(usage, "output_tokens", 0) or 0)
    return prompt_tokens, completion_tokens


def _record_usage(
    *,
    project_id: str | None,
    run_id: str | None,
    model: str,
    task: str,
    result: Any,
) -> None:
    """Best-effort insert of an ``LLMUsage`` row after a routed CAI call.

    Never raises: usage logging must not be able to fail a remediation. A
    missing ``project_id`` (offline / filesystem path) is a no-op, so this
    stays DB-free unless a DB-backed run actually drove the agent.
    """
    if not project_id:
        return
    try:
        from aegis.db.models import LLMUsage
        from aegis.db.session import get_session
        from aegis.llm.pricing import cost_cents

        prompt_tokens, completion_tokens = _usage_from_result(result)
        with get_session() as sess:
            sess.add(LLMUsage(
                project_id=project_id, run_id=run_id, model=model, task=task,
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                cost_cents=cost_cents(model, prompt_tokens, completion_tokens),
            ))
    except Exception:  # noqa: BLE001 - usage logging is strictly best-effort
        logger.warning("LLMUsage logging failed for project %s task %s",
                       project_id, task, exc_info=True)


def _run_cai_agent(
    *,
    task: str,
    action: RemediationAction,
    finding: AegisFinding,
    prompt: str,
    config: AegisConfig,
    project_id: str | None,
    budget_checker: BudgetChecker | None,
    run_id: str | None = None,
    extra_context: dict[str, Any] | None = None,
) -> RemediationResult:
    """Shared CAI invocation path used by ``run_code_fix`` and
    ``run_live_hardening``.

    Routes the LLM model selection through ``aegis.llm.router.route`` —
    a ``BudgetExceeded`` short-circuit returns a structured failure
    without spinning up the agent. CAI's own sys.path injection lives
    in ``cai_loader.load_cai``; this function never touches ``sys.path``.

    Fail-closed budget gate: this is the single ``route()`` call site, so a
    DB-backed run (``project_id`` set) that arrives without a ``budget_checker``
    would route *uncapped* — ``route()`` only enforces a budget when one is
    supplied. Under ``config.llm_budget_strict`` (default in prod) we DENY that
    case here rather than silently routing, so a cap can never be skipped by a
    missing wiring. The offline / filesystem path (``project_id is None``) is
    intentionally unenforced and falls through untouched.
    """
    if project_id and budget_checker is None and getattr(
        config, "llm_budget_strict", False
    ):
        logger.error(
            "llm_budget_strict: DB-backed run for project %s task %s reached "
            "CAI without a budget_checker; denying (fail-closed)",
            project_id, task,
        )
        return RemediationResult(
            success=False, action=action, finding_id=finding.id,
            output=prompt,
            error=(f"BudgetCheckMissing: project {project_id!r} has no budget "
                   "checker; refusing to route an uncapped LLM call "
                   "(llm_budget_strict)"),
            source="cai",
        )

    try:
        spec = route_model(task, config, project_id=project_id,
                           budget_checker=budget_checker)
    except BudgetExceeded as exc:
        return RemediationResult(
            success=False, action=action, finding_id=finding.id,
            output=prompt,
            error=f"BudgetExceeded: {exc}",
            source="cai",
        )

    # Prompt-injection guard on the untrusted finding-derived prompt, *before*
    # any agent infrastructure loads. A GuardrailViolation propagates to the
    # fix service, which turns it into a clean, secret-free FixOutcome error
    # (the agent is never run).
    guard_input(prompt, config=config)

    bundle = load_cai(config)
    if bundle is None:
        return RemediationResult(
            success=False, action=action, finding_id=finding.id,
            output=f"CAI not available. Generated prompt:\n\n{prompt}",
            error="ImportError: CAI library could not be loaded",
            source="cai",
        )

    agent = bundle.codeagent if action == "code_patch" else bundle.blueteam_agent
    context: dict[str, Any] = {
        "finding_id": finding.id,
        "target": finding.target,
        "severity": finding.severity,
        "model": spec.model,
    }
    if extra_context:
        context.update(extra_context)

    try:
        result = bundle.Runner.run_sync(
            starting_agent=agent, input=prompt, context=context,
        )
    except Exception as exc:
        return RemediationResult(
            success=False, action=action, finding_id=finding.id,
            output=prompt, error=str(exc), source="cai",
        )

    _record_usage(project_id=project_id, run_id=run_id,
                  model=spec.model, task=task, result=result)

    # Output-side secret scrub before the result reaches diff extraction /
    # persistence / reporting.
    output = guard_output(_stringify_agent_result(result), config=config)
    if action == "code_patch":
        diff = extract_unified_diff(output)
        if diff is None:
            return RemediationResult(
                success=False, action=action, finding_id=finding.id,
                output=output,
                error="CodeAgent returned no parseable unified diff",
                source="cai",
            )
        return RemediationResult(
            success=True, action=action, finding_id=finding.id,
            output=output, diff=diff, diff_sha256_hex=diff_sha256(diff),
            source="cai",
        )
    return RemediationResult(
        success=True, action=action, finding_id=finding.id,
        output=output, source="cai",
    )


def run_code_fix(
    finding: AegisFinding,
    *,
    repo_path: str | None = None,
    use_golden_patch: bool = False,
    config: AegisConfig | None = None,
    project_id: str | None = None,
    run_id: str | None = None,
    budget_checker: BudgetChecker | None = None,
    test_feedback: str | None = None,
) -> RemediationResult:
    """Invoke CAI CodeAgent to generate a code patch.

    If ``use_golden_patch`` is True or ``AEGIS_DISABLE_LLM=1`` is set, the
    bundled golden patch fixture is loaded instead of calling CAI. The result
    is marked with ``source="golden_fixture"`` so downstream reporting can
    label the stage.

    ``test_feedback`` (C13 iterative loop) carries the failing output from a
    previous patch's project-test run; it is woven into the prompt so the agent
    can correct the diff. The golden-patch / disabled-LLM short-circuit ignores
    feedback by design — there is no agent to re-prompt.
    """
    if use_golden_patch or os.environ.get("AEGIS_DISABLE_LLM") == "1":
        golden = _use_golden_patch(finding)
        if golden is not None:
            return golden

    if config is None:
        from aegis.config import load_config
        config = load_config()

    return _run_cai_agent(
        task="patch", action="code_patch",
        finding=finding,
        prompt=build_code_fix_prompt(finding, test_feedback=test_feedback),
        config=config, project_id=project_id, run_id=run_id,
        budget_checker=budget_checker,
        extra_context={"repo_path": repo_path} if repo_path else None,
    )


def _apply_and_test(
    repo: Path,
    diff: str,
    command_argv: list[str],
    *,
    test_timeout: float,
) -> tuple[bool, str]:
    """Apply ``diff`` to ``repo``, run the test command, then roll back.

    Returns ``(passed, feedback)``. ``feedback`` is the failing-test (or
    apply-failure) output to feed back to the agent on the next iteration; it
    is empty on success. The working tree is always restored to the pre-apply
    ref via :func:`restore_tree` (reset + clean, so files the diff *added* are
    also removed), so iterations never compound each other's changes — mirroring
    the clean-replay discipline of ``verify_finding`` (apply → observe → reset).
    """
    ref_before = _ref_before(repo)
    applied = apply_patch(repo, diff, dry_run=False)
    if not applied.success:
        # A diff that won't even apply is itself actionable feedback.
        return False, (
            "The diff did not apply cleanly to the repository.\n"
            f"git apply error:\n{applied.stderr}"
        )
    try:
        test_result = run_project_tests(repo, command_argv, timeout=test_timeout)
    finally:
        if ref_before is not None:
            restore_tree(repo, ref_before)
    if test_result.passed:
        return True, ""
    if not test_result.ran:
        # Misconfigured command (e.g. binary not found) — surface it, but it is
        # not the agent's fault, so the feedback is informational.
        return False, f"Project test command could not run: {test_result.error}"
    return False, test_result.combined_output


def run_iterative_code_fix(
    finding: AegisFinding,
    *,
    repo: str,
    config: AegisConfig,
    project_id: str | None = None,
    run_id: str | None = None,
    budget_checker: BudgetChecker | None = None,
    use_golden_patch: bool = False,
    test_timeout: float | None = None,
) -> RemediationResult:
    """Generate a code patch, then fix→test→retry until the project tests pass.

    The loop (C13):

      1. Ask the agent for a diff (the first attempt uses the plain finding
         prompt; later attempts append the previous run's failing test output).
      2. Apply the diff to ``repo`` and run the **operator-configured** project
         test command (``config.remediation_test_command``); roll the tree back.
      3. On pass → return the validated diff. On failure → loop, feeding the
         output back, for at most ``config.remediation_max_iters`` attempts.

    When no test command is configured the loop is a no-op: a single
    :func:`run_code_fix` is returned unchanged, so the historical single-shot
    behaviour is preserved. The returned :class:`RemediationResult` carries
    ``iterations`` / ``tests_passed`` / ``test_runs`` so the caller (and the PR
    body) can record how many rounds it took and whether the gate is green.

    SECURITY: the test command comes solely from operator config and is
    executed as list-argv (never ``shell=True``); untrusted finding/patch
    content never reaches the command line — only the agent prompt.
    """
    command_argv = parse_test_command(config.remediation_test_command)
    if command_argv is None:
        # No project-test gate configured → single-shot, unchanged behaviour.
        return run_code_fix(
            finding, repo_path=repo, use_golden_patch=use_golden_patch,
            config=config, project_id=project_id, run_id=run_id,
            budget_checker=budget_checker,
        )

    repo_path = Path(repo)
    if is_repo_dirty(repo_path):
        # The loop reset/cleans the working tree between attempts (restore_tree
        # = git reset --hard + git clean -fd), which would destroy the operator's
        # uncommitted/untracked changes. Refuse the destructive loop on a dirty
        # tree and fall back to the safe single-shot path (branch-first, with its
        # own allow_dirty contract) rather than risk data loss.
        logger.warning(
            "iterative remediation skipped for %s: %s has a dirty working tree; "
            "using single-shot fix instead", finding.id, repo,
        )
        return run_code_fix(
            finding, repo_path=repo, use_golden_patch=use_golden_patch,
            config=config, project_id=project_id, run_id=run_id,
            budget_checker=budget_checker,
        )
    max_iters = max(1, config.remediation_max_iters)
    effective_timeout = (
        DEFAULT_TEST_TIMEOUT_SECONDS if test_timeout is None else test_timeout
    )

    test_runs: list[dict[str, Any]] = []
    feedback: str | None = None
    last: RemediationResult | None = None

    for attempt in range(1, max_iters + 1):
        result = run_code_fix(
            finding, repo_path=repo, use_golden_patch=use_golden_patch,
            config=config, project_id=project_id, run_id=run_id,
            budget_checker=budget_checker, test_feedback=feedback,
        )
        result.iterations = attempt
        result.test_runs = test_runs
        last = result

        # Agent failed to even produce a diff (budget, guardrail, no parse):
        # there is nothing to test, so stop — retrying won't help a hard error.
        if not result.success or not result.diff:
            result.tests_passed = None
            return result

        passed, fb = _apply_and_test(
            repo_path, result.diff, command_argv, test_timeout=effective_timeout,
        )
        test_runs.append({"iteration": attempt, "passed": passed})
        result.tests_passed = passed
        if passed:
            logger.info("remediation tests passed for %s on attempt %d/%d",
                        finding.id, attempt, max_iters)
            return result

        # A golden-fixture diff is immutable — there is no agent to re-prompt,
        # so re-testing the same patch would be pointless. Stop after one round.
        if result.source == "golden_fixture":
            return result

        logger.info("remediation tests failed for %s on attempt %d/%d",
                    finding.id, attempt, max_iters)
        # Scrub secrets from the test output before weaving it into the next
        # agent prompt (and thus shipping it to the LLM provider): failing-test
        # output routinely contains connection strings / tokens / env. The
        # prompt's guard_input does injection detection only, not redaction.
        feedback = guard_output(fb, config=config)

    # Exhausted the budget of attempts with tests still red. Return the last
    # diff (still success=True so the caller may open the PR with a clear
    # "tests not green" signal) — the caller decides whether to proceed.
    assert last is not None  # loop runs at least once (max_iters >= 1)
    last.error = (
        f"project tests still failing after {max_iters} attempt(s)"
        if last.error is None else last.error
    )
    return last


def run_live_hardening(
    finding: AegisFinding,
    *,
    config: AegisConfig | None = None,
    project_id: str | None = None,
    run_id: str | None = None,
    budget_checker: BudgetChecker | None = None,
) -> RemediationResult:
    """Invoke CAI BlueteamAgent for live system hardening (plan-only by default)."""
    if config is None:
        from aegis.config import load_config
        config = load_config()
    return _run_cai_agent(
        task="harden", action="live_hardening",
        finding=finding,
        prompt=build_hardening_prompt(finding),
        config=config, project_id=project_id, run_id=run_id,
        budget_checker=budget_checker,
    )
