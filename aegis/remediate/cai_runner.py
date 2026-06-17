"""CAI agent wrappers for remediation, plus a golden-patch fallback path.

Phase 4 v0.3.1 F10: the sys.path / CAI import dance lives in one place
(``aegis.integrations.cai_loader.load_cai``); per-task model selection
goes through ``aegis.llm.router.route`` so a project's task model
overrides and budget caps land before we touch the runner.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from aegis.integrations.cai_loader import load_cai
from aegis.llm.router import BudgetChecker, BudgetExceeded
from aegis.llm.router import route as route_model
from aegis.remediate.patch_workflow import (
    diff_sha256,
    extract_unified_diff,
    load_golden_patch,
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


def build_code_fix_prompt(finding: AegisFinding) -> str:
    """Build a prompt for CAI CodeAgent to generate a code fix."""
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
    """
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

    output = _stringify_agent_result(result)
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
) -> RemediationResult:
    """Invoke CAI CodeAgent to generate a code patch.

    If ``use_golden_patch`` is True or ``AEGIS_DISABLE_LLM=1`` is set, the
    bundled golden patch fixture is loaded instead of calling CAI. The result
    is marked with ``source="golden_fixture"`` so downstream reporting can
    label the stage.
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
        prompt=build_code_fix_prompt(finding),
        config=config, project_id=project_id, run_id=run_id,
        budget_checker=budget_checker,
        extra_context={"repo_path": repo_path} if repo_path else None,
    )


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
