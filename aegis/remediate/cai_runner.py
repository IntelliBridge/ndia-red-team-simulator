"""CAI agent wrappers for remediation, plus a golden-patch fallback path."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from aegis.remediate.patch_workflow import (
    diff_sha256,
    extract_unified_diff,
    load_golden_patch,
)
from aegis.schema import AegisFinding


def _stringify_agent_result(result) -> str:
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
    action: str                       # "code_patch" | "live_hardening"
    finding_id: str
    output: str
    error: str | None = None
    diff: str | None = None
    diff_sha256_hex: str | None = None
    source: str = "cai"               # "cai" | "golden_fixture" | "manual"
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


def run_code_fix(
    finding: AegisFinding,
    *,
    repo_path: str | None = None,
    use_golden_patch: bool = False,
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

    prompt = build_code_fix_prompt(finding)

    try:
        import sys
        from pathlib import Path
        from aegis.config import load_config
        config = load_config()
        cai_src = Path(config.cai_path) / "src"
        if str(cai_src) not in sys.path:
            sys.path.insert(0, str(cai_src))

        from cai.agents.codeagent import codeagent
        from cai.sdk.agents import Runner

        context = {
            "finding_id": finding.id,
            "target": finding.target,
            "severity": finding.severity,
        }
        if repo_path:
            context["repo_path"] = repo_path

        result = Runner.run_sync(
            starting_agent=codeagent,
            input=prompt,
            context=context,
        )
        output = _stringify_agent_result(result)
        diff = extract_unified_diff(output)
        if diff is None:
            return RemediationResult(
                success=False,
                action="code_patch",
                finding_id=finding.id,
                output=output,
                error="CodeAgent returned no parseable unified diff",
                source="cai",
            )
        return RemediationResult(
            success=True,
            action="code_patch",
            finding_id=finding.id,
            output=output,
            diff=diff,
            diff_sha256_hex=diff_sha256(diff),
            source="cai",
        )
    except ImportError as e:
        return RemediationResult(
            success=False,
            action="code_patch",
            finding_id=finding.id,
            output=f"CAI not available. Generated prompt:\n\n{prompt}",
            error=f"ImportError: {e}",
            source="cai",
        )
    except Exception as e:
        return RemediationResult(
            success=False,
            action="code_patch",
            finding_id=finding.id,
            output=prompt,
            error=str(e),
            source="cai",
        )


def run_live_hardening(finding: AegisFinding) -> RemediationResult:
    """Invoke CAI BlueteamAgent for live system hardening (plan-only by default)."""
    prompt = build_hardening_prompt(finding)
    try:
        import sys
        from pathlib import Path
        from aegis.config import load_config
        config = load_config()
        cai_src = Path(config.cai_path) / "src"
        if str(cai_src) not in sys.path:
            sys.path.insert(0, str(cai_src))

        from cai.agents.blue_teamer import blueteam_agent
        from cai.sdk.agents import Runner

        context = {
            "finding_id": finding.id,
            "target": finding.target,
            "severity": finding.severity,
        }

        result = Runner.run_sync(starting_agent=blueteam_agent, input=prompt, context=context)
        output = _stringify_agent_result(result)
        return RemediationResult(
            success=True,
            action="live_hardening",
            finding_id=finding.id,
            output=output,
            source="cai",
        )
    except ImportError as e:
        return RemediationResult(
            success=False,
            action="live_hardening",
            finding_id=finding.id,
            output=f"CAI not available. Generated prompt:\n\n{prompt}",
            error=f"ImportError: {e}",
            source="cai",
        )
    except Exception as e:
        return RemediationResult(
            success=False,
            action="live_hardening",
            finding_id=finding.id,
            output=prompt,
            error=str(e),
            source="cai",
        )
