"""CI-gate policy evaluator.

Lifted out of ``aegis.workers.tasks.ci_gate`` so it can be imported from
the CLI and the test suite without pulling Celery into the dependency
graph. The Celery task wrapper now imports from here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CIGatePolicy:
    """Pipeline-gating policy applied to a list of findings.

    Fields mirror the historical ``aegis ci-gate`` CLI flags so callers
    can map argparse output straight into a policy object.
    """
    severity_threshold: str = "high"
    max_findings: int | None = None
    require_validated: bool = False


# Lower rank = more severe. Anything not in the table sorts last.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def evaluate(findings: list[dict], policy: CIGatePolicy) -> tuple[int, str]:
    """Return ``(exit_code, reason)``.

    ``exit_code`` is the conventional CI-gate value:

    - ``0`` — pass.
    - ``1`` — policy violation (one or more blocking findings).

    Scanner / orchestration failures should map to ``2`` upstream; this
    function only evaluates the policy against the supplied findings.
    """
    threshold = _SEVERITY_RANK.get(policy.severity_threshold, 1)
    blocking = []
    for f in findings:
        sev = _SEVERITY_RANK.get((f.get("severity") or "").lower(), 99)
        if sev <= threshold:
            if policy.require_validated and \
                    f.get("validation_state") != "poc_passed":
                continue
            blocking.append(f)
    if policy.max_findings is not None and len(blocking) > policy.max_findings:
        return 1, (f"{len(blocking)} blocking findings exceeds max "
                   f"{policy.max_findings}")
    if blocking:
        return 1, (f"{len(blocking)} blocking findings at severity "
                   f"≥ {policy.severity_threshold}")
    return 0, "pass"
