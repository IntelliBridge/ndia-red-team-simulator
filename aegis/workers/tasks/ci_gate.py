"""ci_gate — pipeline-gating task that evaluates findings against policy.

Run by ``aegis ci-gate`` (M12) and the GitHub Action shim. Returns:

- exit_code 0 → pass
- exit_code 1 → policy violation
- exit_code 2 → scanner error

The body composes scan → verify → policy-evaluate.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.workers.celery_app import app


@dataclass
class CIGatePolicy:
    severity_threshold: str = "high"
    max_findings: int | None = None
    require_validated: bool = False


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def evaluate(findings: list[dict], policy: CIGatePolicy) -> tuple[int, str]:
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


@app.task(name="aegis.ci_gate", bind=True, max_retries=0)
def ci_gate(self, job_id: str) -> dict:
    from aegis.workers.bootstrap import task_context
    with task_context(job_id) as ctx:
        findings = ctx.run_state.load_findings()
        # In Phase 3, the policy comes in the job detail.
        from aegis.db.models import Job
        sess = ctx.run_state.session
        job = sess.get(Job, job_id)
        policy_detail = (job.detail or {}).get("policy", {})
        policy = CIGatePolicy(
            severity_threshold=policy_detail.get("severity_threshold", "high"),
            max_findings=policy_detail.get("max_findings"),
            require_validated=bool(policy_detail.get("require_validated", False)),
        )
        exit_code, reason = evaluate(findings, policy)
        return {"job_id": job_id, "exit_code": exit_code, "reason": reason,
                "findings_evaluated": len(findings)}
