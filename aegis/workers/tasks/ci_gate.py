"""ci_gate — pipeline-gating Celery task that evaluates findings against policy.

The policy primitives (``CIGatePolicy``, ``evaluate``) live in
``aegis.policy.ci_gate`` so they can be imported from the CLI and the
test suite without pulling Celery into the dependency graph. This module
is a thin task wrapper around them.

Returns from ``evaluate``:

- exit_code 0 → pass
- exit_code 1 → policy violation
- exit_code 2 → scanner error (upstream signal — not produced here)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aegis.policy.ci_gate import CIGatePolicy, evaluate  # noqa: F401 re-export
from aegis.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

__all__ = ["CIGatePolicy", "evaluate", "ci_gate"]


@app.task(name="aegis.ci_gate", bind=True, max_retries=0)
def ci_gate(self: Task, job_id: str) -> dict[str, Any]:
    from aegis.workers.bootstrap import task_context
    with task_context(job_id) as ctx:
        if ctx.skip or ctx.run_state is None:
            return {"job_id": job_id, "skipped": True}
        findings = ctx.run_state.load_findings()
        from aegis.db.models import Job
        sess = ctx.session
        job = sess.get(Job, job_id)
        detail = (job.detail if job else {}) or {}
        policy_detail = detail.get("policy", {})
        policy = CIGatePolicy(
            severity_threshold=policy_detail.get("severity_threshold", "high"),
            max_findings=policy_detail.get("max_findings"),
            require_validated=bool(policy_detail.get("require_validated", False)),
        )
        exit_code, reason = evaluate(findings, policy)
        return {"job_id": job_id, "exit_code": exit_code, "reason": reason,
                "findings_evaluated": len(findings)}
