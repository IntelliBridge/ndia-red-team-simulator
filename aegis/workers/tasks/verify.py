"""verify.replay — Celery wrapper around ``services.verify.verify``.

Phase 4 v0.3.1 F11: the worker persists the outcome onto
``findings.validation_state`` so subsequent CI gate evaluations and UI
chips reflect the verify result. Mapping:

  verify outcome      -> findings.validation_state
  -------------------    ---------------------------
  verified              poc_passed
  still_vulnerable      poc_failed
  inconclusive          inconclusive
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegis.workers.celery_app import app

_STATE_MAP = {
    "verified": "poc_passed",
    "still_vulnerable": "poc_failed",
    "inconclusive": "inconclusive",
}


@app.task(name="aegis.verify_replay", bind=True, max_retries=2)
def verify_replay(self, job_id: str) -> dict:
    from aegis.config import load_config
    from aegis.db.models import Finding, Job
    from aegis.schema import AegisFinding
    from aegis.services.verify import verify
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id) as ctx:
        sess = ctx.session
        job = sess.get(Job, job_id)
        detail = (job.detail if job else {}) or {}
        finding_row = sess.get(Finding, detail.get("finding_id"))
        if finding_row is None:
            raise RuntimeError("finding missing")
        finding = AegisFinding.from_dict(finding_row.schema_blob)
        outcome = verify(
            run_state=ctx.run_state, finding=finding,
            repo_path=Path(detail.get("repo_path") or ".")
            if detail.get("repo_path") else None,
            actor=ctx.actor, config=config,
        )

        state = _STATE_MAP.get(outcome.status, "inconclusive")
        finding_row.validation_state = state
        finding_row.validated_at = datetime.now(timezone.utc)

        return {"job_id": job_id, "finding_id": outcome.finding_id,
                "status": outcome.status, "strategy": outcome.strategy,
                "validation_state": state}
