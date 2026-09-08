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

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)

_STATE_MAP = {
    "verified": "poc_passed",
    "still_vulnerable": "poc_failed",
    "inconclusive": "inconclusive",
}


@app.task(name="redsim.verify_replay", bind=True, max_retries=2)
def verify_replay(self: Task, job_id: str) -> dict[str, Any]:
    from redsim.config import load_config
    from redsim.db.models import Finding, Job, VerifyJobDetail
    from redsim.schema import RedsimFinding
    from redsim.services.verify import verify
    from redsim.workers.bootstrap import task_context

    config = load_config()
    logger.info("verify_replay begin job_id=%s", job_id)
    with task_context(job_id, task=self) as ctx:
        if ctx.skip or ctx.run_state is None:
            logger.info("verify_replay skipped job_id=%s", job_id)
            return {"job_id": job_id, "skipped": True}
        sess = ctx.session
        job = sess.get(Job, job_id)
        detail = cast(VerifyJobDetail, (job.detail if job else {}) or {})
        finding_row = sess.get(Finding, detail.get("finding_id"))
        if finding_row is None:
            logger.error("verify_replay error job_id=%s: finding missing", job_id)
            raise RuntimeError("finding missing")
        finding = RedsimFinding.from_dict(finding_row.schema_blob)
        outcome = verify(
            run_state=ctx.run_state, finding=finding,
            repo_path=Path(detail.get("repo_path") or ".")
            if detail.get("repo_path") else None,
            actor=ctx.actor, config=config,
        )

        state = _STATE_MAP.get(outcome.status, "inconclusive")
        finding_row.validation_state = state
        finding_row.validated_at = datetime.now(UTC)

        logger.info("verify_replay finished job_id=%s finding_id=%s status=%s validation_state=%s",
                    job_id, outcome.finding_id, outcome.status, state)
        return {"job_id": job_id, "finding_id": outcome.finding_id,
                "status": outcome.status, "strategy": outcome.strategy,
                "validation_state": state}
