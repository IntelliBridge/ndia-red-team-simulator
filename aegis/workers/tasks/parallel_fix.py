"""parallel_fix — red+blue parallel ops on the same finding.

Enqueues sibling ``fix.generate`` jobs (one ``patch``, one ``live``)
sharing the run context, waits for both, writes a combined summary.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from aegis.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)


@app.task(name="aegis.parallel_fix", bind=True, max_retries=0)
def parallel_fix(self: Task, job_id: str) -> dict[str, Any]:
    from celery import group

    from aegis.db.models import Job
    from aegis.workers.bootstrap import task_context
    from aegis.workers.tasks.fix import fix_generate

    logger.info("parallel_fix begin job_id=%s", job_id)
    with task_context(job_id) as ctx:
        if ctx.skip:
            logger.info("parallel_fix skipped job_id=%s", job_id)
            return {"job_id": job_id, "skipped": True}
        parent = ctx.session.get(Job, job_id)
        parent_detail = (parent.detail if parent else {}) or {}
        repo = parent_detail.get("repo")
        finding_id = parent_detail.get("finding_id")
        if not finding_id:
            logger.error("parallel_fix error job_id=%s: finding_id required", job_id)
            raise RuntimeError("finding_id required for parallel_fix")

        patch_job = f"job-{uuid4().hex[:12]}"
        live_job = f"job-{uuid4().hex[:12]}"
        for jid, strategy in ((patch_job, "patch"), (live_job, "live")):
            ctx.session.add(Job(
                id=jid, run_id=ctx.run_id, project_id=ctx.project_id,
                type="fix.generate", status="queued",
                created_by=ctx.actor,
                detail={"finding_id": finding_id, "strategy": strategy,
                        "repo": repo, "apply": False, "open_pr": False,
                        "parent_job_id": job_id},
            ))
        ctx.session.flush()

        group_result = group(
            fix_generate.s(patch_job),
            fix_generate.s(live_job),
        ).apply_async()
        outcomes = group_result.get(timeout=1800)
        logger.info("parallel_fix finished job_id=%s patch_job=%s live_job=%s",
                    job_id, patch_job, live_job)
        return {"job_id": job_id, "patch_job": patch_job,
                "live_job": live_job, "outcomes": outcomes}
