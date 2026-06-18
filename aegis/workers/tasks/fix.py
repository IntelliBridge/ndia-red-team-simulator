"""fix.generate — Celery wrapper around ``services.fixes.generate_fix``.

Phase 4 v0.3.1 F11: the worker persists the resulting ``Finding.status``
back to Postgres so the UI / API see the same outcome the CLI does.
The ``authorize`` event for ``fix.generate`` / ``fix.apply`` was emitted
at admission; the worker's authorize call is the execution-time
re-check (e.g. ``patch.apply``), which the patch_workflow already
emits via the bootstrap-supplied writer.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from aegis.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)


@app.task(name="aegis.fix_generate", bind=True, max_retries=2)
def fix_generate(self: Task, job_id: str) -> dict[str, Any]:
    from aegis.config import load_config
    from aegis.db.models import Finding, FixJobDetail, Job
    from aegis.schema import AegisFinding
    from aegis.services.fixes import Strategy, generate_fix
    from aegis.workers.bootstrap import task_context

    config = load_config()
    logger.info("fix_generate begin job_id=%s", job_id)
    with task_context(job_id, task=self) as ctx:
        if ctx.skip or ctx.run_state is None:
            logger.info("fix_generate skipped job_id=%s", job_id)
            return {"job_id": job_id, "skipped": True}
        sess = ctx.session
        job = sess.get(Job, job_id)
        detail = cast(FixJobDetail, (job.detail if job else {}) or {})
        finding_row = sess.get(Finding, detail.get("finding_id"))
        if finding_row is None:
            logger.error("fix_generate error job_id=%s: finding %s missing",
                         job_id, detail.get("finding_id"))
            raise RuntimeError(f"finding {detail.get('finding_id')} missing")
        finding = AegisFinding.from_dict(finding_row.schema_blob)

        outcome = generate_fix(
            run_state=ctx.run_state, finding=finding,
            strategy=cast(Strategy, detail.get("strategy", "patch")),
            repo=detail.get("repo"),
            apply=bool(detail.get("apply", False)),
            open_pr=bool(detail.get("open_pr", False)),
            branch=detail.get("branch"),
            allow_dirty=bool(detail.get("allow_dirty", False)),
            push=bool(detail.get("push", True)),
            use_golden_patch=bool(detail.get("use_golden_patch", False)),
            override_authorized=bool(detail.get("override_authorized", False)),
            actor=ctx.actor, config=config,
        )

        # F11: persist the resulting status on the Finding row.
        # generate_fix returns a FixOutcome whose ``status`` is one of
        # {"fixed", "pending_apply", "failed", "open"}; we mirror that
        # onto findings.status so /v1/findings + UI badges reflect it.
        finding_row.status = outcome.status

        logger.info("fix_generate finished job_id=%s finding_id=%s status=%s success=%s",
                    job_id, outcome.finding_id, outcome.status, outcome.success)
        return {
            "job_id": job_id, "finding_id": outcome.finding_id,
            "status": outcome.status, "success": outcome.success,
            "branch": outcome.branch, "commit_hash": outcome.commit_hash,
            "pr_url": outcome.pr_url,
        }
