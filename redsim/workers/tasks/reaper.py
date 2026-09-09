"""redsim.reap_stale_jobs — periodic cleanup for crashed jobs.

A task that dies mid-run is left ``status="running"`` forever: the
``task_context`` redelivery guard (``workers.bootstrap``) deliberately
skips re-running non-``queued`` jobs (fail-closed), so nothing flips a
crashed job to ``failed``. This reaper is the complementary cleanup —
it runs on the Celery beat schedule, finds ``running`` jobs whose
``started_at`` is older than the configured TTL, marks them failed, and
rolls each affected run's status up (spec 6.2) so a run whose jobs all
ended reaches its terminal status instead of staying ``running``.

Unlike the job-scoped worker tasks, the reaper scans *all* jobs, so it
manages its own session directly rather than going through
``task_context``. The core logic lives in ``reap_stale_jobs_in_session``
so it's unit-testable without Celery or a real DB.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from redsim.db.models import Job, Run
from redsim.workers.celery_app import app
from redsim.workers.job_state import set_job_status

logger = logging.getLogger(__name__)

#: ``Job.error`` written on every reaped row.
REAPED_ERROR = "reaped: exceeded max runtime TTL"


def _mark_stage_table_failed(sess: Session, job: Job) -> None:
    """Mirror the reaped job into ``Run.stage_table["jobs"]`` (best-effort)."""
    run = sess.get(Run, job.run_id)
    if run is None:
        return
    table = dict(getattr(run, "stage_table", None) or {})
    jobs = dict(table.get("jobs") or {})
    jobs[job.id] = {
        **dict(jobs.get(job.id) or {}),
        "type": job.type, "status": "failed", "error": REAPED_ERROR,
    }
    table["jobs"] = jobs
    table["error"] = REAPED_ERROR
    run.stage_table = table


def reap_stale_jobs_in_session(
    sess: Session, ttl_seconds: int, now: datetime | None = None
) -> int:
    """Flip ``running`` jobs older than the TTL to ``failed`` and roll runs up.

    Selects ``Job`` rows where ``status == "running"`` and
    ``started_at < now - ttl_seconds`` and stamps each with
    ``status="failed"``, ``completed_at=now`` and a reaper ``error``. Every
    run that lost a job this way is then passed through
    ``services.runs.rollup_run_status`` in the same session, so a run whose
    jobs have all ended becomes ``failed`` with ``completed_at`` set (spec
    6.2) — without the roll-up the run would sit ``running`` forever.

    ``now`` is injectable so callers (tests) can be deterministic; it
    defaults to the current UTC time. Returns the number of jobs reaped.
    """
    from redsim.services.runs import rollup_run_status

    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=ttl_seconds)

    stale = (
        sess.query(Job)
        .filter(Job.status == "running", Job.started_at < cutoff)
        .all()
    )
    run_ids: set[str] = set()
    for job in stale:
        # The query already constrains to status == "running", so this is
        # always the legal running → failed edge; routing it through the guard
        # keeps the lifecycle single-sourced.
        set_job_status(job, "failed")
        job.completed_at = now
        job.error = REAPED_ERROR
        _mark_stage_table_failed(sess, job)
        run_ids.add(job.run_id)
    sess.flush()
    for run_id in sorted(run_ids):
        try:
            status = rollup_run_status(sess, run_id)
        except LookupError:
            logger.warning("reaper: run %s missing while rolling up status", run_id)
            continue
        logger.info("reaper: run %s rolled up to %r", run_id, status)
    if stale:
        logger.warning("reaper flipped %d stale running job(s) to failed", len(stale))
    return len(stale)


@app.task(name="redsim.reap_stale_jobs")
def reap_stale_jobs() -> dict[str, Any]:
    """Beat-scheduled entry point: open a session and reap stale jobs."""
    from redsim.config import load_config
    from redsim.db.session import get_session

    logger.info("reap_stale_jobs begin")
    ttl_seconds = load_config().job_max_runtime_seconds
    with get_session() as sess:
        reaped = reap_stale_jobs_in_session(sess, ttl_seconds)
    logger.info("reap_stale_jobs finished reaped=%d", reaped)
    return {"reaped": reaped}
