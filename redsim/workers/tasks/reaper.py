"""redsim.reap_stale_jobs — periodic cleanup for crashed jobs.

A task that dies mid-run is left ``status="running"`` forever: the
``task_context`` redelivery guard (``workers.bootstrap``) deliberately
skips re-running non-``queued`` jobs (fail-closed), so nothing flips a
crashed job to ``failed``. This reaper is the complementary cleanup —
it runs on the Celery beat schedule, finds ``running`` jobs whose
``started_at`` is older than the configured TTL, and marks them failed.

Unlike the job-scoped worker tasks, the reaper scans *all* jobs, so it
manages its own session directly rather than going through
``task_context``. The core logic lives in ``reap_stale_jobs_in_session``
so it's unit-testable without Celery or a real DB.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from redsim.db.models import Job
from redsim.workers.celery_app import app
from redsim.workers.job_state import set_job_status

logger = logging.getLogger(__name__)


def reap_stale_jobs_in_session(
    sess: Session, ttl_seconds: int, now: datetime | None = None
) -> int:
    """Flip ``running`` jobs older than the TTL to ``failed``.

    Selects ``Job`` rows where ``status == "running"`` and
    ``started_at < now - ttl_seconds`` and stamps each with
    ``status="failed"``, ``completed_at=now`` and a reaper ``error``.

    ``now`` is injectable so callers (tests) can be deterministic; it
    defaults to the current UTC time. Returns the number of jobs reaped.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ttl_seconds)

    stale = (
        sess.query(Job)
        .filter(Job.status == "running", Job.started_at < cutoff)
        .all()
    )
    for job in stale:
        # The query already constrains to status == "running", so this is
        # always the legal running → failed edge; routing it through the guard
        # keeps the lifecycle single-sourced.
        set_job_status(job, "failed")
        job.completed_at = now
        job.error = "reaped: exceeded max runtime TTL"
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
