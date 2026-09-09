"""``redsim.ml_dispatch_deferred``: hand deferred ML campaign jobs to the broker as slots free up.

Register BULK-09 / -21 / -22 (plan 12 wave B3, ``bulk-upload-capacity-cli``). A
project over its concurrency cap has its admissions written as ``queued`` jobs
with ``detail.deferred = true`` and no broker message
(``redsim.services.ml_capacity.admit_or_defer`` + ``mark_deferred``). Two paths
move them on, both through :func:`redsim.services.ml_capacity.dispatch_deferred`:

* the **continuation hook**, :func:`continue_deferred`, called at the end of
  ``redsim.ml_campaign_run`` for the finishing job's project (the assembler adds
  the lazy call; see the function docstring). It runs inline in the finishing
  worker: a handful of row reads and one broker message, never a model load.
  The finishing job is excluded from the slot count because ``task_context``
  commits its terminal status only after the body returns.
* the **beat backstop**, the Celery task below every 60 s
  (``redsim/workers/celery_app.py``): a crashed worker, a broker outage during a
  continuation, or a cancel that freed a slot without a completion all leave a
  deferred job waiting, and the backstop picks it up. It also samples the
  capacity gauges (``redsim_jobs_active``, ``redsim_ml_deferred_runs``,
  ``redsim_ml_daily_budget_used``) from the same rows.

Like the reaper, the task scans across projects and manages its own session
rather than going through ``task_context`` (it is not a job). Counts come from
the jobs table, never from broker inspection. Nothing here imports an ML library.
"""

from __future__ import annotations

import logging
from typing import Any

from redsim.workers.celery_app import app

logger = logging.getLogger(__name__)

#: Beat interval of the backstop (seconds); the continuation hook is the primary path.
BACKSTOP_INTERVAL_S = 60.0
#: Queue the task runs on: fast bookkeeping, next to the reaper.
QUEUE = "default"


def continue_deferred(project_id: str | None, *, finishing_job_id: str | None = None) -> dict[str, Any]:
    """Dispatch the project's deferred jobs now that a slot is (about to be) free. Never raises.

    Hook point (assembler, ``redsim/workers/tasks/ml_campaign.py``): at the end
    of ``ml_campaign_run``, after ``complete(...)`` on every exit path (success,
    failure, cancellation), add::

        from redsim.workers.tasks.capacity import continue_deferred
        continue_deferred(ctx.project_id, finishing_job_id=job_id)

    A lazy import keeps the campaign module free of this one; the call is a
    no-op when the project holds no deferred job. ``finishing_job_id`` is
    excluded from the slot count because its terminal write lands after the body.
    """
    if not project_id:
        return {"dispatched": {}, "n_dispatched": 0}
    try:
        from redsim.db.session import get_session
        from redsim.services.ml_capacity import dispatch_deferred, sample_gauges

        excluded = (finishing_job_id,) if finishing_job_id else ()
        with get_session() as sess:
            report = dispatch_deferred(sess, project_id=project_id, exclude_job_ids=excluded)
            sample_gauges(sess)
        if report.n_dispatched:
            logger.info("capacity: continuation dispatched %d deferred job(s) for project %s",
                        report.n_dispatched, project_id)
        return report.as_dict()
    except Exception:  # noqa: BLE001 - the continuation never fails the finishing run; the backstop retries
        logger.warning("capacity: continuation dispatch failed for project %s", project_id, exc_info=True)
        return {"dispatched": {}, "n_dispatched": 0, "error": "continuation failed; backstop retries"}


def dispatch_deferred_once(project_id: str | None = None) -> dict[str, Any]:
    """One dispatcher pass plus a gauge sample, in its own session (the task body, testable without Celery)."""
    from redsim.db.session import get_session
    from redsim.services.ml_capacity import dispatch_deferred, sample_gauges

    with get_session() as sess:
        report = dispatch_deferred(sess, project_id=project_id)
        sample = sample_gauges(sess)
    return {**report.as_dict(), "gauges": sample}


@app.task(name="redsim.ml_dispatch_deferred", queue=QUEUE)
def ml_dispatch_deferred(project_id: str | None = None) -> dict[str, Any]:
    """Beat-scheduled backstop: dispatch every project's deferred jobs and refresh the gauges."""
    logger.info("ml_dispatch_deferred begin project=%s", project_id or "*")
    result = dispatch_deferred_once(project_id)
    logger.info("ml_dispatch_deferred finished n_dispatched=%d still_deferred=%s",
                int(result.get("n_dispatched", 0)), result.get("still_deferred"))
    return result


__all__ = [
    "BACKSTOP_INTERVAL_S",
    "QUEUE",
    "continue_deferred",
    "dispatch_deferred_once",
    "ml_dispatch_deferred",
]
