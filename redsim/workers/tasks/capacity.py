"""``redsim.ml_dispatch_deferred``: hand deferred ML campaign jobs to the broker as slots free up.

Register BULK-09 / -21 / -22 (plan 12 wave B3, ``bulk-upload-capacity-cli``). A
project over its concurrency cap has its admissions written as ``queued`` jobs
with ``detail.deferred = true`` and no broker message
(``redsim.services.ml_capacity.admit_or_defer`` + ``mark_deferred``). Two paths
move them on, both through :func:`redsim.services.ml_capacity.dispatch_deferred`:

* the **continuation hook**, :func:`continue_deferred`, run for the finishing
  job's project when ``redsim.ml_campaign_run`` exits on any path; the campaign
  task wraps its body in :func:`deferred_continuation` (two lines, see that
  docstring). It runs inline in the finishing worker: a handful of row reads and
  one broker message, never a model load. The finishing job is excluded from the
  slot count so the hook is correct whether it runs before or after
  ``task_context`` commits the terminal status.
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
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from redsim.workers.celery_app import app

logger = logging.getLogger(__name__)

#: Beat interval of the backstop (seconds); the continuation hook is the primary path.
BACKSTOP_INTERVAL_S = 60.0
#: Queue the task runs on: fast bookkeeping, next to the reaper.
QUEUE = "default"


def continue_deferred(project_id: str | None, *, finishing_job_id: str | None = None) -> dict[str, Any]:
    """Dispatch the project's deferred jobs now that a slot is (about to be) free. Never raises.

    :func:`deferred_continuation` is the hook point for a task body; call this
    directly when the project id is already at hand (a cancel that freed a slot,
    for instance). The call is a no-op when the project holds no deferred job.
    ``finishing_job_id`` is excluded from the slot count because its terminal
    write may land after the body (``task_context`` commits it on exit).
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


def _job_project_id(job_id: str) -> str | None:
    """The project of ``job_id`` from its row, ``None`` when the job or the database is unavailable."""
    try:
        from redsim.db.models import Job
        from redsim.db.session import get_session

        with get_session() as sess:
            job = sess.get(Job, job_id)
            return str(job.project_id) if job is not None and job.project_id else None
    except Exception:  # noqa: BLE001 - a lookup failure is a skipped continuation, never a failed run
        logger.warning("capacity: could not resolve the project of job %s", job_id, exc_info=True)
        return None


@contextmanager
def deferred_continuation(job_id: str, *, project_id: str | None = None) -> Iterator[None]:
    """Run the continuation hook when the wrapped task body exits, on every path. Never raises.

    Hook point (``redsim/workers/tasks/ml_campaign.py``, ``ml_campaign_run``)::

        from redsim.workers.tasks.capacity import deferred_continuation
        ...
        with deferred_continuation(job_id), task_context(job_id, task=self) as ctx:

    Entered first and exited last, the hook runs after ``task_context`` has
    committed the job's terminal status (or rolled its failure path back),
    whether the body returned (success, cancellation, skip) or raised (sandbox
    failure, campaign failure, retry); the exception, if any, propagates
    unchanged. ``project_id`` may be passed when the caller knows it; otherwise
    it is read from the job row, and a job nobody knows is a no-op.
    """
    try:
        yield
    finally:
        continue_deferred(project_id or _job_project_id(job_id), finishing_job_id=job_id)


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
    "deferred_continuation",
    "dispatch_deferred_once",
    "ml_dispatch_deferred",
]
