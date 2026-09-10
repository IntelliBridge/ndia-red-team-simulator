"""Auto-push a finished campaign's scorecard to Foundry (owner request of 2026-09-10).

Hook point (``redsim/workers/tasks/ml_campaign.py``, ``ml_campaign_run``)::

    with auto_push_continuation(job_id), deferred_continuation(job_id), task_context(job_id, task=self) as ctx:

Entered first and exited last, so it runs after ``task_context`` committed the
campaign job's terminal status. It fires only when the campaign run
``succeeded`` and the project's Foundry settings say ``auto_push``. It then
goes through the one admission boundary, :func:`redsim.integrations.create_foundry_push`,
exactly as an admin's ``POST /v1/runs/{id}/integrations/foundry`` does: the
same refusals (``success=False`` rows on the campaign chain), the same
``integration.push`` admission row, the same follow-up run and job, the same
enqueue on the ``default`` pool. The campaign run is never touched: a refused
or failed push is recorded on its own run, and this hook never raises.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

CAMPAIGN_SCANNER = "ml.campaign"


def auto_push_after_campaign(job_id: str) -> dict[str, Any] | None:
    """One auto-push decision for a finished campaign job. Never raises.

    Returns ``None`` when nothing applies (not a campaign, not succeeded, the
    toggle off), ``{"refused": <code>}`` when the admission refused (already
    audited by the boundary) and the push JobHandle when it was admitted.
    """
    try:
        from redsim.api.errors import ApiError
        from redsim.audit.chain import resolve_writer
        from redsim.config import load_config
        from redsim.db.models import Job, Project, Run
        from redsim.db.session import get_session
        from redsim.integrations import FoundryPushRequest, create_foundry_push
        from redsim.services.ml_integrations import AUTO_PUSH_ACTOR, foundry_project_settings

        with get_session() as sess:
            job = sess.get(Job, job_id)
            if job is None:
                return None
            run = sess.get(Run, job.run_id)
            if run is None or str(run.scanner or "") != CAMPAIGN_SCANNER or str(run.status) != "succeeded":
                return None
            settings = foundry_project_settings(sess.get(Project, run.project_id))
            if not settings["auto_push"]:
                return None
            run_id, project_id = str(run.id), str(run.project_id)
        config = load_config()
        try:
            handle = create_foundry_push(run_id=run_id, body=FoundryPushRequest(), actor=AUTO_PUSH_ACTOR,
                                         config=config, audit_writer=resolve_writer(config))
        except ApiError as exc:
            logger.warning("foundry auto-push refused for run %s (project %s): %s", run_id, project_id, exc.code)
            return {"refused": exc.code, "campaign_run_id": run_id}
        logger.info("foundry auto-push admitted for run %s: push run %s", run_id, handle.run_id)
        return handle.to_response()
    except Exception:  # noqa: BLE001 - a continuation hook must never fail the campaign job
        logger.warning("foundry auto-push hook failed for job %s", job_id, exc_info=True)
        return None


@contextmanager
def auto_push_continuation(job_id: str) -> Iterator[None]:
    """Run :func:`auto_push_after_campaign` when the wrapped task body exits, on every path. Never raises."""
    try:
        yield
    finally:
        auto_push_after_campaign(job_id)


__all__ = ["CAMPAIGN_SCANNER", "auto_push_after_campaign", "auto_push_continuation"]
