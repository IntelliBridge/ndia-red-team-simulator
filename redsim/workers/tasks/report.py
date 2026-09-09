"""report.render — re-emit markdown/json/html for a run.

Two branches (see ``redsim.services.reports``): an adversarial-ML campaign
(``Run.scanner`` ``ml.*`` or an ``ml_campaigns`` row) is re-rendered from its
``ml.run_record`` artifact with the reviewer notes overlay and recorded as
``Artifact`` rows after the ``report.render`` audit event; any other run keeps
the retained filesystem renderer over its ``RedsimFinding`` list.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

    from redsim.workers.bootstrap import TaskContext

logger = logging.getLogger(__name__)


def _ml_campaign(ctx: TaskContext) -> dict[str, Any] | None:
    """The campaign row when this run is an ML campaign, else ``None``."""
    from redsim.services.reports import ml_campaign_row

    try:
        from redsim.db.models import Run

        run = ctx.session.get(Run, ctx.run_id)
        scanner = getattr(run, "scanner", None)
    except Exception:  # noqa: BLE001 - no row, no ML branch
        scanner = None
    is_ml_scanner = isinstance(scanner, str) and scanner.startswith("ml.")
    row = ml_campaign_row(ctx.session, ctx.run_id)
    if row is None and not is_ml_scanner:
        return None
    return row if row is not None else {"run_id": ctx.run_id}


@app.task(name="redsim.report_render", bind=True, max_retries=2)
def report_render(self: Task, job_id: str) -> dict[str, Any]:
    from redsim.schema import RedsimFinding
    from redsim.services.reports import render_campaign_report_artifacts, render_reports
    from redsim.workers.bootstrap import task_context

    logger.info("report_render begin job_id=%s", job_id)
    with task_context(job_id, task=self) as ctx:
        if ctx.skip or ctx.run_state is None:
            logger.info("report_render skipped job_id=%s", job_id)
            return {"job_id": job_id, "skipped": True}
        campaign = _ml_campaign(ctx)
        if campaign is not None:
            if ctx.audit_writer is None:
                # Fail closed: a report without its audit row is not rendered.
                raise RuntimeError("report_render needs an audit writer for an ML campaign")
            outcome = render_campaign_report_artifacts(
                session=ctx.session, blob_store=ctx.blob_store, run_state=ctx.run_state,
                audit_writer=ctx.audit_writer, actor=ctx.actor, run_id=ctx.run_id,
                project_id=ctx.project_id, job_id=job_id, campaign=campaign,
            )
            logger.info("report_render finished job_id=%s run_id=%s ml formats=%s",
                        job_id, ctx.run_id, outcome.formats)
            return {"job_id": job_id, "run_id": ctx.run_id, "source": "ml.run_record",
                    "record_sha256": outcome.record_sha256, "formats": outcome.formats,
                    "artifacts": outcome.artifacts,
                    "reviewer_notes_present": outcome.reviewer_notes_present,
                    "finding_states": outcome.finding_states,
                    "markdown_path": outcome.location("md"),
                    "json_path": outcome.location("json"),
                    "html_path": outcome.location("html")}
        raw = ctx.run_state.load_findings()
        findings = [RedsimFinding.from_dict(f) for f in raw]
        result = render_reports(run_state=ctx.run_state,
                                findings=findings, html=True)
        logger.info("report_render finished job_id=%s findings=%d", job_id, len(findings))
        return {"job_id": job_id,
                "markdown_path": result.markdown_path,
                "json_path": result.json_path,
                "html_path": result.html_path}
