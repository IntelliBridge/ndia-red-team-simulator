"""vulnfixer_render — write the vulnfixer JSON payload to blob storage."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aegis.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)


@app.task(name="aegis.vulnfixer_render", bind=True, max_retries=1)
def vulnfixer_render(self: Task, job_id: str) -> dict[str, Any]:
    from aegis.runners.vulnfixer_converter import export_findings
    from aegis.schema import AegisFinding
    from aegis.workers.bootstrap import task_context

    logger.info("vulnfixer_render begin job_id=%s", job_id)
    with task_context(job_id) as ctx:
        if ctx.skip or ctx.run_state is None:
            logger.info("vulnfixer_render skipped job_id=%s", job_id)
            return {"job_id": job_id, "skipped": True}
        raw = ctx.run_state.load_findings()
        findings = [AegisFinding.from_dict(f) for f in raw]
        out_path = ctx.run_state.run_path / "vulnfixer-export.json"
        summary = export_findings(findings, out_path)
        with open(out_path, "rb") as fh:
            content = fh.read()
        ref = ctx.run_state.record_artifact(
            "vulnfixer_export", content, content_type="application/json",
        )
        logger.info("vulnfixer_render finished job_id=%s findings=%d location=%s",
                    job_id, len(findings), ref.location)
        return {"job_id": job_id, "summary": summary,
                "sha256": ref.sha256, "location": ref.location}
