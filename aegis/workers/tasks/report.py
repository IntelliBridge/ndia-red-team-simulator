"""report.render — re-emit markdown/json/html for a run."""

from __future__ import annotations

from typing import Any

from aegis.workers.celery_app import app


@app.task(name="aegis.report_render", bind=True, max_retries=2)
def report_render(self, job_id: str) -> dict[str, Any]:
    from aegis.schema import AegisFinding
    from aegis.services.reports import render_reports
    from aegis.workers.bootstrap import task_context

    with task_context(job_id) as ctx:
        if ctx.skip or ctx.run_state is None:
            return {"job_id": job_id, "skipped": True}
        raw = ctx.run_state.load_findings()
        findings = [AegisFinding.from_dict(f) for f in raw]
        outcome = render_reports(run_state=ctx.run_state,
                                 findings=findings, html=True)
        return {"job_id": job_id,
                "markdown_path": outcome.markdown_path,
                "json_path": outcome.json_path,
                "html_path": outcome.html_path}
