"""vulnfixer_render — write the vulnfixer JSON payload to blob storage."""

from __future__ import annotations

import json

from aegis.workers.celery_app import app


@app.task(name="aegis.vulnfixer_render", bind=True, max_retries=1)
def vulnfixer_render(self, job_id: str) -> dict:
    from aegis.adapters.vulnfixer_adapter import export_findings
    from aegis.schema import AegisFinding
    from aegis.workers.bootstrap import task_context

    with task_context(job_id) as ctx:
        raw = ctx.run_state.load_findings()
        findings = [AegisFinding.from_dict(f) for f in raw]
        out_path = ctx.run_state.run_path / "vulnfixer-export.json"
        summary = export_findings(findings, out_path)
        with open(out_path, "rb") as fh:
            content = fh.read()
        ref = ctx.run_state.record_artifact(
            "vulnfixer_export", content, content_type="application/json",
        )
        return {"job_id": job_id, "summary": summary,
                "sha256": ref.sha256, "location": ref.location}
