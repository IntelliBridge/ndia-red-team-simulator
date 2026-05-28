"""scan.start — run a scanner against a target."""

from __future__ import annotations

from aegis.config import load_config
from aegis.workers.celery_app import app


@app.task(name="aegis.scan_start", bind=True, max_retries=2)
def scan_start(self, job_id: str) -> dict:
    from aegis.workers.bootstrap import task_context
    from aegis.scanners import dispatch
    from aegis.scanners.registry import ScanOptions

    config = load_config()
    with task_context(job_id) as ctx:
        job = ctx.run_state.session.execute(
            __import__("aegis.db.models", fromlist=["Job"]).Job.__table__.select()
            .where(__import__("aegis.db.models", fromlist=["Job"]).Job.id == ctx.job_id)
        ).mappings().first()
        detail = (job.get("detail") if job else {}) or {}
        target = detail.get("target")
        scanner = detail.get("scanner", "strix")
        instruction = detail.get("instruction")

        ctx.audit_writer.append(
            action="scan.start", actor=ctx.actor, target=target,
            allowlist_check="pass", override=False, success=True,
            detail={"job_id": job_id, "scanner": scanner},
            run_id=ctx.run_id, project_id=ctx.project_id,
        )
        result = dispatch(scanner, ctx.run_state,
                          ScanOptions(target=target,
                                      instruction=instruction))
        ctx.run_state.save_findings(result.findings)
        return {
            "run_id": ctx.run_id, "scanner": scanner,
            "findings": len(result.findings),
            "exit_code": result.exit_code,
        }
