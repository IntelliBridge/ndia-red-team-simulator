"""verify.replay — call into ``aegis.services.verify.verify``."""

from __future__ import annotations

from pathlib import Path

from aegis.workers.celery_app import app


@app.task(name="aegis.verify_replay", bind=True, max_retries=2)
def verify_replay(self, job_id: str) -> dict:
    from aegis.config import load_config
    from aegis.db.models import Finding, Job
    from aegis.schema import AegisFinding
    from aegis.services.verify import verify
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id) as ctx:
        sess = ctx.run_state.session
        job = sess.get(Job, job_id)
        finding_row = sess.get(Finding, (job.detail or {}).get("finding_id"))
        if finding_row is None:
            raise RuntimeError("finding missing")
        finding = AegisFinding.from_dict(finding_row.schema_blob)
        outcome = verify(
            run_state=ctx.run_state, finding=finding,
            repo_path=Path((job.detail or {}).get("repo_path") or ".")
            if (job.detail or {}).get("repo_path") else None,
            actor=ctx.actor, config=config,
        )
        return {"job_id": job_id, "finding_id": outcome.finding_id,
                "status": outcome.status, "strategy": outcome.strategy}
