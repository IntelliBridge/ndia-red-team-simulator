"""fix.generate — call into ``aegis.services.fixes.generate_fix``."""

from __future__ import annotations

from aegis.workers.celery_app import app


@app.task(name="aegis.fix_generate", bind=True, max_retries=2)
def fix_generate(self, job_id: str) -> dict:
    from aegis.config import load_config
    from aegis.db.models import Finding, Job
    from aegis.schema import AegisFinding
    from aegis.services.fixes import generate_fix
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id) as ctx:
        sess = ctx.run_state.session
        job = sess.get(Job, job_id)
        detail = job.detail or {}
        finding_row = sess.get(Finding, detail.get("finding_id"))
        if finding_row is None:
            raise RuntimeError(f"finding {detail.get('finding_id')} missing")
        finding = AegisFinding.from_dict(finding_row.schema_blob)

        outcome = generate_fix(
            run_state=ctx.run_state, finding=finding,
            strategy=detail.get("strategy", "patch"),
            repo=detail.get("repo"),
            apply=bool(detail.get("apply", False)),
            open_pr=bool(detail.get("open_pr", False)),
            branch=detail.get("branch"),
            allow_dirty=bool(detail.get("allow_dirty", False)),
            push=bool(detail.get("push", True)),
            use_golden_patch=bool(detail.get("use_golden_patch", False)),
            actor=ctx.actor, config=config,
        )
        return {
            "job_id": job_id, "finding_id": outcome.finding_id,
            "status": outcome.status, "success": outcome.success,
            "branch": outcome.branch, "commit_hash": outcome.commit_hash,
            "pr_url": outcome.pr_url,
        }
