"""agent.run — Celery wrapper that dispatches a registered CAI agent.

Phase 4 v0.3.1 F6 execution boundary (mirrors ``scan.start``): the
worker re-authorizes the target through ``safety.authorize`` against
the bootstrap-supplied ``PostgresAuditWriter`` — never trusting the
admission-time allowlist decision blindly — then hands the prompt and
``AgentContext`` to the registry ``dispatch``. The audit row carries
the worker actor and is correlated with the admission row by ``run_id``.
"""

from __future__ import annotations

from typing import Any

from aegis.workers.celery_app import app


@app.task(name="aegis.agent_run", bind=True, max_retries=2)
def agent_run(self, job_id: str) -> dict[str, Any]:
    from aegis.agents import AgentContext, dispatch
    from aegis.config import load_config
    from aegis.db.models import Job
    from aegis.safety import authorize
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id, task=self) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        job = ctx.session.get(Job, job_id)
        detail = (job.detail if job else {}) or {}
        agent_name = detail["agent"]
        prompt = detail.get("prompt", "")
        target = detail.get("target")
        execute = bool(detail.get("execute", False))
        # Carried from admission: an off-allowlist target the caller explicitly
        # authorized must stay authorized through the worker re-check, or the
        # job would fail here despite a valid admission decision.
        override_authorized = bool(detail.get("override_authorized", False))

        # Worker-side re-check: drift in config.target_allowlist would
        # surface here before the agent runs. The action name carries the
        # execute decision so the execution-side audit row mirrors admission.
        authorize(
            f"{'agent.execute' if execute else 'agent.run'}.{agent_name}", target,
            allowlist=config.target_allowlist,
            override_authorized=override_authorized,
            actor=ctx.actor, writer=ctx.audit_writer,
            run_id=ctx.run_id, project_id=ctx.project_id,
            detail={"actor": ctx.actor, "job_id": job_id,
                    "agent": agent_name, "target": target,
                    "execute": execute},
        )
        result = dispatch(
            agent_name, prompt,
            AgentContext(
                finding_id=detail.get("finding_id"),
                target=target,
                repo_path=detail.get("repo_path"),
                actor=ctx.actor,
                execute=execute,
            ),
        )
        return {
            "run_id": ctx.run_id, "agent": agent_name,
            "status": result.status,
            "output_len": len(result.output or ""),
        }
