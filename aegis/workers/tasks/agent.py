"""agent.run — Celery wrapper that dispatches a registered CAI agent.

Phase 4 v0.3.1 F6 execution boundary (mirrors ``scan.start``): the
worker re-authorizes the target through ``safety.authorize`` against
the bootstrap-supplied ``PostgresAuditWriter`` — never trusting the
admission-time allowlist decision blindly — then hands the prompt and
``AgentContext`` to the registry ``dispatch``. The audit row carries
the worker actor and is correlated with the admission row by ``run_id``.
"""

from __future__ import annotations

from aegis.workers.celery_app import app


@app.task(name="aegis.agent_run", bind=True, max_retries=2)
def agent_run(self, job_id: str) -> dict:
    from aegis.agents import AgentContext, dispatch
    from aegis.config import load_config
    from aegis.db.models import Job
    from aegis.safety import authorize
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id) as ctx:
        job = ctx.run_state.session.get(Job, job_id)
        detail = (job.detail if job else {}) or {}
        agent_name = detail.get("agent")
        prompt = detail.get("prompt", "")
        target = detail.get("target")

        # Worker-side re-check: drift in config.target_allowlist would
        # surface here before the agent runs.
        authorize(
            f"agent.execute.{agent_name}", target,
            allowlist=config.target_allowlist,
            actor=ctx.actor, writer=ctx.audit_writer,
            run_id=ctx.run_id, project_id=ctx.project_id,
            detail={"actor": ctx.actor, "job_id": job_id,
                    "agent": agent_name, "target": target},
        )
        result = dispatch(
            agent_name, prompt,
            AgentContext(
                finding_id=detail.get("finding_id"),
                target=target,
                repo_path=detail.get("repo_path"),
                actor=ctx.actor,
            ),
        )
        return {
            "run_id": ctx.run_id, "agent": agent_name,
            "status": result.status,
            "output_len": len(result.output or ""),
        }
