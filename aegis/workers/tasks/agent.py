"""agent.run — Celery wrapper that dispatches a registered CAI agent.

Phase 4 v0.3.1 F6 execution boundary (mirrors ``scan.start``): the
worker re-authorizes the target through ``safety.authorize`` against
the bootstrap-supplied ``PostgresAuditWriter`` — never trusting the
admission-time allowlist decision blindly — then hands the prompt and
``AgentContext`` to the registry ``dispatch``. The audit row carries
the worker actor and is correlated with the admission row by ``run_id``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aegis.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)


@app.task(name="aegis.agent_run", bind=True, max_retries=2)
def agent_run(self: Task, job_id: str) -> dict[str, Any]:
    from sqlalchemy import select

    from aegis.agents import AgentContext, dispatch
    from aegis.config import load_config
    from aegis.db.models import Job, Project
    from aegis.llm.budget import enforce_budget_for_run
    from aegis.llm.router import BudgetExceeded
    from aegis.safety import authorize
    from aegis.workers.bootstrap import task_context

    config = load_config()
    logger.info("agent_run begin job_id=%s", job_id)
    with task_context(job_id, task=self) as ctx:
        if ctx.skip:
            logger.info("agent_run skipped job_id=%s", job_id)
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

        # Budget gate for this DB-backed run (after authorize, before dispatch —
        # the same authorize→budget→run order the fix path uses). The CAI agents
        # build their model directly (not via ``router.route``), so the router's
        # budget hook never sees an agent run; this is the chokepoint that
        # enforces the project (and org) cap and fail-closes under
        # ``llm_budget_strict``. A worker job always carries a ``project_id``, so
        # this is always a DB-backed run; the org tier is resolved from the
        # project for the monthly cap.
        org_id = ctx.session.execute(
            select(Project.org_id).where(Project.id == ctx.project_id)
        ).scalar_one_or_none()
        try:
            enforce_budget_for_run(ctx.project_id, org_id=org_id, config=config)
        except BudgetExceeded as exc:
            return {"run_id": ctx.run_id, "agent": agent_name,
                    "status": "error", "error": f"BudgetExceeded: {exc}"}

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
        logger.info("agent_run finished job_id=%s agent=%s status=%s",
                    job_id, agent_name, result.status)
        return {
            "run_id": ctx.run_id, "agent": agent_name,
            "status": result.status,
            "output_len": len(result.output or ""),
        }
