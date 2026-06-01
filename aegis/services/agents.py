"""Agent orchestration service.

Phase 4 v0.3.1 F6 splits this layer into the same two boundaries the
scan and fix services use:

- **Admission** (``create_agent_job``): authorize → create ``Run`` +
  ``Job`` rows → emit a chained audit event via the supplied
  ``audit_writer`` → enqueue the Celery task. Cheap, synchronous,
  request-scoped. Called from API write routes. The audit row's
  ``created_at`` precedes the worker setting the job's
  ``celery_task_id``, so the chain stays consistent even if the worker
  crashes mid-task. NO business logic / dispatch lives here.
- **Execution** (``aegis.workers.tasks.agent.agent_run``): the long-
  running CAI agent ``dispatch`` call. Called from the Celery worker,
  which re-authorizes before invoking the agent.

Unlike ``create_fix_job`` (which attaches to a caller-supplied
``run_id``), an agent invocation mints its OWN ``Run`` — mirroring
``create_scan_job`` — because an agent run is a top-level unit of work,
not a child of an existing scan run.
"""

from __future__ import annotations

from uuid import uuid4

from aegis.config import AegisConfig
from aegis.safety import authorize
from aegis.services.scans import JobHandle


def create_agent_job(
    *,
    agent_name: str,
    prompt: str,
    project_id: str,
    actor: str,
    config: AegisConfig,
    audit_writer,
    target: str | None = None,
    finding_id: str | None = None,
    repo_path: str | None = None,
    execute: bool = False,
    override_authorized: bool = False,
    enqueue: bool = True,
) -> JobHandle:
    """Admission boundary for ``agent.run`` / ``agent.execute``.

    Order of operations (load-bearing):

    1. ``authorize()`` — emits the chained audit row through
       ``audit_writer``. The action is ``agent.execute`` when ``execute``
       is set (the state-changing step) and ``agent.run`` otherwise, so the
       audit trail distinguishes a proposal from an approved action.
       ``target`` may be ``None`` (a code agent need not point at a live
       target); the allowlist check tolerates that exactly as the fix
       service does. If the check fails this raises ``AuthorizationError``
       *before* any DB row is created.
    2. Insert a fresh ``Run`` (flush — FK precedence), insert ``Job``.
    3. Enqueue the Celery task. ``celery_task_id`` is only stamped on
       the Job by the worker on pickup, so the chain row's ``ts``
       precedes the task-id assignment.

    A worker crash anywhere in step 3 leaves a chained audit row + a
    ``queued`` job — never a half-state. The RBAC role check
    (``agent.execute`` needs ``approver``) is enforced at the route before
    this service is called.
    """
    authorize(
        "agent.execute" if execute else "agent.run", target,
        allowlist=config.target_allowlist,
        override_authorized=override_authorized,
        actor=actor, writer=audit_writer,
        project_id=project_id,
        detail={"actor": actor, "agent": agent_name, "target": target,
                "finding_id": finding_id, "prompt_set": bool(prompt),
                "execute": execute},
    )

    from aegis.db.models import Job, Run
    from aegis.db.session import get_session

    run_id = f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Run(
            id=run_id, project_id=project_id, mode="api",
            status="queued", scanner=None, created_by=actor,
            stage_table={},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="agent.run", status="queued",
            created_by=actor,
            detail={"agent": agent_name, "prompt": prompt,
                    "target": target, "finding_id": finding_id,
                    "repo_path": repo_path, "execute": execute},
        ))
        sess.flush()

    if enqueue:
        try:
            from aegis.workers.tasks.agent import agent_run
            agent_run.delay(job_id)
        except Exception:
            # Broker unreachable: row stays queued, picked up next start.
            pass

    return JobHandle(run_id=run_id, job_id=job_id)
