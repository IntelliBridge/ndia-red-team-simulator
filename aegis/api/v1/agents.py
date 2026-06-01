"""POST /v1/agents/{agent_name}/run — invoke a registered CAI agent.

F6 admission entry: RBAC → ``create_agent_job`` → return a JobHandle.
The admission service emits the ``agent.run`` audit row *before* the
Run and Job rows are created and *before* Celery is touched, so a
worker crash mid-enqueue can never produce a row without a matching
chain event. No business logic / dispatch happens here — the worker
task does the execution.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.agents import create_agent_job

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/{agent_name}/run")
def run_agent(
    agent_name: str,
    body: dict = Body(default_factory=dict),
    user: CurrentUser = Depends(get_current_user),
):
    """Enqueue an agent invocation through the admission service."""
    project_id = body.get("project_id") or "default"
    prompt = body.get("prompt")
    if not prompt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="prompt required")
    # ``execute`` is the human-gate flip: running an active/external agent
    # for real needs the approver role, exactly like fix.apply. Without it
    # the worker returns a proposal (status="pending_approval").
    execute = bool(body.get("execute", False))
    check(user, Action.AGENT_EXECUTE if execute else Action.AGENT_RUN,
          project_id)

    config = load_config()
    try:
        handle = create_agent_job(
            agent_name=agent_name,
            prompt=prompt,
            target=body.get("target"),
            finding_id=body.get("finding_id"),
            repo_path=body.get("repo_path"),
            execute=execute,
            project_id=project_id, actor=f"user:{user.sub}",
            config=config,
            audit_writer=resolve_writer(config),
            override_authorized=bool(body.get("override_authorized", False)),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc))

    return {
        "run_id": handle.run_id, "job_id": handle.job_id,
        "status_url": f"/v1/runs/{handle.run_id}",
    }
