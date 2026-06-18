"""POST /v1/agents/{agent_name}/run — invoke a registered CAI agent.

F6 admission entry: RBAC → ``create_agent_job`` → return a JobHandle.
The admission service emits the ``agent.run`` audit row *before* the
Run and Job rows are created and *before* Celery is touched, so a
worker crash mid-enqueue can never produce a row without a matching
chain event. No business logic / dispatch happens here — the worker
task does the execution.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.agents import create_agent_job

router = APIRouter(prefix="/agents", tags=["agents"])


class RunAgentBody(BaseModel):
    project_id: str | None = None
    prompt: str | None = None
    execute: bool = False
    target: str | None = None
    finding_id: str | None = None
    repo_path: str | None = None
    override_authorized: bool = False


@router.get("")
def list_agents_route(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List the registered CAI agents (name, domain, effect, wired).

    Read-only catalog: any authenticated user may enumerate the roster
    (the picker in ``web/src/app/agents/page.tsx`` consumes this). The
    per-run RBAC + human gate still apply at ``POST /{agent_name}/run``.
    Importing the ``aegis.agents`` package (not ``registry`` directly)
    triggers built-in registration, so the list is populated.
    """
    from aegis.agents import list_agents

    return {"agents": list_agents()}


@router.post("/{agent_name}/run")
def run_agent(
    agent_name: str,
    body: RunAgentBody = RunAgentBody(),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Enqueue an agent invocation through the admission service."""
    project_id = body.project_id or "default"
    prompt = body.prompt
    if not prompt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="prompt required")
    # ``execute`` is the human-gate flip: running an active/external agent
    # for real needs the approver role, exactly like fix.apply. Without it
    # the worker returns a proposal (status="pending_approval").
    execute = bool(body.execute)
    check(user, Action.AGENT_EXECUTE if execute else Action.AGENT_RUN,
          project_id)

    config = load_config()
    try:
        handle = create_agent_job(
            agent_name=agent_name,
            prompt=prompt,
            target=body.target,
            finding_id=body.finding_id,
            repo_path=body.repo_path,
            execute=execute,
            project_id=project_id, actor=f"user:{user.sub}",
            config=config,
            audit_writer=resolve_writer(config),
            override_authorized=bool(body.override_authorized),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc

    return handle.to_response()
