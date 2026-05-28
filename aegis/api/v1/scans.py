"""POST /v1/scans — enqueue a scan via the admission service."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.scans import create_scan_job

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
def start(
    body: dict = Body(default_factory=dict),
    user: CurrentUser = Depends(get_current_user),
):
    """F6 admission entry — RBAC → ``create_scan_job`` → return JobHandle.

    The admission service emits the ``scan.start`` audit row *before*
    the Run and Job rows are created and *before* Celery is touched,
    so a worker crash mid-enqueue can never produce a row without a
    matching chain event.
    """
    project_id = body.get("project_id") or "default"
    target = body.get("target")
    scanner = body.get("scanner", "strix")
    if not target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="target required")
    check(user, Action.SCAN_START, project_id)

    config = load_config()
    try:
        handle = create_scan_job(
            target=target, scanner=scanner,
            project_id=project_id, actor=f"user:{user.sub}",
            instruction=body.get("instruction"),
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
