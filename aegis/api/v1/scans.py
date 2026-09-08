"""POST /v1/scans — enqueue a scan via the admission service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.safety import AuthorizationError
from aegis.services.scans import create_scan_job

router = APIRouter(prefix="/scans", tags=["scans"])


class StartScanBody(BaseModel):
    project_id: str | None = None
    target: str | None = None
    scanner: str = "strix"
    instruction: str | None = None
    # Authenticated DAST: id of a stored AuthProfile. Only the id travels
    # through admission; the worker resolves (decrypts) it at execution time.
    auth_profile_id: str | None = None
    override_authorized: bool = False


@router.post("")
def start(
    body: StartScanBody = StartScanBody(),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """F6 admission entry — RBAC → ``create_scan_job`` → return JobHandle.

    The admission service emits the ``scan.start`` audit row *before*
    the Run and Job rows are created and *before* Celery is touched,
    so a worker crash mid-enqueue can never produce a row without a
    matching chain event.
    """
    project_id = body.project_id or "default"
    target = body.target
    scanner = body.scanner
    if not target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="target required")
    from aegis.scanners import list_scanners
    if scanner not in list_scanners():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"unknown scanner: {scanner}")
    check(user, Action.SCAN_START, project_id)

    config = load_config()
    try:
        handle = create_scan_job(
            target=target, scanner=scanner,
            project_id=project_id, actor=f"user:{user.sub}",
            instruction=body.instruction,
            auth_profile_id=body.auth_profile_id,
            config=config,
            audit_writer=resolve_writer(config),
            override_authorized=bool(body.override_authorized),
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=str(exc)) from exc

    return handle.to_response()
