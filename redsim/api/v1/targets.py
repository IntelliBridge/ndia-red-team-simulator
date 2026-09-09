"""Target management (admin-only).

F6: writes go through ``services.targets`` so each create/delete lands
on the audit chain before the DB row is mutated.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import ApiError
from redsim.api.policy import Action, check, ensure_project_access
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.services import targets as targets_svc

router = APIRouter(prefix="/targets", tags=["targets"])


class CreateTargetBody(BaseModel):
    project_id: str = "default"
    kind: str = "url"
    value: str | None = None


@router.get("")
def list_targets(project: str = "default",
                 user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.db.models import Target
    from redsim.db.session import get_session

    ensure_project_access(user, project)
    with get_session() as sess:
        rows = sess.execute(select(Target).where(Target.project_id == project))\
            .scalars().all()
        targets = [
            {"id": t.id, "kind": t.kind, "value": t.value,
             "verified": t.verified, "project_id": t.project_id}
            for t in rows
        ]
        return {"targets": targets, "count": len(targets)}


@router.post("")
def create_target(body: CreateTargetBody = Body(default_factory=CreateTargetBody),
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = body.project_id
    check(user, Action.TARGET_MANAGE, project_id)
    kind = body.kind
    value = body.value
    config = load_config()
    if kind in targets_svc.ML_TARGET_KINDS:
        # Spec 17.1: ML kinds go through POST /v1/models so the upload rules
        # cannot be bypassed. The service refuses before ``value`` matters and
        # writes the refused audit row; ``400 use_models_route`` comes back.
        value = value or ""
    elif not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="value required")
    try:
        record = targets_svc.create_target(
            project_id=project_id, kind=kind, value=value,
            actor=f"user:{user.sub}", config=config,
            audit_writer=resolve_writer(config),
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    return {"id": record.id, "kind": record.kind, "value": record.value,
            "project_id": record.project_id}


@router.delete("/{target_id}")
def delete_target(target_id: str,
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from redsim.db.models import Target
    from redsim.db.session import get_session
    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="target not found")
        project_id = target.project_id

    check(user, Action.TARGET_MANAGE, project_id)
    config = load_config()
    try:
        targets_svc.delete_target(
            target_id=target_id, actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="target not found") from exc
    return {"deleted": target_id}


@router.get("/{target_id}/verification")
def get_verification(target_id: str,
                     user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Ownership-verification instructions — unavailable in this build.

    Read-gated by ``ensure_project_access`` (404 for an unknown target). The
    DNS-TXT / GitHub-App ownership-verification engine was removed with the
    pentest domain, so this returns 501 rather than faking an instruction set.
    Targets are gated by the project allowlist alone in the ML red-team fork.
    """
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="target not found")
        ensure_project_access(user, target.project_id)

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=("target ownership verification is unavailable: the DNS/GitHub "
                "ownership-verification engine was removed with the pentest "
                "domain"),
    )


@router.post("/{target_id}/verify")
def verify_target(target_id: str,
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Ownership check — unavailable in this build (501).

    Gated at the admin tier via ``check(TARGET_MANAGE)`` plus
    ``ensure_project_access``. 404 for an unknown target. The ownership
    engine was removed with the pentest domain, so the service raises
    ``TargetVerificationUnavailable`` which maps to 501.
    """
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="target not found")
        project_id = target.project_id

    ensure_project_access(user, project_id)
    check(user, Action.TARGET_MANAGE, project_id)

    config = load_config()
    try:
        with get_session() as sess:
            targets_svc.verify_target(
                sess, target_id, actor=f"user:{user.sub}",
                audit_writer=resolve_writer(config), config=config,
            )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="target not found") from exc
    except targets_svc.TargetVerificationUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                            detail=str(exc)) from exc
    # Unreachable today: the service always raises above. Kept so the shape is
    # restored verbatim when the ML re-evaluation path lands.
    raise HTTPException(  # pragma: no cover
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="target ownership verification is unavailable",
    )
