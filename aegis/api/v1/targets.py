"""Target management (admin-only).

F6: writes go through ``services.targets`` so each create/delete lands
on the audit chain before the DB row is mutated.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.services import targets as targets_svc

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("")
def list_targets(project: str = "default",
                 user: CurrentUser = Depends(get_current_user)):
    from sqlalchemy import select
    from aegis.db.models import Target
    from aegis.db.session import get_session
    with get_session() as sess:
        rows = sess.execute(select(Target).where(Target.project_id == project))\
            .scalars().all()
        return {"targets": [
            {"id": t.id, "kind": t.kind, "value": t.value,
             "verified": t.verified, "project_id": t.project_id}
            for t in rows
        ]}


@router.post("")
def create_target(body: dict = Body(default_factory=dict),
                  user: CurrentUser = Depends(get_current_user)):
    project_id = body.get("project_id", "default")
    check(user, Action.TARGET_MANAGE, project_id)
    kind = body.get("kind", "url")
    value = body.get("value")
    if not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="value required")
    config = load_config()
    record = targets_svc.create_target(
        project_id=project_id, kind=kind, value=value,
        actor=f"user:{user.sub}", config=config,
        audit_writer=resolve_writer(config),
    )
    return {"id": record.id, "kind": record.kind, "value": record.value,
            "project_id": record.project_id}


@router.delete("/{target_id}")
def delete_target(target_id: str,
                  user: CurrentUser = Depends(get_current_user)):
    from aegis.db.models import Target
    from aegis.db.session import get_session
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
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="target not found")
    return {"deleted": target_id}
