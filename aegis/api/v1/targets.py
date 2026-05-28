"""Target management (admin-only)."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check

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
    from aegis.db.models import Target
    from aegis.db.session import get_session
    tid = f"target-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Target(
            id=tid, project_id=project_id, kind=kind, value=value,
            verified=False,
        ))
        sess.flush()
    return {"id": tid, "kind": kind, "value": value, "project_id": project_id}


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
        check(user, Action.TARGET_MANAGE, target.project_id)
        sess.delete(target)
    return {"deleted": target_id}
