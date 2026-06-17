"""Target management (admin-only).

F6: writes go through ``services.targets`` so each create/delete lands
on the audit chain before the DB row is mutated.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check, ensure_project_access
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.services import targets as targets_svc

router = APIRouter(prefix="/targets", tags=["targets"])


class CreateTargetBody(BaseModel):
    project_id: str = "default"
    kind: str = "url"
    value: str | None = None


@router.get("")
def list_targets(project: str = "default",
                 user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from sqlalchemy import select

    from aegis.db.models import Target
    from aegis.db.session import get_session

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
def create_target(body: CreateTargetBody = CreateTargetBody(),
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = body.project_id
    check(user, Action.TARGET_MANAGE, project_id)
    kind = body.kind
    value = body.value
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
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
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
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="target not found") from exc
    return {"deleted": target_id}


@router.get("/{target_id}/verification")
def get_verification(target_id: str,
                     user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Return the instructions an operator must satisfy to verify ownership.

    Read-gated by ``ensure_project_access``. For ``url`` targets this returns
    the exact TXT record name (the host) and value (the per-target token) to
    publish; for ``github_repo`` it states the App-installation linkage
    required. Never exposes the verification secret.
    """
    from aegis.db.models import Target
    from aegis.db.session import get_session
    from aegis.services.target_verify import (
        expected_dns_token,
        extract_host,
    )

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="target not found")
        project_id = target.project_id
        ensure_project_access(user, project_id)
        config = load_config()
        out: dict[str, Any] = {
            "target_id": target.id,
            "kind": target.kind,
            "verified": target.verified,
            "project_id": project_id,
        }
        if target.kind == "url":
            token = expected_dns_token(target, config=config)
            out["method"] = "dns-txt"
            out["record_type"] = "TXT"
            out["record_name"] = extract_host(target.value)
            out["record_value"] = token
            out["instructions"] = (
                f"Add a DNS TXT record on {extract_host(target.value)} with the "
                f"value '{token}', then POST to this target's /verify endpoint."
            )
        elif target.kind == "github_repo":
            out["method"] = "github-app"
            out["installation_id"] = target.installation_id
            out["instructions"] = (
                "Install the Aegis GitHub App on this repository and ensure the "
                "target's installation_id is set, then POST to /verify."
            )
        else:
            out["method"] = "unsupported"
            out["instructions"] = (
                f"targets of kind '{target.kind}' cannot be ownership-verified."
            )
        return out


@router.post("/{target_id}/verify")
def verify_target(target_id: str,
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Run the ownership check; 200 on success, 422 when it fails.

    Gated at the admin tier via ``check(TARGET_MANAGE)`` plus
    ``ensure_project_access``. 404 for an unknown target. The response and
    audit event are secret-free.
    """
    from aegis.db.models import Target
    from aegis.db.session import get_session

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
            verified = targets_svc.verify_target(
                sess, target_id, actor=f"user:{user.sub}",
                audit_writer=resolve_writer(config), config=config,
            )
            payload = {
                "verified": verified.verified,
                "method": getattr(verified, "verify_method", "unknown"),
                "detail": getattr(verified, "verify_detail", ""),
                "target_id": verified.id,
            }
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="target not found") from exc
    except targets_svc.TargetVerificationError as exc:
        # 422: the request is well-formed but the operator hasn't yet proven
        # control of the target. Integer literal avoids the starlette
        # ENTITY->CONTENT constant rename churn across versions.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return payload
