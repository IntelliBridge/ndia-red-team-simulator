"""DAST auth-profile management (admin-only writes).

Stores authentication material for authenticated DAST scans. Secrets are
Fernet-encrypted at rest (``security_utils.secrets``) and NEVER returned
by any endpoint — workers obtain decrypted material server-side via
``services.auth_profiles.resolve_auth_for_scan``. Writes go through
``services.auth_profiles`` so each create/delete lands on the audit
chain before the DB row is mutated (mirrors ``targets``).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check, ensure_project_access
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.services import auth_profiles as auth_profiles_svc

router = APIRouter(prefix="/auth-profiles", tags=["auth-profiles"])

AuthProfileKind = Literal["form", "bearer", "header", "cookie"]


class CreateAuthProfileBody(BaseModel):
    project_id: str = "default"
    name: str
    kind: AuthProfileKind
    # Non-secret fields only (login_url, username_field, password_field,
    # username, header_name, cookie_name, …). The secret goes in ``secret``.
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str


def _serialize(profile: Any) -> dict[str, Any]:
    # NEVER include secret_ciphertext (or anything derived from it).
    return {
        "id": profile.id,
        "project_id": profile.project_id,
        "name": profile.name,
        "kind": profile.kind,
        "config": dict(profile.config or {}),
        "created_at": profile.created_at.isoformat() if profile.created_at else None,
    }


@router.get("")
def list_auth_profiles(project: str = "default",
                       user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.session import get_session

    ensure_project_access(user, project)
    with get_session() as sess:
        rows = auth_profiles_svc.list_auth_profiles(sess, project)
        profiles = [_serialize(p) for p in rows]
        return {"auth_profiles": profiles, "count": len(profiles)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_auth_profile(body: CreateAuthProfileBody,
                        user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.session import get_session

    check(user, Action.AUTH_PROFILE_MANAGE, body.project_id)
    writer = resolve_writer(load_config())
    with get_session() as sess:
        try:
            profile = auth_profiles_svc.create_auth_profile(
                sess, project_id=body.project_id, name=body.name,
                kind=body.kind, config=body.config, secret=body.secret,
                actor=f"user:{user.sub}", audit_writer=writer,
            )
        except auth_profiles_svc.DuplicateAuthProfileError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=str(exc)) from exc
        return _serialize(profile)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_auth_profile(profile_id: str,
                        user: CurrentUser = Depends(get_current_user)) -> Response:
    from aegis.db.models import AuthProfile
    from aegis.db.session import get_session

    with get_session() as sess:
        profile = sess.get(AuthProfile, profile_id)
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="auth profile not found")
        project_id = profile.project_id

    check(user, Action.AUTH_PROFILE_MANAGE, project_id)
    writer = resolve_writer(load_config())
    with get_session() as sess:
        try:
            auth_profiles_svc.delete_auth_profile(
                sess, profile_id, actor=f"user:{user.sub}", audit_writer=writer)
        except LookupError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="auth profile not found") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
