"""Project membership endpoints.

Phase 4 v0.3.1 FP — prereq for v0.4.0 UI role gating. The web app's
``useRoles(projectId)`` hook reads from these endpoints to decide
which controls to render. Mutation routes still enforce RBAC server
side; the UI gating is cosmetic.

Endpoints:
- ``GET /v1/projects`` — list projects the caller has membership on,
  with the caller's role per project.
- ``GET /v1/projects/{slug}/membership`` — membership list for a
  single project (visible to any member of that project).
- ``PUT /v1/projects/{slug}/settings`` — admin-only project settings
  patch (daily LLM budget for now).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check, ensure_project_access

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from aegis.db.models import Project

router = APIRouter(prefix="/projects", tags=["projects"])


class UpdateSettingsBody(BaseModel):
    # ``Any`` (not ``int | None``) is deliberate: the handler does its own
    # non-negative-int validation and returns 400 on bad input. A typed
    # ``int`` field would let Pydantic reject bad values as 422 first,
    # changing the existing error contract.
    daily_llm_budget_cents: Any = None


def _project_to_dict(project: Project, *, role: str | None = None) -> dict[str, Any]:
    out = {
        "id": project.id, "slug": project.slug, "name": project.name,
        "org_id": project.org_id,
        "daily_llm_budget_cents": project.daily_llm_budget_cents,
    }
    if role is not None:
        out["role"] = role
    return out


@router.get("")
def list_projects(user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Return the caller's projects with per-project role.

    System callers (workers) get the whole list with ``role="system"``.
    """
    from sqlalchemy import select

    from aegis.db.models import Project, ProjectMembership, User
    from aegis.db.session import get_session

    out: list[dict] = []
    with get_session() as sess:
        if user.is_system:
            projects = sess.execute(select(Project)).scalars().all()
            sys_out = [_project_to_dict(p, role="system") for p in projects]
            return {"projects": sys_out, "count": len(sys_out)}

        db_user = sess.execute(
            select(User).where(User.sub == user.sub)
        ).scalar_one_or_none()
        if db_user is None:
            fallback_out = [_project_to_dict(
                Project(id=pid, slug=pid, name=pid, org_id="org-default"),
                role=role,
            ) for pid, role in user.project_memberships.items()]
            return {"projects": fallback_out, "count": len(fallback_out)}

        rows = sess.execute(
            select(Project, ProjectMembership.role)
            .join(ProjectMembership,
                  ProjectMembership.project_id == Project.id)
            .where(ProjectMembership.user_id == db_user.id)
        ).all()
        for project, role in rows:
            out.append(_project_to_dict(project, role=role))
    return {"projects": out, "count": len(out)}


def _resolve_project_by_slug(sess: Session, slug: str) -> Project:
    from sqlalchemy import select

    from aegis.db.models import Project
    project = sess.execute(
        select(Project).where(Project.slug == slug)
    ).scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"project {slug!r} not found")
    return project


@router.get("/{slug}/membership")
def list_membership(slug: str,
                    user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Return all (user, role) pairs on the project.

    Any member of the project can read; non-members get 403.
    """
    from sqlalchemy import select

    from aegis.db.models import ProjectMembership, User
    from aegis.db.session import get_session

    with get_session() as sess:
        project = _resolve_project_by_slug(sess, slug)
        ensure_project_access(user, project.id)
        rows = sess.execute(
            select(User.sub, User.email, User.display_name,
                   ProjectMembership.role)
            .join(ProjectMembership,
                  ProjectMembership.user_id == User.id)
            .where(ProjectMembership.project_id == project.id)
        ).all()
        members = [
            {"sub": sub, "email": email,
             "display_name": dn or "", "role": role}
            for (sub, email, dn, role) in rows
        ]
        return {
            "project": _project_to_dict(project),
            "members": members,
            "count": len(members),
        }


@router.put("/{slug}/settings")
def update_settings(slug: str,
                    body: UpdateSettingsBody = UpdateSettingsBody(),
                    user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Update project-level settings. Admin-only on the project."""
    from aegis.db.session import get_session

    with get_session() as sess:
        project = _resolve_project_by_slug(sess, slug)
        check(user, Action.TARGET_MANAGE, project.id)

        # The settings surface is intentionally small in v0.3.1: only
        # the LLM budget knob. v0.4.0+ may add CI gate policy, default
        # scanner, etc. — additive only, validated per-field.
        if "daily_llm_budget_cents" in body.model_fields_set:
            v = body.daily_llm_budget_cents
            if v is not None and (not isinstance(v, int) or v < 0):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="daily_llm_budget_cents must be a non-negative int",
                )
            project.daily_llm_budget_cents = v

    return _project_to_dict(project)
