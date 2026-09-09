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
- ``GET /v1/projects/{slug}/ml-scoring`` — the effective MRI scoring block
  (``source: "project" | "default"``), visible to any member (Phase B,
  REVIEW_REPORTS-28).
- ``PUT /v1/projects/{slug}/ml-scoring`` — admin-only per-project scoring
  override: a full ``ScoringConfig`` whose five weights are all present and
  sum to 1 within 1e-9, or ``null`` to return to the deployment default. A
  partial vector or one that does not sum to 1 is refused (422), never filled
  in or renormalised (spec 15.3, 15.4). Audited as ``project.settings`` with
  digests only, before the write; refusals land as ``success=False`` rows. The
  override reaches only campaigns admitted after it (REVIEW_REPORTS-29).
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, ValidationError

import redsim.api.errors as _errors
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import PARAMS_OUT_OF_RANGE, api_error
from redsim.api.policy import Action, check, ensure_project_access

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.db.models import Project

router = APIRouter(prefix="/projects", tags=["projects"])

#: Audit action of a settings change (project chain; spec 5.11 naming style).
PROJECT_SETTINGS_ACTION = "project.settings"
#: The refusal code for a bad weight vector. ``scoring_weights_invalid`` is the
#: register's name (REVIEW_REPORTS-28); until it has a 17.3 row the in-table
#: ``params_out_of_range`` (also 422) carries the refusal with ``field``.
SCORING_WEIGHTS_INVALID: str = getattr(_errors, "SCORING_WEIGHTS_INVALID", PARAMS_OUT_OF_RANGE)
_WEIGHT_KEYS: tuple[str, ...] = ("acc", "asr", "eps", "conf", "expl")


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

    from redsim.db.models import Project, ProjectMembership, User
    from redsim.db.session import get_session

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

    from redsim.db.models import Project
    project: Project | None = sess.execute(
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

    from redsim.db.models import ProjectMembership, User
    from redsim.db.session import get_session

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
                    body: UpdateSettingsBody = Body(default_factory=UpdateSettingsBody),
                    user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Update project-level settings. Admin-only on the project."""
    from redsim.db.session import get_session

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


# --------------------------------------------------------------------------- ML scoring override


def _sha(payload: Any) -> str | None:
    if payload is None:
        return None
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _weights_refusal(message: str, *, reasons: list[str] | None = None) -> HTTPException:
    return api_error(SCORING_WEIGHTS_INVALID, message, field="ml_scoring.weights", reasons=reasons or [])


def validate_ml_scoring(body: Any) -> dict[str, Any] | None:
    """A full ``ScoringConfig`` dump from ``body``, or ``None`` for ``null`` (reset to default).

    Refuses (``422``) a body that is not an object, a missing ``weights`` block, a
    partial vector (every one of ``acc, asr, eps, conf, expl`` must be present, no
    other key), a non-numeric weight, or a vector that does not sum to 1 within
    1e-9 (``MRIWeights``' own validator). Nothing is filled in or renormalised.
    """
    from redsim.ml.schema import ScoringConfig

    if body is None:
        return None
    if not isinstance(body, dict):
        raise _weights_refusal("ml_scoring must be a ScoringConfig object or null")
    weights = body.get("weights")
    if not isinstance(weights, dict):
        raise _weights_refusal("ml_scoring.weights is required: the full five-key weight vector",
                               reasons=[f"expected keys {list(_WEIGHT_KEYS)}"])
    missing = [k for k in _WEIGHT_KEYS if k not in weights]
    extra = sorted(set(weights) - set(_WEIGHT_KEYS))
    if missing or extra:
        reasons = ([f"missing {missing}"] if missing else []) + ([f"unknown {extra}"] if extra else [])
        raise _weights_refusal("a partial weight vector is never filled in; give all five weights",
                               reasons=reasons)
    for key in _WEIGHT_KEYS:
        value = weights[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise _weights_refusal(f"weight {key} must be a number", reasons=[f"{key}={value!r}"])
    try:
        config = ScoringConfig.model_validate(body)
    except ValidationError as exc:
        reasons = [f"{'.'.join(str(p) for p in err.get('loc', ()))}: {err.get('msg')}" for err in exc.errors()]
        raise _weights_refusal("ml_scoring is not a valid ScoringConfig (weights must sum to 1; never renormalised)",
                               reasons=reasons) from exc
    total = sum(config.weights.as_dict().values())
    if abs(total - 1.0) > 1e-9:  # pragma: no cover - MRIWeights refuses first; kept as the stated rule
        raise _weights_refusal(f"weights sum to {total!r}, not 1", reasons=["never renormalised"])
    return config.model_dump(mode="json")


def _effective_scoring(project: Project) -> dict[str, Any]:
    from redsim.ml.schema import ScoringConfig

    stored = getattr(project, "ml_scoring", None)
    if isinstance(stored, dict) and stored:
        return {"project": project.slug, "project_id": project.id, "source": "project", "ml_scoring": stored,
                "non_default_weights": _non_default(stored)}
    default = ScoringConfig().model_dump(mode="json")
    return {"project": project.slug, "project_id": project.id, "source": "default", "ml_scoring": default,
            "non_default_weights": False}


def _non_default(scoring: dict[str, Any]) -> bool:
    from redsim.ml.compare import is_default_weights

    weights = scoring.get("weights")
    return not is_default_weights(weights if isinstance(weights, dict) else None)


@router.get("/{slug}/ml-scoring")
def get_ml_scoring(slug: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The scoring block campaigns of this project are admitted with, and where it comes from."""
    from redsim.db.session import get_session

    with get_session() as sess:
        project = _resolve_project_by_slug(sess, slug)
        ensure_project_access(user, project.id)
        return _effective_scoring(project)


@router.put("/{slug}/ml-scoring")
def put_ml_scoring(slug: str, body: Any = Body(default=None),
                   user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Set (or with ``null`` clear) the per-project ``ScoringConfig``. Admin-only; audited before the write."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.session import get_session
    from redsim.safety import authorize

    with get_session() as sess:
        project = _resolve_project_by_slug(sess, slug)
        project_id, previous = project.id, getattr(project, "ml_scoring", None)
    check(user, Action.TARGET_MANAGE, project_id)
    writer = resolve_writer(load_config())
    actor = f"user:{user.sub}"
    detail: dict[str, Any] = {
        "project_id": project_id, "field": "ml_scoring",
        "old_sha256": _sha(previous), "new_sha256": _sha(body), "cleared": body is None,
    }
    try:
        validated = validate_ml_scoring(body)
    except HTTPException as exc:
        # A refused override is still on the chain, as a success=False row (digests only).
        refusal = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        writer.append(action=PROJECT_SETTINGS_ACTION, actor=actor, target=None, allowlist_check="n/a",
                      override=False, success=False,
                      detail={**detail, "refusal": refusal.get("code"), "message": refusal.get("message"),
                              "reasons": refusal.get("reasons", [])},
                      run_id=None, project_id=project_id)
        raise
    detail["new_sha256"] = _sha(validated)
    detail["weights"] = None if validated is None else validated["weights"]
    # Audit before mutation (spec 10.5): the vector itself is configuration, not a secret.
    authorize(PROJECT_SETTINGS_ACTION, None, allowlist=[], actor=actor, writer=writer,
              project_id=project_id, detail=detail)
    with get_session() as sess:
        project = _resolve_project_by_slug(sess, slug)
        project.ml_scoring = validated
        sess.flush()
        return _effective_scoring(project)
