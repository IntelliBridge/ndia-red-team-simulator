"""Per-project Foundry integration settings (owner request of 2026-09-10).

The Exports page lets a project admin choose the Foundry dataset, the bearer
``AuthProfile`` that holds the token and whether finished campaigns push on
their own. The host, the operator attestation and the egress allowlist stay in
the process environment of the API and the default worker (spec 27.3, D3):
this module never reads a token and never stores a host.

Stored shape, ``projects.ml_integrations`` (migration ``0013_foundry_auto_push``)::

    {"foundry": {"dataset_rid": str | None, "auth_profile_id": str | None, "auto_push": bool,
                 "updated_at": str | None, "updated_by": str | None}}

Stdlib, SQLAlchemy and pure redsim modules only: the API process imports it.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from redsim.api.errors import (
    AUTH_PROFILE_KIND_UNSUPPORTED,
    INTEGRATION_DISABLED,
    NOT_FOUND,
    PARAMS_OUT_OF_RANGE,
    ApiError,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.config import RedsimConfig
    from redsim.db.models import Project

FOUNDRY_KEY = "foundry"
SETTINGS_FIELDS: tuple[str, ...] = ("dataset_rid", "auth_profile_id", "auto_push")

Blocker = Literal[
    "integration_disabled",
    "integration_misconfigured",
    "auth_profile_missing",
    "auth_profile_deleted",
    "auth_profile_kind_unsupported",
    "dataset_rid_missing",
]

#: The actor a worker-initiated push admission carries (``detail.requested_by`` on the admission row).
AUTO_PUSH_ACTOR = "worker:auto_push"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def foundry_project_settings(project: Project | None) -> dict[str, Any]:
    """The stored Foundry block of a project, normalised; every key present, ``auto_push`` a bool."""
    raw = getattr(project, "ml_integrations", None) if project is not None else None
    block = raw.get(FOUNDRY_KEY) if isinstance(raw, Mapping) else None
    block = block if isinstance(block, Mapping) else {}
    rid = block.get("dataset_rid")
    profile = block.get("auth_profile_id")
    return {
        "dataset_rid": str(rid) if rid else None,
        "auth_profile_id": str(profile) if profile else None,
        "auto_push": bool(block.get("auto_push", False)),
        "updated_at": block.get("updated_at"),
        "updated_by": block.get("updated_by"),
    }


def foundry_deployment_block(config: RedsimConfig, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """What the operator configured: status, host, the rule that failed, the attestation and the default rid.

    The host is shown to project members here (it is the audit ``target`` of every
    push row already); a token never exists in the environment.
    """
    from redsim.integrations.foundry import FoundryMisconfigured, FoundrySettings, foundry_status

    allowlist = list(getattr(config, "target_allowlist", None) or [])
    status = foundry_status(environ, allowlist=allowlist)
    block: dict[str, Any] = {
        "status": str(status.get("status")), "host": None, "reason": status.get("reason"),
        "attested": bool(status.get("attested")), "default_dataset_rid": None,
    }
    try:
        settings = FoundrySettings.from_env(environ, allowlist=allowlist)
    except FoundryMisconfigured:
        return block
    if settings is not None:
        block["host"] = settings.host
        block["default_dataset_rid"] = settings.dataset_rid
    return block


def _profile_row(session: Session, project_id: str, profile_id: str | None) -> tuple[Any | None, Blocker | None]:
    from redsim.db.models import AuthProfile

    if not profile_id:
        return None, "auth_profile_missing"
    profile = session.get(AuthProfile, profile_id)
    if profile is None or str(profile.project_id) != str(project_id):
        return None, "auth_profile_deleted"
    if getattr(profile, "deleted_at", None) is not None:
        return profile, "auth_profile_deleted"
    if str(profile.kind) != "bearer":
        return profile, "auth_profile_kind_unsupported"
    return profile, None


def foundry_effective(session: Session, project: Project, settings: Mapping[str, Any],
                      deployment: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    """``(effective block, auth profile name)``: what a push from this project would use, and why not."""
    blockers: list[Blocker] = []
    status = str(deployment.get("status"))
    if status == "disabled":
        blockers.append("integration_disabled")
    elif status != "configured":
        blockers.append("integration_misconfigured")
    profile, problem = _profile_row(session, str(project.id), settings.get("auth_profile_id"))
    if problem is not None:
        blockers.append(problem)
    dataset_rid = settings.get("dataset_rid") or deployment.get("default_dataset_rid")
    if not dataset_rid:
        blockers.append("dataset_rid_missing")
    name = str(profile.name) if profile is not None else None
    return {"dataset_rid": dataset_rid, "ready": not blockers, "blockers": blockers}, name


def foundry_view(session: Session, project: Project, config: RedsimConfig,
                 environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The body of ``GET`` and ``PUT /v1/projects/{slug}/integrations/foundry``."""
    settings = foundry_project_settings(project)
    deployment = foundry_deployment_block(config, environ)
    effective, profile_name = foundry_effective(session, project, settings, deployment)
    return {
        "project_id": str(project.id),
        "project": str(project.slug),
        "deployment": deployment,
        "settings": {**settings, "auth_profile_name": profile_name},
        "effective": effective,
    }


def validate_foundry_settings(session: Session, project: Project, body: Any, *, actor: str,
                              config: RedsimConfig, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The merged settings block a ``PUT`` body produces, or the typed :class:`ApiError`.

    Present keys are set, absent keys keep their value, ``null`` clears.
    ``auto_push: true`` needs a configured deployment, a usable bearer profile
    and an effective dataset rid, so a toggle never promises a push that the
    admission would refuse.
    """
    from redsim.integrations.foundry import validate_target_ref

    if body is None or not isinstance(body, Mapping):
        raise ApiError(PARAMS_OUT_OF_RANGE, "the body must be an object with dataset_rid, auth_profile_id and/or "
                       "auto_push", field="body")
    unknown = sorted(set(body) - set(SETTINGS_FIELDS))
    if unknown:
        raise ApiError(PARAMS_OUT_OF_RANGE, f"unknown field(s) {unknown}", field=unknown[0],
                       allowed=list(SETTINGS_FIELDS))
    current = foundry_project_settings(project)
    merged = dict(current)

    if "dataset_rid" in body:
        value = body["dataset_rid"]
        if value is not None and not isinstance(value, str):
            raise ApiError(PARAMS_OUT_OF_RANGE, "dataset_rid must be a string or null", field="dataset_rid")
        try:
            merged["dataset_rid"] = validate_target_ref(value.strip() if isinstance(value, str) else value)
        except ValueError as exc:
            raise ApiError(PARAMS_OUT_OF_RANGE, str(exc), field="dataset_rid") from None
    if "auth_profile_id" in body:
        value = body["auth_profile_id"]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ApiError(PARAMS_OUT_OF_RANGE, "auth_profile_id must be a non-empty string or null",
                           field="auth_profile_id")
        profile_id = value.strip() if isinstance(value, str) else None
        if profile_id is not None:
            profile, problem = _profile_row(session, str(project.id), profile_id)
            if problem in ("auth_profile_missing", "auth_profile_deleted"):
                raise ApiError(NOT_FOUND, f"auth profile {profile_id!r} is not a live profile of this project",
                               field="auth_profile_id")
            if problem == "auth_profile_kind_unsupported":
                kind = str(getattr(profile, "kind", ""))
                raise ApiError(AUTH_PROFILE_KIND_UNSUPPORTED, f"auth profile kind {kind!r} cannot carry a "
                               "Foundry token; the REST API takes Authorization: Bearer (kind 'bearer')",
                               field="auth_profile_id", kind=kind, allowed=["bearer"])
        merged["auth_profile_id"] = profile_id
    if "auto_push" in body:
        value = body["auto_push"]
        if not isinstance(value, bool):
            raise ApiError(PARAMS_OUT_OF_RANGE, "auto_push must be true or false", field="auto_push")
        merged["auto_push"] = value

    if merged["auto_push"]:
        deployment = foundry_deployment_block(config, environ)
        if deployment["status"] != "configured":
            raise ApiError(INTEGRATION_DISABLED, "auto-push needs the Foundry integration configured on this "
                           f"deployment; it is {deployment['status']}" + (f": {deployment['reason']}" if
                                                                          deployment.get("reason") else ""),
                           phase="B", integration=FOUNDRY_KEY, reason=deployment["status"])
        effective, _name = foundry_effective(session, project, merged, deployment)
        if not effective["ready"]:
            raise ApiError(PARAMS_OUT_OF_RANGE, "auto-push needs a usable bearer auth profile and a Foundry "
                           "dataset rid (from the project or the deployment default)", field="auto_push",
                           reason="auto_push_not_ready", blockers=list(effective["blockers"]))

    merged["updated_at"] = _now_iso()
    merged["updated_by"] = actor
    return merged


def store_foundry_settings(project: Project, settings: Mapping[str, Any]) -> None:
    """Write the block; other integration keys (none today) are kept."""
    existing = dict(getattr(project, "ml_integrations", None) or {})
    existing[FOUNDRY_KEY] = dict(settings)
    project.ml_integrations = existing


__all__ = [
    "AUTO_PUSH_ACTOR",
    "FOUNDRY_KEY",
    "SETTINGS_FIELDS",
    "foundry_deployment_block",
    "foundry_effective",
    "foundry_project_settings",
    "foundry_view",
    "store_foundry_settings",
    "validate_foundry_settings",
]
