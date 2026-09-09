"""Target management service.

Phase 4 v0.3.1 F6: admission boundary for ``target.manage``. The API
route calls these helpers so the create/delete event lands on the
canonical audit chain before the DB row is mutated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

from redsim.config import RedsimConfig
from redsim.safety import authorize

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.db.models import Target

logger = logging.getLogger(__name__)

#: ``Target.kind`` values owned by ``POST /v1/models`` (spec 17.1: ``400 use_models_route``).
ML_TARGET_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})


@dataclass
class TargetRecord:
    id: str
    project_id: str
    kind: str
    value: str
    verified: bool


def create_target(
    *,
    project_id: str,
    kind: str,
    value: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
) -> TargetRecord:
    """Admission boundary for adding a target to a project's allowlist.

    ML kinds are refused with ``ApiError(use_models_route)`` (spec 17.1) so the
    upload and bundled-registration rules of ``POST /v1/models`` cannot be
    bypassed; the refusal writes its ``success=False`` audit row first.
    """
    if kind in ML_TARGET_KINDS:
        # Lazy: ``redsim.api`` builds the FastAPI app on package import and this
        # service is shared with the CLI.
        from redsim.api.errors import USE_MODELS_ROUTE, ApiError
        from redsim.services.ml_models import audit_refused_admission

        audit_refused_admission(
            audit_writer, action="target.manage", actor=actor, project_id=project_id,
            detail={"op": "create", "kind": kind, "reason": USE_MODELS_ROUTE},
        )
        raise ApiError(
            USE_MODELS_ROUTE,
            f"targets of kind {kind!r} are registered through POST /v1/models",
            field="kind",
        )
    authorize(
        "target.manage", value,
        allowlist=config.target_allowlist,
        override_authorized=True,    # creating an allowlist entry, not using one
        actor=actor, writer=audit_writer,
        project_id=project_id,
        detail={"actor": actor, "op": "create", "kind": kind, "value": value},
    )

    from redsim.db.models import Target
    from redsim.db.session import get_session
    tid = f"target-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Target(id=tid, project_id=project_id,
                        kind=kind, value=value, verified=False))
        sess.flush()
    logger.info("create_target project_id=%s target_id=%s kind=%s",
                project_id, tid, kind)
    return TargetRecord(id=tid, project_id=project_id, kind=kind,
                        value=value, verified=False)


def delete_target(
    *,
    target_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
) -> str:
    """Admission boundary for removing a target from a project's allowlist."""
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise LookupError(f"target not found: {target_id}")
        project_id, value, kind = target.project_id, target.value, target.kind

    authorize(
        "target.manage", value,
        allowlist=config.target_allowlist,
        override_authorized=True,
        actor=actor, writer=audit_writer,
        project_id=project_id,
        detail={"actor": actor, "op": "delete", "kind": kind,
                "value": value, "target_id": target_id},
    )

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is not None:
            sess.delete(target)
    return target_id


class TargetVerificationUnavailable(NotImplementedError):
    """Raised when target ownership verification is not available in this build.

    The DNS-TXT / GitHub-App ownership-verification engine
    (``redsim.services.target_verify``) was removed with the pentest domain.
    The adversarial-ML red-team vertical does not verify target ownership;
    targets are gated by the project allowlist alone. The API maps this to
    501 Not Implemented so the failure is explicit, never faked.
    """


def verify_target(
    session: Session,
    target_id: str,
    *,
    actor: str,
    audit_writer: AuditWriter | None = None,
    config: RedsimConfig | None = None,
) -> Target:
    """Ownership verification — unavailable in this build.

    The DNS-TXT / GitHub-App ownership-verification engine was removed with
    the pentest domain, so this always raises
    :class:`TargetVerificationUnavailable`. ``LookupError`` still fires first
    for an unknown target so callers keep their 404 path.
    """
    from redsim.db.models import Target

    target = session.get(Target, target_id)
    if target is None:
        raise LookupError(f"target not found: {target_id}")

    logger.info("verify_target unavailable target_id=%s kind=%s",
                target_id, target.kind)
    raise TargetVerificationUnavailable(
        "target ownership verification is unavailable: the DNS/GitHub "
        "ownership-verification engine was removed with the pentest domain"
    )
