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

from aegis.config import AegisConfig
from aegis.safety import authorize

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from aegis.audit.chain import AuditWriter
    from aegis.db.models import Target

logger = logging.getLogger(__name__)


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
    config: AegisConfig,
    audit_writer: AuditWriter,
) -> TargetRecord:
    """Admission boundary for adding a target to a project's allowlist."""
    authorize(
        "target.manage", value,
        allowlist=config.target_allowlist,
        override_authorized=True,    # creating an allowlist entry, not using one
        actor=actor, writer=audit_writer,
        project_id=project_id,
        detail={"actor": actor, "op": "create", "kind": kind, "value": value},
    )

    from aegis.db.models import Target
    from aegis.db.session import get_session
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
    config: AegisConfig,
    audit_writer: AuditWriter,
) -> str:
    """Admission boundary for removing a target from a project's allowlist."""
    from aegis.db.models import Target
    from aegis.db.session import get_session

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
    (``aegis.services.target_verify``) was removed with the pentest domain.
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
    config: AegisConfig | None = None,
) -> Target:
    """Ownership verification — unavailable in this build.

    The DNS-TXT / GitHub-App ownership-verification engine was removed with
    the pentest domain, so this always raises
    :class:`TargetVerificationUnavailable`. ``LookupError`` still fires first
    for an unknown target so callers keep their 404 path.
    """
    from aegis.db.models import Target

    target = session.get(Target, target_id)
    if target is None:
        raise LookupError(f"target not found: {target_id}")

    logger.info("verify_target unavailable target_id=%s kind=%s",
                target_id, target.kind)
    raise TargetVerificationUnavailable(
        "target ownership verification is unavailable: the DNS/GitHub "
        "ownership-verification engine was removed with the pentest domain"
    )
