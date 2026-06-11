"""Target management service.

Phase 4 v0.3.1 F6: admission boundary for ``target.manage``. The API
route calls these helpers so the create/delete event lands on the
canonical audit chain before the DB row is mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from aegis.config import AegisConfig
from aegis.safety import authorize


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
    audit_writer,
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
    return TargetRecord(id=tid, project_id=project_id, kind=kind,
                        value=value, verified=False)


def delete_target(
    *,
    target_id: str,
    actor: str,
    config: AegisConfig,
    audit_writer,
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


class TargetVerificationError(Exception):
    """Raised when an ownership-verification check does not pass.

    The API maps this to 422 (the request was well-formed but the operator
    has not yet proven control of the target). The message is operator-safe
    — it never carries the verification secret.
    """


def verify_target(
    session,
    target_id: str,
    *,
    actor: str,
    audit_writer=None,
    config: AegisConfig | None = None,
):
    """Prove the operator controls a target, then mark it ``verified``.

    Dispatches on ``Target.kind``:

    - ``url`` → a DNS TXT record on the host must carry the deterministic
      ``expected_dns_token``.
    - ``github_repo`` → the linked GitHub App installation must access the repo.
    - ``image`` → unsupported (raises ``TargetVerificationError``).

    On success: sets ``verified=True``, flushes, and emits a secret-free
    ``target.verify`` audit event (mirroring ``create_target``: detail carries
    kind + matched bool, never the token/secret). On failure: leaves
    ``verified`` untouched and raises ``TargetVerificationError`` with the
    reason. ``LookupError`` if the target is unknown.

    Returns the (refreshed) ``Target`` on success; the verification ``method``
    and ``detail`` are attached as ``target.verify_method`` /
    ``target.verify_detail`` transient attributes so the API can echo them
    without re-running the check.
    """
    from aegis.config import load_config
    from aegis.db.models import Target
    from aegis.services.target_verify import (
        expected_dns_token,
        verify_dns_txt,
        verify_github_repo,
    )

    cfg = config or load_config()

    target = session.get(Target, target_id)
    if target is None:
        raise LookupError(f"target not found: {target_id}")

    if target.kind == "url":
        expected = expected_dns_token(target, config=cfg)
        matched, detail = verify_dns_txt(target.value, expected)
        method = "dns-txt"
    elif target.kind == "github_repo":
        matched, detail = verify_github_repo(target.value, target.installation_id)
        method = "github-app"
    elif target.kind == "image":
        raise TargetVerificationError(
            "image targets cannot be ownership-verified "
            "(no DNS/GitHub ownership channel for a container image)"
        )
    else:
        raise TargetVerificationError(
            f"unsupported target kind for verification: {target.kind!r}"
        )

    if audit_writer is not None:
        audit_writer.append(
            action="target.verify",
            actor=actor,
            target=target.value,
            allowlist_check="n/a",
            override=False,
            success=matched,
            detail={
                "actor": actor,
                "target_id": target_id,
                "kind": target.kind,
                "method": method,
                "matched": matched,
            },
            project_id=target.project_id,
        )

    if not matched:
        raise TargetVerificationError(detail)

    target.verified = True
    session.flush()
    # Transient attributes for the API to echo (not persisted columns).
    target.verify_method = method
    target.verify_detail = detail
    return target
