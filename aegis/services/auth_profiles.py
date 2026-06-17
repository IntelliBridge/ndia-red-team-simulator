"""DAST auth-profile management service.

Admission boundary for ``auth_profile.manage``: the API route calls these
helpers so every create/delete lands on the canonical audit chain before
the DB row is mutated (mirrors ``services.targets``).

Secret handling invariants:

- The plaintext secret is encrypted (``security_utils.secrets``) before
  anything is written; only ``secret_ciphertext`` is persisted.
- Audit ``detail`` payloads carry only non-secret metadata (name, kind,
  profile id) — never the secret, never the ciphertext.
- ``resolve_auth_for_scan`` is the single decryption point, used by the
  worker just before an authenticated scan. Its name and return shape
  are a contract with the worker — do not change them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from aegis.security_utils.secrets import decrypt_secret, encrypt_secret

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from aegis.audit.chain import AuditWriter
    from aegis.db.models import AuthProfile

VALID_KINDS = frozenset({"form", "bearer", "header", "cookie"})


class DuplicateAuthProfileError(Exception):
    """An auth profile with this (project_id, name) already exists."""


def _audit(audit_writer: AuditWriter | None, *, action: str, actor: str,
           project_id: str, detail: dict[str, Any]) -> None:
    """Emit the chained audit event for an auth-profile mutation.

    Goes through ``authorize()`` with ``target=None`` (no network target
    is involved), which records ``allowlist_check="n/a"``. When no writer
    is supplied, ``resolve_writer`` picks the canonical backend for the
    environment — there is no silent no-audit path.
    """
    from aegis.audit.chain import resolve_writer
    from aegis.config import load_config
    from aegis.safety import authorize

    writer = audit_writer if audit_writer is not None else resolve_writer(load_config())
    authorize(
        action, None,
        allowlist=[],
        actor=actor, writer=writer,
        project_id=project_id,
        detail=detail,
    )


def create_auth_profile(
    session: Session,
    *,
    project_id: str,
    name: str,
    kind: str,
    config: dict[str, Any] | None = None,
    secret: str,
    actor: str = "system",
    audit_writer: AuditWriter | None = None,
) -> AuthProfile:
    """Admission boundary for creating an auth profile.

    Validates ``kind``, encrypts ``secret`` (failing closed if the key is
    unset — before any audit row or DB mutation), emits the chained
    ``auth_profile.create`` event, then inserts the row. The plaintext
    secret is never stored or logged.
    """
    if kind not in VALID_KINDS:
        raise ValueError(
            f"invalid auth-profile kind: {kind!r} "
            f"(expected one of {sorted(VALID_KINDS)})"
        )

    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    from aegis.db.models import AuthProfile

    existing = session.execute(
        select(AuthProfile.id).where(AuthProfile.project_id == project_id,
                                     AuthProfile.name == name)
    ).scalar_one_or_none()
    if existing is not None:
        raise DuplicateAuthProfileError(
            f"auth profile '{name}' already exists on project {project_id}")

    # Encrypt before the audit emission so a missing/invalid key aborts
    # without leaving a create event that has no matching row.
    ciphertext = encrypt_secret(secret)

    profile_id = f"authprof-{uuid4().hex[:12]}"
    _audit(audit_writer, action="auth_profile.create", actor=actor,
           project_id=project_id,
           detail={"actor": actor, "op": "create", "profile_id": profile_id,
                   "name": name, "kind": kind})

    profile = AuthProfile(
        id=profile_id, project_id=project_id, name=name, kind=kind,
        config=dict(config or {}), secret_ciphertext=ciphertext,
    )
    session.add(profile)
    try:
        session.flush()
    except IntegrityError as exc:
        # Race with a concurrent create: the unique constraint is the
        # source of truth; surface the same error as the pre-check.
        raise DuplicateAuthProfileError(
            f"auth profile '{name}' already exists on project {project_id}"
        ) from exc
    return profile


def list_auth_profiles(session: Session, project_id: str) -> list[AuthProfile]:
    """Return the project's auth profiles. Never decrypts anything."""
    from sqlalchemy import select

    from aegis.db.models import AuthProfile

    return list(
        session.execute(
            select(AuthProfile)
            .where(AuthProfile.project_id == project_id)
            .order_by(AuthProfile.created_at, AuthProfile.id)
        ).scalars().all()
    )


def delete_auth_profile(
    session: Session,
    profile_id: str,
    *,
    actor: str = "system",
    audit_writer: AuditWriter | None = None,
) -> str:
    """Admission boundary for deleting an auth profile.

    Emits the chained ``auth_profile.delete`` event before the row is
    removed. Raises ``LookupError`` if the profile does not exist.
    """
    from aegis.db.models import AuthProfile

    profile = session.get(AuthProfile, profile_id)
    if profile is None:
        raise LookupError(f"auth profile not found: {profile_id}")

    _audit(audit_writer, action="auth_profile.delete", actor=actor,
           project_id=profile.project_id,
           detail={"actor": actor, "op": "delete", "profile_id": profile_id,
                   "name": profile.name, "kind": profile.kind})

    session.delete(profile)
    session.flush()
    return profile_id


def resolve_auth_for_scan(session: Session, profile_id: str) -> dict[str, Any]:
    """Decrypt and return the auth material for a worker-side scan.

    Contract with the authenticated-DAST worker — do not change the
    name or return shape::

        {"kind": <str>, "config": {<non-secret fields>}, "secret": <str>}

    The returned dict contains the plaintext secret: callers must keep it
    out of logs, job ``detail`` blobs, and audit events. Raises
    ``LookupError`` for an unknown profile and ``AuthProfilesKeyError``
    if the encryption key is unset.
    """
    from aegis.db.models import AuthProfile

    profile = session.get(AuthProfile, profile_id)
    if profile is None:
        raise LookupError(f"auth profile not found: {profile_id}")

    return {
        "kind": profile.kind,
        "config": dict(profile.config or {}),
        "secret": decrypt_secret(profile.secret_ciphertext),
    }
