"""Ticket-sync admission service.

Mirrors ``services.targets``: the API route delegates here so the external
ticket op + the audit event land before/around the DB row mutation. The
audit ``detail`` is secret-free — provider + external_id only, never creds
or the ticket body.

The provider is resolved via ``aegis.integrations.ticket_provider`` (env-
selected, cached). ``sync_finding`` upserts a ``FindingTicket`` keyed on
``(finding_id, provider)`` so re-syncing the same finding is idempotent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from aegis.integrations.ticket_provider import (
    TicketProvider,
    TicketRef,
    resolve_ticket_provider,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from aegis.audit.chain import AuditWriter
    from aegis.db.models import FindingTicket


def sync_finding(
    session: Session,
    finding_id: str,
    *,
    actor: str,
    audit_writer: AuditWriter | None = None,
    provider: TicketProvider | None = None,
) -> FindingTicket:
    """Push a finding to the configured tracker and upsert its FindingTicket.

    Loads the finding, calls the resolved provider's ``sync_finding``,
    upserts a ``FindingTicket`` row keyed on ``(finding_id, provider)``, and
    (when an ``audit_writer`` is supplied) emits a secret-free ``ticket.sync``
    audit event. Returns the persisted ``FindingTicket``.

    Raises ``LookupError`` if the finding is unknown and
    ``TicketProviderError`` if no provider is configured / the push fails.
    """
    from datetime import datetime, timezone

    from sqlalchemy import select

    from aegis.db.models import Finding, FindingTicket

    finding = session.get(Finding, finding_id)
    if finding is None:
        raise LookupError(f"finding not found: {finding_id}")
    project_id = finding.project_id
    schema_blob = dict(finding.schema_blob or {})

    prov = provider or resolve_ticket_provider()
    ref: TicketRef = prov.sync_finding(
        finding_id, schema_blob, project_id=project_id
    )

    now = datetime.now(timezone.utc)
    row = session.execute(
        select(FindingTicket).where(
            FindingTicket.finding_id == finding_id,
            FindingTicket.provider == ref.provider,
        )
    ).scalar_one_or_none()
    if row is None:
        row = FindingTicket(
            id=f"tkt-{uuid4().hex[:12]}",
            finding_id=finding_id,
            project_id=project_id,
            provider=ref.provider,
            external_id=ref.external_id,
            url=ref.url,
            status=ref.status,
            created_at=now,
            synced_at=now,
        )
        session.add(row)
    else:
        row.external_id = ref.external_id
        row.url = ref.url
        row.status = ref.status
        row.synced_at = now
    session.flush()

    if audit_writer is not None:
        audit_writer.append(
            action="ticket.sync",
            actor=actor,
            target=ref.external_id,
            allowlist_check="n/a",
            override=False,
            success=True,
            detail={
                "actor": actor,
                "finding_id": finding_id,
                "provider": ref.provider,
                "external_id": ref.external_id,
            },
            project_id=project_id,
        )
    synced: FindingTicket = row
    return synced


def refresh_status(
    session: Session,
    finding_ticket_id: str,
    *,
    provider: TicketProvider | None = None,
) -> FindingTicket:
    """Pull the external status for a ticket and update the row.

    Raises ``LookupError`` if the ticket id is unknown. Returns the updated
    ``FindingTicket``.
    """
    from datetime import datetime, timezone

    from aegis.db.models import FindingTicket

    row = session.get(FindingTicket, finding_ticket_id)
    if row is None:
        raise LookupError(f"finding ticket not found: {finding_ticket_id}")

    prov = provider or resolve_ticket_provider()
    status = prov.fetch_status(row.external_id)
    row.status = status
    row.synced_at = datetime.now(timezone.utc)
    session.flush()
    refreshed: FindingTicket = row
    return refreshed


def list_tickets(session: Session, finding_id: str) -> list[FindingTicket]:
    """Return all FindingTicket rows for a finding (most-recent first)."""
    from sqlalchemy import select

    from aegis.db.models import FindingTicket

    rows: list[FindingTicket] = list(
        session.execute(
            select(FindingTicket)
            .where(FindingTicket.finding_id == finding_id)
            .order_by(FindingTicket.synced_at.desc())
        ).scalars().all()
    )
    return rows
