"""Ticket-sync routes for findings.

  POST /v1/findings/{finding_id}/ticket                  -> sync (push)
  GET  /v1/findings/{finding_id}/tickets                 -> list
  POST /v1/findings/{finding_id}/tickets/{ticket_id}/refresh -> pull status

Sync is gated at the remediator+ tier via ``policy.check`` (same bar as
fix.generate / verify.replay); reads are gated by ``ensure_project_access``
on the finding's project. When no provider is configured (the default),
sync returns 409 with a clear message. No response ever carries a secret.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import Action, check, ensure_project_access
from aegis.audit.chain import resolve_writer
from aegis.config import load_config
from aegis.integrations.ticket_provider import TicketProviderError
from aegis.services import finding_tickets as svc

if TYPE_CHECKING:
    from aegis.db.models import FindingTicket

router = APIRouter(prefix="/findings", tags=["tickets"])


def _ticket_to_dict(row: FindingTicket) -> dict[str, Any]:
    """Serialize a ``FindingTicket`` to the wire shape (no secret)."""
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "project_id": row.project_id,
        "provider": row.provider,
        "external_id": row.external_id,
        "url": row.url,
        "status": row.status,
        "synced_at": row.synced_at.isoformat() if row.synced_at else None,
    }


def _load_finding_project(finding_id: str) -> str:
    from aegis.db.models import Finding
    from aegis.db.session import get_session

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="finding not found")
        project_id: str = finding.project_id
        return project_id


@router.post("/{finding_id}/ticket")
def sync_ticket(finding_id: str,
                user: CurrentUser = Depends(get_current_user)) -> JSONResponse:
    from aegis.db.session import get_session

    project_id = _load_finding_project(finding_id)
    check(user, Action.TICKET_SYNC, project_id)

    config = load_config()
    try:
        with get_session() as sess:
            row = svc.sync_finding(
                sess, finding_id,
                actor=f"user:{user.sub}",
                audit_writer=resolve_writer(config),
            )
            payload = _ticket_to_dict(row)
            created = row.created_at == row.synced_at
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="finding not found") from exc
    except TicketProviderError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=str(exc)) from exc

    code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return JSONResponse(status_code=code, content=payload)


@router.get("/{finding_id}/tickets")
def list_finding_tickets(
        finding_id: str,
        user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.session import get_session

    project_id = _load_finding_project(finding_id)
    ensure_project_access(user, project_id)
    with get_session() as sess:
        rows = svc.list_tickets(sess, finding_id)
        tickets = [_ticket_to_dict(r) for r in rows]
    return {"tickets": tickets, "count": len(tickets)}


@router.post("/{finding_id}/tickets/{ticket_id}/refresh")
def refresh_finding_ticket(
        finding_id: str,
        ticket_id: str,
        user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.session import get_session

    project_id = _load_finding_project(finding_id)
    check(user, Action.TICKET_SYNC, project_id)
    try:
        with get_session() as sess:
            from aegis.db.models import FindingTicket
            existing = sess.get(FindingTicket, ticket_id)
            if existing is None or existing.finding_id != finding_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                    detail="ticket not found")
            row = svc.refresh_status(sess, ticket_id)
            return _ticket_to_dict(row)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="ticket not found") from exc
    except TicketProviderError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=str(exc)) from exc
