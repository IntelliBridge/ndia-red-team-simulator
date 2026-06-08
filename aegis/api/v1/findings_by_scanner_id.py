"""Backwards-compat lookup for the pre-Phase-4 finding URL shape.

Phase 4 v0.3.1 F9 moved the Finding PK from the scanner-supplied
identifier to an internal UUID. Anyone holding a pre-v0.3.1 URL of the
form ``/v1/findings/vuln-0001`` would now 404. This route lets them
resolve the same content via ``/v1/findings/by-scanner-id?run=&scanner_id=``.

Marked deprecated; sunset planned for v0.5.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import ensure_project_access
from aegis.api.v1.findings import _finding_to_dict

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/by-scanner-id", deprecated=True)
def lookup_by_scanner_id(
    run: str,
    scanner_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Resolve a finding by ``(run_id, scanner_finding_id)``. Deprecated."""
    from aegis.db.models import Finding
    from aegis.db.session import get_session

    with get_session() as sess:
        row = sess.execute(
            select(Finding).where(
                Finding.run_id == run,
                Finding.scanner_finding_id == scanner_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(f"no finding with scanner_finding_id={scanner_id!r} "
                        f"on run {run!r}"),
            )
        ensure_project_access(user, row.project_id)
        return _finding_to_dict(row, scanner_finding_id=True)
