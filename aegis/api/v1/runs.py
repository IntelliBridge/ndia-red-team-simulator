"""Run listing / inspection routes (read-only in M3; write endpoints land in M4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import accessible_project_ids, ensure_project_access

if TYPE_CHECKING:
    from aegis.db.models import Run

router = APIRouter(prefix="/runs", tags=["runs"])


def _run_to_dict(
    row: Run,
    *,
    created_by: bool = False,
    completed_at: bool = False,
    stage_table: bool = False,
) -> dict[str, Any]:
    """Serialize a ``Run`` row to the API wire shape.

    The six-field core is identical across every run route; the keyword
    flags opt in to the per-route extras (the list view exposes
    ``created_by``, the detail view ``completed_at`` and ``stage_table``)
    so the shared shape stays the single source of truth.
    """
    out: dict[str, Any] = {
        "id": row.id, "project_id": row.project_id,
        "status": row.status, "scanner": row.scanner,
        "mode": row.mode, "created_at": row.created_at,
    }
    if created_by:
        out["created_by"] = row.created_by
    if completed_at:
        out["completed_at"] = row.completed_at
    if stage_table:
        out["stage_table"] = row.stage_table or {}
    return out


@router.get("")
def list_runs(
    project: str | None = None,
    limit: int = 50,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from sqlalchemy import select

    from aegis.db.models import Run
    from aegis.db.session import get_session

    if project is not None:
        ensure_project_access(user, project)
    allowed = accessible_project_ids(user)

    try:
        with get_session() as sess:
            stmt = select(Run).order_by(Run.created_at.desc())
            if project:
                stmt = stmt.where(Run.project_id == project)
            elif allowed is not None:
                stmt = stmt.where(Run.project_id.in_(allowed))
            stmt = stmt.limit(limit)
            rows = sess.execute(stmt).scalars().all()
            payload = [_run_to_dict(r, created_by=True) for r in rows]
        return {"runs": payload, "count": len(payload)}
    except RuntimeError as exc:  # AEGIS_DB_URL missing
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=str(exc)) from exc


@router.get("/{run_id}")
def get_run(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.models import Run
    from aegis.db.session import get_session

    with get_session() as sess:
        row = sess.get(Run, run_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"run {run_id} not found")
        ensure_project_access(user, row.project_id)
        return _run_to_dict(row, completed_at=True, stage_table=True)
