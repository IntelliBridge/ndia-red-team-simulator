"""Run listing / inspection routes (read-only in M3; write endpoints land in M4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("")
def list_runs(
    project: str | None = None,
    limit: int = 50,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from sqlalchemy import select
    from aegis.db.models import Run
    from aegis.db.session import get_session

    try:
        with get_session() as sess:
            stmt = select(Run).order_by(Run.created_at.desc()).limit(limit)
            if project:
                stmt = stmt.where(Run.project_id == project)
            rows = sess.execute(stmt).scalars().all()
            payload = [
                {
                    "id": r.id, "project_id": r.project_id,
                    "status": r.status, "scanner": r.scanner,
                    "mode": r.mode, "created_at": r.created_at,
                    "created_by": r.created_by,
                }
                for r in rows
            ]
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
        if (row.project_id not in user.project_memberships
                and not user.is_system):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="no access to this project")
        return {
            "id": row.id, "project_id": row.project_id,
            "status": row.status, "mode": row.mode,
            "scanner": row.scanner, "stage_table": row.stage_table or {},
            "created_at": row.created_at, "completed_at": row.completed_at,
        }
