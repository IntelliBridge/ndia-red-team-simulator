"""Findings read routes (M3 read-only; write actions land in M4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from aegis.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
def list_findings(
    run: str | None = None,
    project: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from aegis.db.models import Finding
    from aegis.db.session import get_session

    with get_session() as sess:
        stmt = select(Finding).limit(limit)
        if run:
            stmt = stmt.where(Finding.run_id == run)
        if project:
            stmt = stmt.where(Finding.project_id == project)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        rows = sess.execute(stmt).scalars().all()
        out = []
        for row in rows:
            if (row.project_id not in user.project_memberships
                    and not user.is_system):
                continue
            out.append({
                "id": row.id, "run_id": row.run_id,
                "project_id": row.project_id,
                "severity": row.severity, "status": row.status,
                "source_tool": row.source_tool,
                "validation_state": row.validation_state,
                "dedup_key": row.dedup_key,
                "schema_blob": row.schema_blob,
            })
        return {"findings": out, "count": len(out)}


@router.get("/{finding_id}")
def get_finding(finding_id: str,
                user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from aegis.db.models import Finding
    from aegis.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"finding {finding_id} not found")
        if (row.project_id not in user.project_memberships
                and not user.is_system):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="no access to this project")
        return {
            "id": row.id, "run_id": row.run_id,
            "project_id": row.project_id,
            "severity": row.severity, "status": row.status,
            "validation_state": row.validation_state,
            "validated_at": row.validated_at, "dedup_key": row.dedup_key,
            "schema_blob": row.schema_blob,
        }
