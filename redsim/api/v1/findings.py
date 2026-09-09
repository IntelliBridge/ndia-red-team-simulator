"""Findings read routes (M3 read-only; write actions land in M4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import ensure_project_access, has_project_access

if TYPE_CHECKING:
    from redsim.db.models import Finding

router = APIRouter(prefix="/findings", tags=["findings"])



def is_llm_finding(row: Finding) -> bool:
    """True for an LLM probe finding (``schema_blob.finding_kind == "adversarial_llm"``)."""
    blob = row.schema_blob if isinstance(row.schema_blob, dict) else {}
    kind = blob.get("finding_kind") or blob.get("finding_type") or ""
    return str(kind) == "adversarial_llm" or str(getattr(row, "source_tool", "") or "") == "ml.llm_probe"

def _finding_to_dict(
    row: Finding,
    *,
    source_tool: bool = False,
    validated_at: bool = False,
    dedup_key: bool = False,
    scanner_finding_id: bool = False,
) -> dict[str, Any]:
    """Serialize a ``Finding`` row to the API wire shape.

    The seven-field core is identical across every finding route; the
    keyword flags opt in to the per-route extras (the list view exposes
    ``source_tool``, the detail view ``validated_at``, the legacy
    by-scanner-id lookup ``scanner_finding_id``) so the shared shape stays
    the single source of truth.
    """
    out: dict[str, Any] = {
        "id": row.id, "run_id": row.run_id,
        "project_id": row.project_id,
        "severity": row.severity, "status": row.status,
        "schema_blob": row.schema_blob,
    }
    # Validation is the verify-after-harden outcome of a classifier finding.
    # An LLM probe finding has no verify loop, so the field would only ever
    # carry its "unvalidated" default; it is omitted for that kind (owner
    # decision 2026-09-09) rather than shown as if it meant something.
    if not is_llm_finding(row):
        out["validation_state"] = row.validation_state
        if validated_at:
            out["validated_at"] = row.validated_at
    if source_tool:
        out["source_tool"] = row.source_tool
    if dedup_key:
        out["dedup_key"] = row.dedup_key
    if scanner_finding_id:
        out["scanner_finding_id"] = row.scanner_finding_id
    return out


@router.get("")
def list_findings(
    run: str | None = None,
    project: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from redsim.db.models import Finding
    from redsim.db.session import get_session

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
            if not has_project_access(user, row.project_id):
                continue
            out.append(_finding_to_dict(row, source_tool=True, dedup_key=True))
        return {"findings": out, "count": len(out)}


@router.get("/{finding_id}")
def get_finding(finding_id: str,
                user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"finding {finding_id} not found")
        ensure_project_access(user, row.project_id)
        return _finding_to_dict(row, validated_at=True, dedup_key=True)
