"""GET /v1/logs — admin-only structured-log query (Phase 4 v0.4.1 F22).

Backed by the application_logs table the redsim-log-ingest service
populates. Admin-only; the route emits a ``logs.queried`` audit event
on every query so the audit chain captures who looked at what.

Cursor pagination uses the row id as the cursor token — application
log rows are monotonically increasing, so ``id < cursor`` is the
"older than this page" predicate.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import authorize

if TYPE_CHECKING:
    from redsim.db.models import ApplicationLog

router = APIRouter(prefix="/logs", tags=["logs"])


_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _row_to_dict(row: ApplicationLog) -> dict[str, Any]:
    return {
        "id": row.id,
        "ts": row.ts.isoformat() if row.ts else None,
        "severity": row.severity,
        "service": row.service,
        "message": row.message,
        "run_id": row.run_id,
        "job_id": row.job_id,
        "project_id": row.project_id,
        "actor": row.actor,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "span_id": row.span_id,
        "attrs": row.attrs or {},
    }


@router.get("")
def list_logs(
    user: CurrentUser = Depends(get_current_user),
    run: str | None = Query(default=None),
    project: str | None = Query(default=None),
    service: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    since: str | None = Query(default=None,
                              description="ISO-8601 lower bound on ts"),
    cursor: int | None = Query(default=None,
                                description="Pagination: id < cursor"),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
) -> dict[str, Any]:
    """Return the most recent matching log rows.

    Admin-only on the default project for now; per-project ACLs land
    in v0.4.2 (the read-side surface already enforces project access
    on reports / exports — logs aggregate across projects so a project
    role isn't sufficient).
    """
    # Admin gate: anyone with AUDIT_VERIFY-equivalent on the default
    # project. policy.check raises 403 when the role is too low.
    check(user, Action.AUDIT_VERIFY, project or "default")

    from redsim.db.models import ApplicationLog
    from redsim.db.session import get_session

    stmt = select(ApplicationLog).order_by(ApplicationLog.id.desc())
    if run:
        stmt = stmt.where(ApplicationLog.run_id == run)
    if project:
        stmt = stmt.where(ApplicationLog.project_id == project)
    if service:
        stmt = stmt.where(ApplicationLog.service == service)
    if severity:
        stmt = stmt.where(ApplicationLog.severity == severity.lower())
    if request_id:
        stmt = stmt.where(ApplicationLog.request_id == request_id)
    if since:
        try:
            ts_lower = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid `since`: {exc}",
            ) from exc
        stmt = stmt.where(ApplicationLog.ts >= ts_lower)
    if cursor is not None:
        stmt = stmt.where(ApplicationLog.id < cursor)
    stmt = stmt.limit(limit)

    with get_session() as sess:
        rows = sess.execute(stmt).scalars().all()

    next_cursor = rows[-1].id if len(rows) == limit and rows else None

    # F22: every query lands an audit event ("audit the auditors") so a
    # forensic review can tell who looked at which logs.
    config = load_config()
    authorize(
        "logs.queried", None,
        allowlist=config.target_allowlist,
        actor=f"user:{user.sub}",
        writer=resolve_writer(config),
        project_id=project,
        detail={
            "actor": f"user:{user.sub}",
            "filters": {
                "run": run, "project": project, "service": service,
                "severity": severity, "request_id": request_id,
                "since": since,
            },
            "returned": len(rows),
            "cursor": cursor,
        },
    )

    return {
        "logs": [_row_to_dict(r) for r in rows],
        "next_cursor": next_cursor,
        "count": len(rows),
    }
