"""redsim.verify_tenant_integrity — periodic tenant-isolation reconciliation.

Migration 0006 denormalizes ``org_id`` onto the eight project-scoped tables and
0009 adds a ``BEFORE UPDATE`` trigger that rejects ``org_id`` drift. This task
is the complementary *detective* control: a Celery-beat scan that re-derives
each scoped row's expected ``org_id`` from ``projects.org_id`` and flags any row
whose stored ``org_id`` disagrees (or is NULL). The trigger keeps drift from
being *written*; the reconciler catches rows that predate the trigger, were
written out-of-band (bulk SQL, restore, replication), or slipped through.

Mirrors ``tasks/reaper.py``: the core logic lives in
``verify_tenant_integrity_in_session`` so it's unit-testable without Celery or a
real DB, and the ``@app.task`` wrapper just opens a system-scope session and
runs it. Like the reaper it scans *all* rows (system scope — no tenant GUC), so
it manages its own session directly rather than going through ``task_context``.

The task is read-only by default: it logs each mismatch and emits one
``tenant.integrity_check`` audit event with the (id-only, secret-free) summary.
Detected drift is surfaced, not silently repaired — repair is an operator
decision (the on-demand ``redsim tenants verify --repair`` CLI can backfill from
the project once the drift is understood).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# The eight project-scoped tables carrying a denormalized ``org_id`` (kept in
# lockstep with ``_SCOPED_TABLES`` in migration 0006/0009). Each has a NOT NULL
# ``project_id`` FK to ``projects`` and a nullable ``org_id`` the trigger fills.
_SCOPED_TABLES: tuple[str, ...] = (
    "targets",
    "runs",
    "jobs",
    "findings",
    "llm_usage",
    "artifacts",
    "remediation_attempts",
    "application_logs",
)


@dataclass
class TenantDrift:
    """A single scoped row whose ``org_id`` disagrees with its project's org."""

    table: str
    row_id: str
    project_id: str | None
    stored_org_id: str | None
    expected_org_id: str | None


@dataclass
class ReconcileReport:
    """Summary of a reconciliation scan: per-table counts + the drift rows."""

    drifts: list[TenantDrift] = field(default_factory=list)
    per_table: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.drifts)

    @property
    def ok(self) -> bool:
        return self.total == 0

    def to_dict(self) -> dict[str, Any]:
        """Secret-free summary suitable for the audit chain / task result."""
        return {
            "total": self.total,
            "per_table": dict(self.per_table),
            "drifts": [
                {
                    "table": d.table,
                    "row_id": d.row_id,
                    "project_id": d.project_id,
                    "stored_org_id": d.stored_org_id,
                    "expected_org_id": d.expected_org_id,
                }
                for d in self.drifts
            ],
        }


def verify_tenant_integrity_in_session(
    sess: Session, *, repair: bool = False
) -> ReconcileReport:
    """Scan every scoped table for ``org_id`` drift versus the owning project.

    For each table a single set-based query joins to ``projects`` and selects
    rows where the stored ``org_id`` is ``DISTINCT FROM`` the project's
    ``org_id`` (so NULL drift is caught too). Each mismatch is collected into a
    :class:`TenantDrift` and counted per table. When ``repair`` is true, each
    drifted row's ``org_id`` is rewritten to the project's value in the same
    transaction (the 0009 UPDATE trigger permits this — it sets ``org_id`` to
    exactly the expected value).

    Read-only by default. Returns a :class:`ReconcileReport`; callers decide
    whether a non-empty report is fatal.
    """
    report = ReconcileReport()
    for table in _SCOPED_TABLES:
        # ``id`` is the PK on every scoped table except ``application_logs``
        # (integer ``id``); both stringify cleanly for reporting. project_id is
        # NOT NULL on all of them, but LEFT JOIN keeps a row with a dangling
        # project visible as expected_org_id = NULL drift rather than dropping
        # it. Identifiers are static (from the module constant), never user
        # input, so the f-string interpolation is safe.
        rows = sess.execute(text(  # nosemgrep
            f"SELECT x.id, x.project_id, x.org_id, p.org_id AS expected "
            f"FROM {table} x "
            f"LEFT JOIN projects p ON p.id = x.project_id "
            f"WHERE x.org_id IS DISTINCT FROM p.org_id"
        )).all()
        report.per_table[table] = len(rows)
        for row_id, project_id, stored, expected in rows:
            report.drifts.append(TenantDrift(
                table=table,
                row_id=str(row_id),
                project_id=project_id,
                stored_org_id=stored,
                expected_org_id=expected,
            ))
            logger.warning(
                "tenant integrity drift: %s id=%s project=%s org_id=%r "
                "expected=%r",
                table, row_id, project_id, stored, expected,
            )
            if repair and expected is not None:
                sess.execute(
                    text(  # nosemgrep
                        f"UPDATE {table} SET org_id = :org WHERE id = :id"
                    ),
                    {"org": expected, "id": row_id},
                )
    if report.ok:
        logger.info("tenant integrity check clean: no org_id drift")
    return report


def _emit_audit(report: ReconcileReport, *, repaired: bool) -> None:
    """Record one ``tenant.integrity_check`` event on the system audit chain.

    Best-effort: an audit-emit failure must never fail the reconciliation
    (mirrors ``worm_export``'s guarded append).
    """
    try:
        from redsim.audit.chain import resolve_writer
        from redsim.config import load_config

        writer = resolve_writer(load_config())
        detail = report.to_dict()
        detail["repaired"] = repaired
        writer.append(
            action="tenant.integrity_check",
            actor="worker:tenant_reconcile",
            target=None,
            allowlist_check="n/a",
            override=False,
            success=report.ok,
            detail=detail,
        )
    except Exception:  # pragma: no cover - audit emit must not fail the scan
        logger.debug("tenant integrity audit emit failed", exc_info=True)


def verify_tenant_integrity(repair: bool = False) -> dict[str, Any]:
    """Beat-scheduled entry point: open a system-scope session and reconcile.

    Importable/callable directly (the Celery task below wraps it) so the CLI and
    tests can run a scan without a broker. Returns the summary dict.
    """
    from redsim.db.session import get_session

    with get_session() as sess:
        report = verify_tenant_integrity_in_session(sess, repair=repair)
    _emit_audit(report, repaired=repair)
    result = report.to_dict()
    result["status"] = "ok" if report.ok else "drift"
    return result


def _register_task() -> Any:
    """Bind ``verify_tenant_integrity`` as a Celery task.

    Defined as a thin wrapper (rather than decorating the function above) so the
    pure entry point stays directly importable/callable from the CLI and tests
    without pulling in Celery's task machinery.
    """
    from redsim.workers.celery_app import app

    @app.task(name="redsim.verify_tenant_integrity")
    def _task() -> dict[str, Any]:
        return verify_tenant_integrity()

    return _task


verify_tenant_integrity_task = _register_task()
