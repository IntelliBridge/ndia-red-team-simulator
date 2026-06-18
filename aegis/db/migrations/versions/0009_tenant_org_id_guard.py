"""Phase 6 (Multi-tenancy) — reject ``org_id`` drift on UPDATE.

Migration 0006 denormalized ``org_id`` onto the eight project-scoped tables and
installed a ``BEFORE INSERT`` trigger (``aegis_set_org_id_<table>``) that
backfills ``org_id`` from the row's project when NULL. That trigger only fires
on INSERT, so an UPDATE could still drive a row's ``org_id`` out of sync with
its ``project_id``'s owning org — either by bug (a service rewriting columns) or
by a compromised/over-privileged session. RLS ``WITH CHECK`` blocks an UPDATE
that moves a row *out of* the caller's tenant scope, but the *system* path
(no ``app.current_tenants`` GUC) bypasses that predicate, and even a scoped
caller could set ``org_id`` to any value still inside its own scope yet
mismatched against the project.

This migration adds the missing integrity rail: a ``BEFORE UPDATE`` trigger per
scoped table (``aegis_check_org_id_<table>``) that **raises** whenever the new
``org_id`` does not equal the org that owns the row's project. ``project_id`` is
``NOT NULL`` on seven of the eight scoped tables; ``application_logs`` permits a
NULL ``project_id`` for system-scoped logs, in which case there is no owning org
to enforce against and the row is left untouched. If a NULL ``org_id`` is written
(e.g. a column reset) the trigger backfills it from the project rather than
rejecting, mirroring the INSERT trigger's tolerance. The
shape (one static-name function per table, ``CREATE OR REPLACE`` + ``DROP
TRIGGER IF EXISTS``) is copied from ``aegis_set_org_id_<table>`` in
``0006_tenant_rls.py`` so the two triggers read as a matched pair.

Idempotency + reversibility match 0006: the function/trigger SQL is naturally
idempotent (``CREATE OR REPLACE`` / ``DROP ... IF EXISTS``) and ``downgrade``
drops both. Postgres-only — the offline/sqlite path never runs migrations, but
a dialect guard keeps an accidental sqlite alembic run a clean no-op.

Revision ID: 0009_tenant_org_id_guard
Revises: 0008_finding_tickets
Create Date: 2026-06-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_tenant_org_id_guard"
down_revision: Union[str, None] = "0008_finding_tickets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The eight project-scoped tables that carry a denormalized ``org_id`` (see
# ``_SCOPED_TABLES`` in 0006). ``projects`` is excluded: it *is* the tenant key
# (its own ``org_id``), so there is no separate project to mismatch against.
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


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # plpgsql triggers are Postgres-only. The offline / sqlite unit path
        # never runs migrations (it uses create_all); guard defensively so an
        # accidental sqlite alembic run is a clean no-op rather than a syntax
        # error. Mirrors 0006.
        return

    # Per-table BEFORE UPDATE trigger: reject any org_id that disagrees with the
    # org owning the row's project. A NULL new org_id is backfilled from the
    # project (matching the INSERT trigger's tolerance) rather than rejected, so
    # a column reset re-resolves instead of erroring. One function per table
    # keeps the body trivial and the table name static (no dynamic SQL).
    for table in _SCOPED_TABLES:
        fn = f"aegis_check_org_id_{table}"
        op.execute(sa.text(f"""
            CREATE OR REPLACE FUNCTION {fn}()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $fn$
            DECLARE
                expected_org VARCHAR(64);
            BEGIN
                SELECT p.org_id INTO expected_org
                FROM projects p WHERE p.id = NEW.project_id;
                IF NEW.org_id IS NULL THEN
                    NEW.org_id := expected_org;
                ELSIF expected_org IS NOT NULL
                      AND NEW.org_id IS DISTINCT FROM expected_org THEN
                    -- expected_org NULL means the row has no owning project
                    -- (e.g. a system-scoped application_logs row): nothing to
                    -- enforce, so leave the write alone rather than rejecting.
                    RAISE EXCEPTION
                        'org_id % does not match project % owning org % '
                        '(tenant integrity violation on {table})',
                        NEW.org_id, NEW.project_id, expected_org
                        USING ERRCODE = 'check_violation';
                END IF;
                RETURN NEW;
            END;
            $fn$;
        """))
        op.execute(sa.text(
            f"DROP TRIGGER IF EXISTS trg_check_org_id_{table} ON {table}"))
        op.execute(sa.text(f"""
            CREATE TRIGGER trg_check_org_id_{table}
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION {fn}();
        """))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table in _SCOPED_TABLES:
        op.execute(sa.text(
            f"DROP TRIGGER IF EXISTS trg_check_org_id_{table} ON {table}"))
        op.execute(sa.text(
            f"DROP FUNCTION IF EXISTS aegis_check_org_id_{table}()"))
