"""Phase 6 (Multi-tenancy) — Postgres Row-Level Security for cross-ORG isolation.

App-layer scoping (post-query Python filters keyed on ``project_id``) already
keeps one tenant from *reading* another's rows — but a single forgotten
``WHERE`` clause would leak across tenants. This migration makes the database
enforce the tenant boundary (the **Organization**) as defense-in-depth:

1. **Denormalize ``org_id``** onto every project-scoped table (targets, runs,
   jobs, findings, llm_usage, artifacts, remediation_attempts,
   application_logs). A join-free local column is what lets the RLS policy be a
   simple column comparison — a policy that subqueried ``projects`` would
   recurse through that table's own RLS. Existing rows are backfilled from
   ``projects.org_id``; a ``BEFORE INSERT`` trigger per table populates
   ``org_id`` from the row's ``project_id`` when NULL, so **no insert code
   changes** are required.
2. **ENABLE + FORCE ROW LEVEL SECURITY** on ``projects`` and the eight
   denormalized tables. ``FORCE`` is critical: without it the table owner /
   superuser bypasses policies, which would make the CI test (it connects as a
   superuser) a no-op. The policy reads a per-transaction GUC
   ``app.current_tenants`` (a comma-separated list of org ids the caller may
   see); an empty / unset GUC means full access — the system / worker path.

Idempotency: ``0001_initial`` runs ``Base.metadata.create_all`` against the
current ``models.py``, which now declares ``org_id`` on those tables. A fresh
``alembic upgrade head`` therefore already has the columns + indexes when this
revision runs, so the column / index DDL uses ``IF NOT EXISTS``. The RLS,
trigger and policy SQL is naturally idempotent (``DROP ... IF EXISTS`` /
``CREATE OR REPLACE``).

The RLS / FORCE / policy / trigger SQL is unconditional so it applies in CI;
only role GRANTs (none here) would need 0004-style DO-block guards.

Revision ID: 0006_tenant_rls
Revises: 0005_auth_profiles
Create Date: 2026-06-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_tenant_rls"
down_revision: Union[str, None] = "0005_auth_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Project-scoped tables that gain a denormalized ``org_id`` + a backfill
# trigger. ``projects`` is handled separately (it carries org_id already and
# its policy compares its own row), so it is NOT in this list.
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

# Every table whose rows are filtered by RLS — the scoped tables plus
# ``projects`` itself (whose own ``org_id`` is the tenant key).
_RLS_TABLES: tuple[str, ...] = ("projects", *_SCOPED_TABLES)

_GUC = "app.current_tenants"

# The shared USING / WITH CHECK predicate. Empty or unset GUC => system (full
# access); otherwise the row's org_id must be in the comma-separated list.
# current_setting(..., true) returns NULL when unset; coalesce to '' so the
# system test (= '') matches. string_to_array('', ',') would yield {''}, so the
# explicit '' check short-circuits before the ANY().
_PREDICATE = (
    "coalesce(current_setting('app.current_tenants', true), '') = '' "
    "OR {col} = ANY (string_to_array("
    "current_setting('app.current_tenants', true), ','))"
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # RLS, FORCE, policies and plpgsql triggers are Postgres-only. The
        # offline / sqlite unit path never runs migrations (it uses
        # create_all), but guard defensively so an accidental sqlite alembic
        # run is a clean no-op rather than a syntax error.
        return

    # ---- 1. Denormalize org_id + backfill + BEFORE INSERT trigger ----------
    for table in _SCOPED_TABLES:
        op.execute(sa.text(
            f"ALTER TABLE {table} "
            f"ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) "
            f"REFERENCES organizations(id)"
        ))
        op.execute(sa.text(
            f"CREATE INDEX IF NOT EXISTS ix_{table}_org_id "
            f"ON {table} (org_id)"
        ))
        # Backfill existing rows from the owning project.
        op.execute(sa.text(
            f"UPDATE {table} x SET org_id = p.org_id "
            f"FROM projects p WHERE x.project_id = p.id "
            f"AND x.org_id IS NULL"
        ))
        # Per-table BEFORE INSERT trigger: when org_id is NULL, resolve it from
        # the row's project. One function per table keeps the body trivial and
        # the table name static (no dynamic SQL). project_id is NOT NULL on
        # every scoped table, so the lookup always resolves.
        fn = f"aegis_set_org_id_{table}"
        op.execute(sa.text(f"""
            CREATE OR REPLACE FUNCTION {fn}()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $fn$
            BEGIN
                IF NEW.org_id IS NULL THEN
                    SELECT p.org_id INTO NEW.org_id
                    FROM projects p WHERE p.id = NEW.project_id;
                END IF;
                RETURN NEW;
            END;
            $fn$;
        """))
        op.execute(sa.text(
            f"DROP TRIGGER IF EXISTS trg_set_org_id_{table} ON {table}"))
        op.execute(sa.text(f"""
            CREATE TRIGGER trg_set_org_id_{table}
                BEFORE INSERT ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION {fn}();
        """))

    # ---- 2. ENABLE + FORCE RLS + per-table policy -------------------------
    # projects compares its own org_id; scoped tables compare their org_id. The
    # predicate is identical (both use the local org_id column).
    for table in _RLS_TABLES:
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        # FORCE so the owner / superuser is bound too (otherwise CI is a no-op).
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            f"DROP POLICY IF EXISTS aegis_tenant_isolation ON {table}"))
        predicate = _PREDICATE.format(col="org_id")
        op.execute(sa.text(f"""
            CREATE POLICY aegis_tenant_isolation ON {table}
                USING ({predicate})
                WITH CHECK ({predicate});
        """))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # Reverse order: drop policies + disable RLS, then triggers + functions,
    # then the columns (index drops with the column).
    for table in _RLS_TABLES:
        op.execute(sa.text(
            f"DROP POLICY IF EXISTS aegis_tenant_isolation ON {table}"))
        op.execute(sa.text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))

    for table in _SCOPED_TABLES:
        op.execute(sa.text(
            f"DROP TRIGGER IF EXISTS trg_set_org_id_{table} ON {table}"))
        op.execute(sa.text(
            f"DROP FUNCTION IF EXISTS aegis_set_org_id_{table}()"))
        op.execute(sa.text(
            f"DROP INDEX IF EXISTS ix_{table}_org_id"))
        op.execute(sa.text(
            f"ALTER TABLE {table} DROP COLUMN IF EXISTS org_id"))
