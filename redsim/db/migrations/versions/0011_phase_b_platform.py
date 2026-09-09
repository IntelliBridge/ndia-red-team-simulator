"""Phase B platform tables and columns, one additive revision.

Plan: docs/plans/12-phase-b-plan.md (wave B0, track ``migration-0011``).
Register: docs/plans/11-phase-b-register-2026-09-09.md items REVIEW_REPORTS-44,
BULK-01, BULK-20 and INTEROP-14. Spec: sections 5.3 (additive migrations),
7.6 (RLS on every new table), 17.4, 27.1 and F004/F007.

The P0 freeze (docs/plans/01 section 8) froze the migration head at
``0010_ml_vertical``. This is the single announced move of that head for
Phase B; every Phase B DDL lands here so the head moves once.

Six additive changes and nothing else. No existing column changes.

1. ``report_snapshots``. One immutable row per rendered report; the bytes
   stay in the content-addressed ``artifacts`` rows named by ``artifact_ids``.
2. ``idempotency_keys``. Stored request identity for ``Idempotency-Key`` on
   mutating routes, unique per ``(project_id, key)`` (the primary key).
3. ``projects.ml_scoring`` (JSONB, nullable): the per-project ``ScoringConfig``
   override. ``projects.ml_max_concurrent_runs`` and
   ``projects.ml_daily_run_budget`` (Integer, nullable): per-project capacity
   caps. NULL keeps the deployment default.
4. ``ml_campaigns.batch_id`` (String(64), nullable, indexed): the batch a run
   belongs to. ``ml_campaigns`` stays migration-owned (no ORM model).
5. ``ml_batches``. The batch record for bulk campaigns, bulk verify and bulk
   upload.
6. ``ml_datasets``. The record of a consumed evaluation slice
   (``validating | available | refused``).

Tenant isolation parity. The four new tables carry ``project_id`` and a
denormalized ``org_id`` and join the RLS-scoped tables of ``0006_tenant_rls``
exactly as ``ml_campaigns`` did in 0010: the ``redsim_set_org_id_<table>``
BEFORE INSERT backfill trigger, the ``redsim_check_org_id_<table>`` BEFORE
UPDATE drift guard from 0009, ``ENABLE`` plus ``FORCE ROW LEVEL SECURITY`` and
the ``redsim_tenant_isolation`` policy over the ``app.current_tenants`` GUC.
The trigger, guard and policy SQL in ``_install_tenant_isolation`` is the 0010
text with only the table name substituted; ``tests/test_migration_0011.py``
asserts that parity token for token. Application code never sets ``org_id``.

Role separation. 0004 enumerates the tables the restricted ``redsim_app`` role
may write, so each new table gets the guarded GRANT that 0005 used for
``auth_profiles`` (a no-op where the role is absent, as in CI).

Idempotency and dialect. ``0001_initial`` runs ``Base.metadata.create_all``
against the current ORM, so on a fresh database the four tables and the three
``projects`` columns already exist when this revision runs; every ``CREATE``
and ``ADD COLUMN`` is guarded by an inspector check (offline ``--sql`` mode
has no connection and emits the DDL of the requested direction). The RLS,
trigger, policy and GRANT SQL is Postgres-only and skipped on other dialects,
mirroring 0006, 0009 and 0010; the table and column DDL itself runs on sqlite
too, which is what the sqlite round trip in the test exercises. ``downgrade``
removes the policy, triggers and functions, then the tables, then the columns.

Revision ID: 0011_phase_b_platform
Revises: 0010_ml_vertical
Create Date: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0011_phase_b_platform"
down_revision: str | None = "0010_ml_vertical"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# JSONB on Postgres, plain JSON elsewhere (the sqlite unit path), as in 0010.
_JSON = sa.JSON().with_variant(JSONB(), "postgresql")

# The four new tenant-scoped tables, in creation order. Each has a NOT NULL
# ``project_id`` and a nullable, trigger-backfilled ``org_id``.
_RLS_TABLES: tuple[str, ...] = (
    "report_snapshots",
    "idempotency_keys",
    "ml_batches",
    "ml_datasets",
)

_PROJECT_COLUMNS: tuple[str, ...] = ("ml_scoring", "ml_max_concurrent_runs", "ml_daily_run_budget")

# Same predicate as ``_PREDICATE`` in 0006_tenant_rls.py and 0010. Empty or
# unset GUC means the system path (full access), otherwise the row's org_id
# must be in the comma-separated list.
_PREDICATE = (
    "coalesce(current_setting('app.current_tenants', true), '') = '' "
    "OR org_id = ANY (string_to_array("
    "current_setting('app.current_tenants', true), ','))"
)


def _has_column(table: str, column: str, *, offline: bool) -> bool:
    # Offline (``--sql``) mode has no live connection to inspect. ``offline``
    # is the answer that makes the DDL of the calling direction emit: False
    # for upgrade (create), True for downgrade (drop).
    if context.is_offline_mode():
        return offline
    inspector = sa.inspect(op.get_bind())
    return any(col["name"] == column for col in inspector.get_columns(table))


def _has_table(table: str, *, offline: bool) -> bool:
    if context.is_offline_mode():
        return offline
    return bool(sa.inspect(op.get_bind()).has_table(table))


def _tenant_columns() -> list[sa.Column]:
    """``project_id`` and the denormalized ``org_id`` shared by every new table."""
    return [
        sa.Column("project_id", sa.String(64), sa.ForeignKey("projects.id"), nullable=False),
        # Denormalized tenant key for RLS. Nullable because the BEFORE INSERT
        # trigger backfills it from the row's project.
        sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id"), nullable=True),
    ]


def _install_tenant_isolation(table: str) -> None:
    """0010's trigger, guard, RLS and policy SQL with only the table name substituted."""
    # ---- BEFORE INSERT org_id backfill trigger (copied from 0006) -----------
    fn_set = f"redsim_set_org_id_{table}"
    op.execute(sa.text(f"""
        CREATE OR REPLACE FUNCTION {fn_set}()
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
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_set_org_id_{table} ON {table}"))
    op.execute(sa.text(f"""
        CREATE TRIGGER trg_set_org_id_{table}
            BEFORE INSERT ON {table}
            FOR EACH ROW
            EXECUTE FUNCTION {fn_set}();
    """))

    # ---- BEFORE UPDATE org_id drift guard (copied from 0009) ----------------
    fn_check = f"redsim_check_org_id_{table}"
    op.execute(sa.text(f"""
        CREATE OR REPLACE FUNCTION {fn_check}()
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
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_check_org_id_{table} ON {table}"))
    op.execute(sa.text(f"""
        CREATE TRIGGER trg_check_org_id_{table}
            BEFORE UPDATE ON {table}
            FOR EACH ROW
            EXECUTE FUNCTION {fn_check}();
    """))

    # ---- ENABLE + FORCE RLS + tenant policy (copied from 0006) --------------
    op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"DROP POLICY IF EXISTS redsim_tenant_isolation ON {table}"))
    op.execute(sa.text(f"""
        CREATE POLICY redsim_tenant_isolation ON {table}
            USING ({_PREDICATE})
            WITH CHECK ({_PREDICATE});
    """))


def _remove_tenant_isolation(table: str) -> None:
    """Reverse of ``_install_tenant_isolation`` in the 0010 downgrade order."""
    op.execute(sa.text(f"DROP POLICY IF EXISTS redsim_tenant_isolation ON {table}"))
    op.execute(sa.text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_check_org_id_{table} ON {table}"))
    op.execute(sa.text(f"DROP FUNCTION IF EXISTS redsim_check_org_id_{table}()"))
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_set_org_id_{table} ON {table}"))
    op.execute(sa.text(f"DROP FUNCTION IF EXISTS redsim_set_org_id_{table}()"))


def _grant_app_role(table: str) -> None:
    """Guarded DML grant for the restricted app role (mirrors 0005; no-op without the role)."""
    op.execute(sa.text(f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'redsim_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE
                    ON TABLE {table} TO redsim_app;
            END IF;
        END
        $$;
    """))


def upgrade() -> None:
    bind = op.get_bind()

    # ---- 1. report_snapshots ------------------------------------------------
    if not _has_table("report_snapshots", offline=False):
        op.create_table(
            "report_snapshots",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("run_id", sa.String(64), sa.ForeignKey("runs.id"), nullable=False),
            *_tenant_columns(),
            sa.Column("artifact_ids", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("record_sha256", sa.String(64), nullable=False),
            sa.Column("rendered_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_by", sa.String(256), nullable=True),
        )
        op.create_index("ix_report_snapshots_run_id", "report_snapshots", ["run_id"])
        op.create_index("ix_report_snapshots_project_id", "report_snapshots", ["project_id"])
        op.create_index("ix_report_snapshots_org_id", "report_snapshots", ["org_id"])

    # ---- 2. idempotency_keys ------------------------------------------------
    if not _has_table("idempotency_keys", offline=False):
        op.create_table(
            "idempotency_keys",
            *_tenant_columns(),
            sa.Column("key", sa.String(128), nullable=False),
            sa.Column("route", sa.String(256), nullable=False),
            sa.Column("request_sha256", sa.String(64), nullable=False),
            sa.Column("response_status", sa.Integer(), nullable=False),
            sa.Column("response_body", _JSON, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            # The (project_id, key) uniqueness the route relies on IS the key.
            sa.PrimaryKeyConstraint("project_id", "key", name="pk_idempotency_keys"),
        )
        op.create_index("ix_idempotency_keys_org_id", "idempotency_keys", ["org_id"])

    # ---- 3. projects capacity + scoring columns -----------------------------
    if not _has_column("projects", "ml_scoring", offline=False):
        op.add_column("projects", sa.Column("ml_scoring", _JSON, nullable=True))
    if not _has_column("projects", "ml_max_concurrent_runs", offline=False):
        op.add_column("projects", sa.Column("ml_max_concurrent_runs", sa.Integer(), nullable=True))
    if not _has_column("projects", "ml_daily_run_budget", offline=False):
        op.add_column("projects", sa.Column("ml_daily_run_budget", sa.Integer(), nullable=True))

    # ---- 4. ml_campaigns.batch_id -------------------------------------------
    if not _has_column("ml_campaigns", "batch_id", offline=False):
        op.add_column("ml_campaigns", sa.Column("batch_id", sa.String(64), nullable=True))
        op.create_index("ix_ml_campaigns_batch_id", "ml_campaigns", ["batch_id"])

    # ---- 5. ml_batches ------------------------------------------------------
    if not _has_table("ml_batches", offline=False):
        op.create_table(
            "ml_batches",
            sa.Column("id", sa.String(64), primary_key=True),
            *_tenant_columns(),
            sa.Column("kind", sa.String(16), nullable=False),       # campaign | verify | upload
            sa.Column("config", _JSON, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("status", sa.String(32), nullable=False, server_default="accepted"),
            sa.Column("created_by", sa.String(256), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("idempotency_key", sa.String(128), nullable=True),
            sa.Column("request_sha256", sa.String(64), nullable=True),
        )
        op.create_index("ix_ml_batches_project_id", "ml_batches", ["project_id"])
        op.create_index("ix_ml_batches_org_id", "ml_batches", ["org_id"])

    # ---- 6. ml_datasets -----------------------------------------------------
    if not _has_table("ml_datasets", offline=False):
        op.create_table(
            "ml_datasets",
            sa.Column("id", sa.String(64), primary_key=True),
            *_tenant_columns(),
            sa.Column("status", sa.String(16), nullable=False,      # validating | available | refused
                      server_default="validating"),
            sa.Column("refusal_reason", sa.Text(), nullable=True),
            sa.Column("license", sa.String(256), nullable=True),
            sa.Column("modality", sa.String(16), nullable=True),
            sa.Column("class_names", _JSON, nullable=True),
            sa.Column("manifest_sha256", sa.String(64), nullable=True),
            sa.Column("blob_location", sa.String(1024), nullable=True),
            sa.Column("detail", _JSON, nullable=True),
            sa.Column("created_by", sa.String(256), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
        )
        op.create_index("ix_ml_datasets_project_id", "ml_datasets", ["project_id"])
        op.create_index("ix_ml_datasets_org_id", "ml_datasets", ["org_id"])
        op.create_index("ix_ml_datasets_manifest_sha256", "ml_datasets", ["manifest_sha256"])

    if bind.dialect.name != "postgresql":
        # RLS, FORCE, policies, plpgsql triggers and role grants are
        # Postgres-only (0006, 0010).
        return

    # ---- 7. RLS parity and app-role grant on every new tenant-scoped table --
    for table in _RLS_TABLES:
        _install_tenant_isolation(table)
        _grant_app_role(table)


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        for table in reversed(_RLS_TABLES):
            _remove_tenant_isolation(table)

    for table in reversed(_RLS_TABLES):
        if _has_table(table, offline=True):
            op.drop_table(table)

    if _has_column("ml_campaigns", "batch_id", offline=True):
        # Index first: Postgres drops it with the column, sqlite refuses to
        # drop an indexed column.
        op.drop_index("ix_ml_campaigns_batch_id", table_name="ml_campaigns", if_exists=True)
        op.drop_column("ml_campaigns", "batch_id")

    for column in reversed(_PROJECT_COLUMNS):
        if _has_column("projects", column, offline=True):
            op.drop_column("projects", column)
