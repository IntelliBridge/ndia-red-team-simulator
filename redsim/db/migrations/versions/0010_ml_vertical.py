"""ML vertical (milestone M0): ``targets.detail`` and the ``ml_campaigns`` table.

Spec: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md,
sections 5.3, 5.5, 5.6 and 7.6. Plan: docs/plans/01-p0-contracts-api-skeleton.md.

Two additive changes and nothing else:

1. ``targets.detail`` (JSONB, nullable). Holds the ``MLModelManifest`` of
   ``redsim/ml/schema.py`` for targets of kind ``ml_model_artifact`` and
   ``ml_model_endpoint``. NULL for every other kind. No existing row changes
   meaning.
2. ``ml_campaigns``. The campaign and score record, one row per ML ``Run``
   (``run_id`` is both the primary key and the foreign key). It carries the
   frozen ``CampaignConfig``, the ``Provenance``, the ``MRIRecord``, the
   limitations, the reviewer notes, the lineage columns (``baseline_run_id``
   for verify campaigns, ``parent_run_id`` for reruns) and the
   ``settings_hash`` that decides whether two campaigns are comparable.

Tenant isolation parity. ``ml_campaigns`` joins the eight RLS-scoped tables
of ``0006_tenant_rls.py``: the same denormalized ``org_id`` column, the same
``redsim_set_org_id_<table>`` BEFORE INSERT backfill trigger, the same
``redsim_check_org_id_<table>`` BEFORE UPDATE drift guard from
``0009_tenant_org_id_guard.py``, ``ENABLE`` plus ``FORCE ROW LEVEL SECURITY``,
and the ``redsim_tenant_isolation`` policy over the ``app.current_tenants``
GUC. The trigger, guard and policy SQL is copied from those two migrations
with only the table name substituted. ML code never sets ``org_id``.

Idempotency and dialect. The column and table DDL is guarded with
``IF NOT EXISTS`` checks so the migration is safe if a later ORM change lets
``0001_initial``'s ``create_all`` create them first. The RLS, trigger and
policy SQL is Postgres-only and is skipped on other dialects, mirroring 0006
and 0009. ``downgrade`` drops the policy, the triggers, the functions, the
table and the column in reverse order.

Revision ID: 0010_ml_vertical
Revises: 0009_tenant_org_id_guard
Create Date: 2026-09-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0010_ml_vertical"
down_revision: str | None = "0009_tenant_org_id_guard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "ml_campaigns"

# JSONB on Postgres, plain JSON elsewhere (the sqlite unit path).
_JSON = sa.JSON().with_variant(JSONB(), "postgresql")

# Same predicate as ``_PREDICATE`` in 0006_tenant_rls.py. Empty or unset GUC
# means the system path (full access), otherwise the row's org_id must be in
# the comma-separated list.
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
    return sa.inspect(op.get_bind()).has_table(table)


def upgrade() -> None:
    bind = op.get_bind()

    # ---- 1. targets.detail --------------------------------------------------
    if not _has_column("targets", "detail", offline=False):
        op.add_column("targets", sa.Column("detail", _JSON, nullable=True))

    # ---- 2. ml_campaigns ----------------------------------------------------
    if not _has_table(_TABLE, offline=False):
        op.create_table(
            _TABLE,
            sa.Column("run_id", sa.String(64), sa.ForeignKey("runs.id"), primary_key=True),
            sa.Column("project_id", sa.String(64), sa.ForeignKey("projects.id"), nullable=False),
            # Denormalized tenant key for RLS. Nullable because the BEFORE
            # INSERT trigger backfills it from the row's project.
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id"), nullable=True),
            sa.Column("target_id", sa.String(64), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),        # attack | verify | ingest
            sa.Column("modality", sa.String(16), nullable=False),    # image | tabular
            sa.Column("baseline_run_id", sa.String(64), sa.ForeignKey("runs.id"), nullable=True),
            sa.Column("parent_run_id", sa.String(64), sa.ForeignKey("runs.id"), nullable=True),
            sa.Column("settings_hash", sa.String(64), nullable=True),
            sa.Column("config", _JSON, nullable=False),
            sa.Column("provenance", _JSON, nullable=True),
            sa.Column("score", _JSON, nullable=True),
            sa.Column("limitations", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("reviewer_notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(f"ix_{_TABLE}_project_id", _TABLE, ["project_id"])
        op.create_index(f"ix_{_TABLE}_org_id", _TABLE, ["org_id"])
        op.create_index(f"ix_{_TABLE}_target_id", _TABLE, ["target_id"])
        op.create_index(f"ix_{_TABLE}_settings_hash", _TABLE, ["settings_hash"])

    if bind.dialect.name != "postgresql":
        # RLS, FORCE, policies and plpgsql triggers are Postgres-only (0006).
        return

    # ---- 3. BEFORE INSERT org_id backfill trigger (copied from 0006) --------
    fn_set = f"redsim_set_org_id_{_TABLE}"
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
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_set_org_id_{_TABLE} ON {_TABLE}"))
    op.execute(sa.text(f"""
        CREATE TRIGGER trg_set_org_id_{_TABLE}
            BEFORE INSERT ON {_TABLE}
            FOR EACH ROW
            EXECUTE FUNCTION {fn_set}();
    """))

    # ---- 4. BEFORE UPDATE org_id drift guard (copied from 0009) -------------
    fn_check = f"redsim_check_org_id_{_TABLE}"
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
                    '(tenant integrity violation on {_TABLE})',
                    NEW.org_id, NEW.project_id, expected_org
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END;
        $fn$;
    """))
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_check_org_id_{_TABLE} ON {_TABLE}"))
    op.execute(sa.text(f"""
        CREATE TRIGGER trg_check_org_id_{_TABLE}
            BEFORE UPDATE ON {_TABLE}
            FOR EACH ROW
            EXECUTE FUNCTION {fn_check}();
    """))

    # ---- 5. ENABLE + FORCE RLS + tenant policy (copied from 0006) -----------
    op.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"DROP POLICY IF EXISTS redsim_tenant_isolation ON {_TABLE}"))
    op.execute(sa.text(f"""
        CREATE POLICY redsim_tenant_isolation ON {_TABLE}
            USING ({_PREDICATE})
            WITH CHECK ({_PREDICATE});
    """))


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP POLICY IF EXISTS redsim_tenant_isolation ON {_TABLE}"))
        op.execute(sa.text(f"ALTER TABLE {_TABLE} NO FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_check_org_id_{_TABLE} ON {_TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION IF EXISTS redsim_check_org_id_{_TABLE}()"))
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_set_org_id_{_TABLE} ON {_TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION IF EXISTS redsim_set_org_id_{_TABLE}()"))

    if _has_table(_TABLE, offline=True):
        op.drop_table(_TABLE)

    if _has_column("targets", "detail", offline=True):
        op.drop_column("targets", "detail")
