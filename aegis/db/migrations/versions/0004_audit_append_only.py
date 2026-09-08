"""Phase 5 (Security) — DB-side append-only enforcement for audit_events.

The hash chain is tamper-*evident* (``verify_chain`` recomputes hashes), but
a privileged operator with ``UPDATE``/``DELETE`` could re-sign a chain end to
end. This migration makes ``audit_events`` insert-only *at the database*:

1. A row-immutability trigger that ``RAISE EXCEPTION``s on UPDATE/DELETE (and a
   statement-level trigger for TRUNCATE). It fires for everyone, including the
   table owner and superusers, so a forged re-sign is rejected by Postgres.
2. (Wave 2, below) least-privilege role separation + pgaudit, all guarded so
   they no-op where the roles / extension are absent (e.g. CI).

``audit_chain_heads`` is deliberately left untouched — ``PostgresAuditWriter``
UPDATEs its head pointer on every append, so locking it would break all writes.

Migrations run online inside a single transaction (see ``env.py``), so every
statement here must be transaction-safe: ``CREATE EXTENSION`` and
``ALTER ROLE ... SET`` are fine; ``ALTER SYSTEM`` is NOT and lives in the
deploy/operator layer (see ``docs/ops/deploy.md``).

Revision ID: 0004_audit_append_only
Revises: 0003_application_logs
Create Date: 2026-06-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_audit_append_only"
down_revision: Union[str, None] = "0003_application_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- Layer 1: row-immutability trigger (unconditional) ----------------
    # One function serves UPDATE, DELETE and TRUNCATE; TG_OP makes the error
    # specific. ERRCODE 42501 maps to psycopg.errors.InsufficientPrivilege.
    # A BEFORE trigger raising blocks even the table owner / superuser, since
    # triggers fire regardless of privilege.
    op.execute(sa.text("""
        CREATE OR REPLACE FUNCTION aegis_audit_events_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $fn$
        BEGIN
            RAISE EXCEPTION
                'audit_events is append-only: % is not permitted', TG_OP
                USING ERRCODE = '42501',
                      HINT = 'Audit events cannot be modified, deleted, or truncated.';
            RETURN NULL;
        END;
        $fn$;
    """))

    # Row trigger for UPDATE/DELETE. Row triggers never fire on TRUNCATE, so a
    # separate statement-level trigger is required to block it.
    op.execute(sa.text(
        "DROP TRIGGER IF EXISTS trg_audit_events_no_update_delete "
        "ON audit_events;"))
    op.execute(sa.text("""
        CREATE TRIGGER trg_audit_events_no_update_delete
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW
            EXECUTE FUNCTION aegis_audit_events_immutable();
    """))

    op.execute(sa.text(
        "DROP TRIGGER IF EXISTS trg_audit_events_no_truncate "
        "ON audit_events;"))
    op.execute(sa.text("""
        CREATE TRIGGER trg_audit_events_no_truncate
            BEFORE TRUNCATE ON audit_events
            FOR EACH STATEMENT
            EXECUTE FUNCTION aegis_audit_events_immutable();
    """))

    # ---- Layer 2: role separation (guarded; no-ops where roles absent) ----
    # The roles are provisioned out-of-band (see docs/ops/deploy.md), so CI —
    # which connects as a superuser with neither role present — skips all of
    # this. Never CREATE ROLE here (would leave stray roles in CI).
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_owner') THEN
                ALTER TABLE audit_events OWNER TO aegis_owner;
                ALTER FUNCTION aegis_audit_events_immutable() OWNER TO aegis_owner;
            END IF;
        END
        $$;
    """))
    # App role: append + read only on audit_events; full DML on every OTHER
    # table (enumerated — a blanket GRANT ON ALL TABLES would re-grant
    # UPDATE/DELETE on audit_events and defeat the lock-down). audit_chain_heads
    # MUST be in the DML list: the append UPDATEs its head pointer every write.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
                REVOKE ALL ON TABLE audit_events FROM aegis_app;
                GRANT INSERT, SELECT ON TABLE audit_events TO aegis_app;

                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
                    organizations, projects, users, project_memberships,
                    targets, runs, jobs, findings, llm_usage, artifacts,
                    remediation_attempts, audit_chain_heads,
                    github_installations, application_logs
                TO aegis_app;

                GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO aegis_app;
            END IF;
        END
        $$;
    """))

    # ---- Layer 3: pgaudit (guarded) — out-of-band logging of DDL + role/GRANT
    # changes, so disabling the controls above is itself recorded. Guard on
    # availability: the stock postgres image / CI doesn't ship the shared
    # library, and CREATE EXTENSION fails even with IF NOT EXISTS when absent.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_available_extensions
                       WHERE name = 'pgaudit') THEN
                CREATE EXTENSION IF NOT EXISTS pgaudit;
            ELSE
                RAISE NOTICE 'pgaudit not available; skipping audit-log extension';
            END IF;
        END
        $$;
    """))
    # Set the log classes per-role via ALTER ROLE (transaction-safe; takes
    # effect on the role's next session). NOT ALTER SYSTEM — that cannot run
    # inside the migration transaction (see env.py) and needs a reload; it
    # lives in the deploy/operator layer.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgaudit') THEN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_owner') THEN
                    ALTER ROLE aegis_owner SET pgaudit.log = 'ddl, role';
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
                    ALTER ROLE aegis_app SET pgaudit.log = 'ddl, role';
                END IF;
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    # Reverse order; guarded so the bare CI superuser path succeeds. Leave the
    # pgaudit extension installed (shared server resource); RESET the per-role
    # config instead. Table ownership is left as-is (env-specific).
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgaudit') THEN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_owner') THEN
                    ALTER ROLE aegis_owner RESET pgaudit.log;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
                    ALTER ROLE aegis_app RESET pgaudit.log;
                END IF;
            END IF;
        END
        $$;
    """))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE
                    ON TABLE audit_events TO aegis_app;
            END IF;
        END
        $$;
    """))
    op.execute(sa.text(
        "DROP TRIGGER IF EXISTS trg_audit_events_no_truncate "
        "ON audit_events;"))
    op.execute(sa.text(
        "DROP TRIGGER IF EXISTS trg_audit_events_no_update_delete "
        "ON audit_events;"))
    op.execute(sa.text(
        "DROP FUNCTION IF EXISTS aegis_audit_events_immutable();"))
