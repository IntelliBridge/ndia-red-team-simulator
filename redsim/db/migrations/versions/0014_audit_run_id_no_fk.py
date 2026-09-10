"""Drop the foreign key from ``audit_events.run_id`` to ``runs.id``.

Spec 6.7 invariant 4 and spec 10.5: every admission appends its audit event,
naming the run it is about to create, BEFORE it writes the ``Run`` and ``Job``
rows and before it touches Celery. ``PostgresAuditWriter`` commits that event
in its own transaction. A foreign key from the audit row to ``runs`` therefore
contradicts the platform's own ordering rule, and on 2026-09-10 the first ML
campaign admitted on a Postgres deployment failed with
``audit_events_run_id_fkey`` (sqlite, where every test ran, does not enforce
foreign keys by default). The LLM probe admission had side-stepped it by
writing its admission row with ``run_id = NULL``.

The audit log is append-only evidence (0004); a run id on it is a chain key,
not a relational reference, and must survive the run row it names. This
revision drops the constraint and keeps the column, its index and the RLS of
0006. Downgrade re-adds the constraint ``NOT VALID`` on Postgres so existing
rows that name a run written moments after them do not block it.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op

revision: str = "0014_audit_run_id_no_fk"
down_revision: str | None = "0013_foundry_auto_push"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "audit_events"
CONSTRAINT = "audit_events_run_id_fkey"


def _is_postgres() -> bool:
    if context.is_offline_mode():
        return context.get_context().dialect.name == "postgresql"
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgres():
        # sqlite never enforced the constraint and cannot ALTER one away; the
        # ORM model no longer declares it, so a fresh sqlite schema matches.
        return
    op.execute(f"ALTER TABLE {TABLE} DROP CONSTRAINT IF EXISTS {CONSTRAINT}")


def downgrade() -> None:
    if not _is_postgres():
        return
    op.execute(f"ALTER TABLE {TABLE} ADD CONSTRAINT {CONSTRAINT} FOREIGN KEY (run_id) REFERENCES runs (id) NOT VALID")
