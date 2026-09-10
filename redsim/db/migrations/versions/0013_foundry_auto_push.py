"""Per-project Foundry integration settings: one nullable JSONB column.

Owner request of 2026-09-10: the Exports page configures the Foundry dataset,
the bearer auth profile and an auto-push toggle per project. The host, the
attestation and the egress allowlist stay operator-set on the API and worker
(spec 27.3, D3); this column holds only what a project admin may choose.

``projects.ml_integrations`` (JSONB, nullable) holds ``{"foundry": {...}}`` as
``redsim.services.ml_integrations`` reads and writes it. NULL means nothing
configured. Additive, announced in docs/plans/00-master-plan.md section 5.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "0013_foundry_auto_push"
down_revision: str | None = "0012_remove_verify_paradigm"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "projects"
COLUMN = "ml_integrations"


def _has_column(table: str, column: str, *, offline: bool) -> bool:
    # Offline (``--sql``) mode has no connection to inspect; ``offline`` is the
    # answer that makes the calling direction emit its DDL.
    if context.is_offline_mode():
        return offline
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(col["name"] == column for col in inspector.get_columns(table))


def _table_exists(table: str) -> bool:
    if context.is_offline_mode():
        return True
    return bool(sa.inspect(op.get_bind()).has_table(table))


def upgrade() -> None:
    # A database without ``projects`` (a reduced test database stamped below this
    # revision) has nothing to alter; a live database always has the table.
    if not _table_exists(TABLE) or _has_column(TABLE, COLUMN, offline=False):
        return
    op.add_column(TABLE, sa.Column(COLUMN, postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
                                   nullable=True))


def downgrade() -> None:
    if not _has_column(TABLE, COLUMN, offline=True):
        return
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_column(COLUMN)
