"""Remove the verify paradigm's columns (product owner decision, 2026-09-09).

Product owner decision of 2026-09-09. Every run is a measurement in its
own right, so the verify-after-harden loop, the finding validation state and
the defense catalog left the tree. This revision drops the three columns that
carried them and nothing else:

1. ``findings.validation_state`` (``unvalidated`` / ``poc_passed`` /
   ``poc_failed`` / ``inconclusive``), written only by the verify worker.
2. ``findings.validated_at``, its timestamp.
3. ``ml_campaigns.baseline_run_id``, the verify run's link to the campaign
   it re-measured. ``ml_campaigns.kind`` keeps its column; live values are
   ``attack`` and ``ingest``.

Historical rows keep every other column. The downgrade restores the three
columns with their original defaults; the dropped values are not recoverable.

Idempotency and dialect. Column drops are guarded by an inspector check so a
re-run on a database that already lacks them is a no-op; the sqlite unit path
uses ``batch_alter_table`` for the drop.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "0012_remove_verify_paradigm"
down_revision: str | None = "0011_phase_b_platform"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DROPPED: tuple[tuple[str, str], ...] = (
    ("findings", "validation_state"),
    ("findings", "validated_at"),
    ("ml_campaigns", "baseline_run_id"),
)


def _has_column(table: str, column: str, *, offline: bool) -> bool:
    # Offline (``--sql``) mode has no live connection to inspect. ``offline``
    # is the answer that makes the DDL of the calling direction emit: True for
    # upgrade (drop), False for downgrade (re-add).
    if context.is_offline_mode():
        return offline
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(col["name"] == column for col in inspector.get_columns(table))


def upgrade() -> None:
    for table, column in _DROPPED:
        if not _has_column(table, column, offline=True):
            continue
        with op.batch_alter_table(table) as batch:
            batch.drop_column(column)


def downgrade() -> None:
    if not _has_column("findings", "validation_state", offline=False):
        op.add_column("findings", sa.Column("validation_state", sa.String(32), nullable=True,
                                            server_default="unvalidated"))
    if not _has_column("findings", "validated_at", offline=False):
        op.add_column("findings", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
    if not _has_column("ml_campaigns", "baseline_run_id", offline=False):
        op.add_column("ml_campaigns", sa.Column("baseline_run_id", sa.String(64), nullable=True))
        # The FK of 0010; sqlite cannot ALTER constraints and the unit path does not need it.
        if op.get_bind().dialect.name == "postgresql":
            op.create_foreign_key("ml_campaigns_baseline_run_id_fkey", "ml_campaigns", "runs",
                                  ["baseline_run_id"], ["id"])
