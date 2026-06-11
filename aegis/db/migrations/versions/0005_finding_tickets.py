"""Phase 5 (Integrations) — finding_tickets table.

Backs the pluggable bidirectional ticket-sync layer
(``aegis.integrations.ticket_provider`` + ``aegis.services.finding_tickets``):
one row per ``(finding_id, provider)`` recording the external tracker's id,
url, and last-pulled status. No credential is stored here.

Revision ID: 0005_finding_tickets
Revises: 0004_audit_append_only
Create Date: 2026-06-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_finding_tickets"
down_revision: Union[str, None] = "0004_audit_append_only"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotency — see 0002/0003 for the same pattern + reasoning.
    inspector = sa.inspect(op.get_bind())
    if "finding_tickets" in inspector.get_table_names():
        return

    op.create_table(
        "finding_tickets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "finding_id", sa.String(36),
            sa.ForeignKey("findings.id"), nullable=False,
        ),
        sa.Column(
            "project_id", sa.String(64),
            sa.ForeignKey("projects.id"), nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("status", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.Column(
            "synced_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "finding_id", "provider",
            name="uq_finding_tickets_finding_provider",
        ),
    )
    op.create_index(
        "ix_finding_tickets_finding_id", "finding_tickets", ["finding_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_finding_tickets_finding_id", table_name="finding_tickets")
    op.drop_table("finding_tickets")
