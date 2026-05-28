"""Phase 4 v0.3.1 F9 — Finding PK becomes a UUID; scanner identifier
moves to scanner_finding_id with UNIQUE(run_id, scanner_finding_id).

Two parallel runs can independently emit findings with the same upstream
identifier (e.g. ``vuln-0001`` from Strix); the original String(128) PK
made them collide. This migration walks every existing row, allocates a
UUID for the new PK, copies the old identifier into scanner_finding_id,
and updates the FK fan-out from remediation_attempts.

Revision ID: 0002_findings_pk_uuid
Revises: 0001_initial
Create Date: 2026-05-28
"""

from __future__ import annotations

from typing import Sequence, Union
from uuid import uuid4

import sqlalchemy as sa
from alembic import op


revision: str = "0002_findings_pk_uuid"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Add the new scanner_finding_id column (nullable for the backfill).
    op.add_column(
        "findings",
        sa.Column("scanner_finding_id", sa.String(length=256), nullable=True),
    )

    # 2. Backfill: copy current findings.id into scanner_finding_id.
    op.execute("UPDATE findings SET scanner_finding_id = id")

    # 3. Drop the existing PK + FK referencing it.
    op.execute("ALTER TABLE remediation_attempts DROP CONSTRAINT IF EXISTS remediation_attempts_finding_id_fkey")
    op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_pkey")

    # 4. Walk every row, assign a new UUID, propagate to remediation_attempts.
    rows = bind.execute(sa.text("SELECT id FROM findings")).fetchall()
    for (old_id,) in rows:
        new_id = str(uuid4())
        bind.execute(
            sa.text("UPDATE findings SET id = :new WHERE id = :old"),
            {"new": new_id, "old": old_id},
        )
        bind.execute(
            sa.text("UPDATE remediation_attempts SET finding_id = :new WHERE finding_id = :old"),
            {"new": new_id, "old": old_id},
        )

    # 5. Shrink the id column to UUID width.
    op.alter_column(
        "findings", "id",
        existing_type=sa.String(length=128),
        type_=sa.String(length=36),
        existing_nullable=False,
    )

    # 6. Make scanner_finding_id NOT NULL + add the unique constraint.
    op.alter_column("findings", "scanner_finding_id", nullable=False)
    op.create_unique_constraint(
        "uq_findings_run_scanner_id", "findings",
        ["run_id", "scanner_finding_id"],
    )
    op.create_index(
        "ix_findings_scanner_finding_id", "findings", ["scanner_finding_id"],
    )

    # 7. Restore the PK + the remediation_attempts FK.
    op.create_primary_key("findings_pkey", "findings", ["id"])
    op.create_foreign_key(
        "remediation_attempts_finding_id_fkey",
        "remediation_attempts", "findings",
        ["finding_id"], ["id"],
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.execute("ALTER TABLE remediation_attempts DROP CONSTRAINT IF EXISTS remediation_attempts_finding_id_fkey")
    op.drop_index("ix_findings_scanner_finding_id", table_name="findings")
    op.drop_constraint("uq_findings_run_scanner_id", "findings", type_="unique")
    op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_pkey")

    # Restore the original PK shape from scanner_finding_id values.
    bind.execute(sa.text("UPDATE findings SET id = scanner_finding_id"))
    op.alter_column(
        "findings", "id",
        existing_type=sa.String(length=36),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    op.drop_column("findings", "scanner_finding_id")
    op.create_primary_key("findings_pkey", "findings", ["id"])
    op.create_foreign_key(
        "remediation_attempts_finding_id_fkey",
        "remediation_attempts", "findings",
        ["finding_id"], ["id"],
    )
