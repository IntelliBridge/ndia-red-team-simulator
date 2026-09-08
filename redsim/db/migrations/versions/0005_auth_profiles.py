"""Phase 5 (Authenticated DAST) — auth_profiles table.

Encrypted-at-rest DAST authentication profiles. ``config`` is the
non-secret half (login_url, username_field, header_name, …); the secret
itself lives Fernet-encrypted in ``secret_ciphertext``
(``redsim.security_utils.secrets``) and is only decrypted server-side for
the worker via ``services.auth_profiles.resolve_auth_for_scan``.

Revision ID: 0005_auth_profiles
Revises: 0004_audit_append_only
Create Date: 2026-06-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_auth_profiles"
down_revision: str | None = "0004_audit_append_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Idempotency — see 0002/0003 for the same pattern + reasoning
    # (0001 is a metadata create_all, so fresh DBs already have the table).
    inspector = sa.inspect(op.get_bind())
    if "auth_profiles" in inspector.get_table_names():
        return

    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64),
                  sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("config", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("secret_ciphertext", sa.LargeBinary, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("project_id", "name",
                            name="uq_auth_profiles_project_name"),
    )
    op.create_index("ix_auth_profiles_project_id",
                    "auth_profiles", ["project_id"])

    # Role separation (guarded; mirrors 0004 Layer 2): the redsim_app DML
    # grant list there is enumerated per-table, so the new table needs its
    # own grant. No-ops in CI where the role is absent.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'redsim_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE
                    ON TABLE auth_profiles TO redsim_app;
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.drop_index("ix_auth_profiles_project_id", table_name="auth_profiles")
    op.drop_table("auth_profiles")
