"""Phase 4 v0.4.1 F20c — application_logs table.

The OTel Collector fans logs out to Loki / Elasticsearch under the
``obs`` and ``obs-search`` compose profiles; the always-on Postgres
mirror path lands rows here via the ``aegis-log-ingest`` service.

Revision ID: 0003_application_logs
Revises: 0002_findings_pk_uuid
Create Date: 2026-05-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0003_application_logs"
down_revision: Union[str, None] = "0002_findings_pk_uuid"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotency — see 0002 for the same pattern + reasoning.
    inspector = sa.inspect(op.get_bind())
    if "application_logs" in inspector.get_table_names():
        return

    op.create_table(
        "application_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("run_id", sa.String(64), nullable=True),
        sa.Column("job_id", sa.String(64), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column("actor", sa.String(256), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("trace_id", sa.String(64), nullable=True),
        sa.Column("span_id", sa.String(32), nullable=True),
        sa.Column(
            "attrs", postgresql.JSONB, nullable=False, server_default="{}",
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Index set chosen to support the common queries:
    # - per run, descending ts (run-detail logs tab)
    # - per project, descending ts (project-wide tail)
    # - per request_id (correlate API + worker + scanner)
    # - per trace_id (Tempo / Jaeger correlation)
    # - per severity + ts (filtered tail)
    op.create_index("ix_logs_run_ts",
                    "application_logs", ["run_id", "ts"],
                    postgresql_ops={"ts": "DESC"})
    op.create_index("ix_logs_project_ts",
                    "application_logs", ["project_id", "ts"],
                    postgresql_ops={"ts": "DESC"})
    op.create_index("ix_logs_request",
                    "application_logs", ["request_id"])
    op.create_index("ix_logs_trace",
                    "application_logs", ["trace_id"])
    op.create_index("ix_logs_severity_ts",
                    "application_logs", ["severity", "ts"],
                    postgresql_ops={"ts": "DESC"})
    op.create_index("ix_logs_service",
                    "application_logs", ["service"])
    op.create_index("ix_logs_ts",
                    "application_logs", ["ts"])


def downgrade() -> None:
    op.drop_index("ix_logs_ts", table_name="application_logs")
    op.drop_index("ix_logs_service", table_name="application_logs")
    op.drop_index("ix_logs_severity_ts", table_name="application_logs")
    op.drop_index("ix_logs_trace", table_name="application_logs")
    op.drop_index("ix_logs_request", table_name="application_logs")
    op.drop_index("ix_logs_project_ts", table_name="application_logs")
    op.drop_index("ix_logs_run_ts", table_name="application_logs")
    op.drop_table("application_logs")
