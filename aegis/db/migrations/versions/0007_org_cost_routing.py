"""Phase 6 (Multi-tenancy) — per-ORG cost + LLM-routing columns.

Cost accounting and model routing were per-PROJECT (``projects.daily_llm_budget_cents``
+ ``DbBudgetChecker.remaining(project_id)``). This revision lifts both knobs to
the Organization tier:

- ``organizations.monthly_llm_budget_cents`` (Integer, nullable) — the org's
  monthly LLM spend cap in cents; NULL means *uncapped*.
- ``organizations.llm_model_overrides`` (JSONB, nullable) — a ``{task: model}``
  map of per-tenant routing overrides that win over the config default.

No RLS changes: ``organizations`` is the tenant *root*, not a project-scoped
table — 0006 forces RLS only on ``projects`` and the eight denormalized tables,
not on ``organizations`` itself, so there is nothing to amend here.

Idempotency mirrors 0006: ``0001_initial`` runs ``create_all`` against the
current ``models.py`` (which now declares both columns), so a fresh
``alembic upgrade head`` already has them — the ADD COLUMN uses IF NOT EXISTS.

Revision ID: 0007_org_cost_routing
Revises: 0006_tenant_rls
Create Date: 2026-06-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_org_cost_routing"
down_revision: Union[str, None] = "0006_tenant_rls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # The offline / sqlite unit path never runs migrations (it uses
        # create_all). The JSONB column + IF NOT EXISTS DDL below are
        # Postgres-specific, so guard for a clean no-op on other dialects.
        return

    op.execute(sa.text(
        "ALTER TABLE organizations "
        "ADD COLUMN IF NOT EXISTS monthly_llm_budget_cents INTEGER"
    ))
    op.execute(sa.text(
        "ALTER TABLE organizations "
        "ADD COLUMN IF NOT EXISTS llm_model_overrides JSONB"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(sa.text(
        "ALTER TABLE organizations DROP COLUMN IF EXISTS llm_model_overrides"
    ))
    op.execute(sa.text(
        "ALTER TABLE organizations DROP COLUMN IF EXISTS monthly_llm_budget_cents"
    ))
