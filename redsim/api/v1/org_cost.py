"""GET /v1/orgs/{org_id}/cost — per-Organization LLM cost dashboard (Phase 6).

Cost accounting moved up a tier (migration 0006): an Organization now carries a
``monthly_llm_budget_cents`` cap, and ``LLMUsage`` rows carry a denormalized
``org_id`` (0005). This endpoint aggregates that usage into a chargeback view:
total + per-day / per-model / per-task breakdowns + the month-to-date budget
block.

Read gating mirrors reports / exports (``ensure_*_access``): any member of the
org may read its own cost dashboard — here via ``ensure_org_access`` (a member
of at least one project in the org). That is the closest existing precedent for
a tenant-scoped read; the admin-only ``/audit`` + ``/logs`` gate is the wrong
fit because cost visibility is something a tenant sees for their *own* org, not
a cross-tenant forensic surface.

The aggregation queries filter on ``LLMUsage.org_id`` (the denormalized key) so
the app-layer filter and Postgres RLS agree on the same column.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import ensure_org_access
from redsim.llm.budget import _start_of_utc_month

router = APIRouter(prefix="/orgs", tags=["orgs"])


class OrgBudget(BaseModel):
    monthly_cap_cents: int | None
    month_spent_cents: int
    remaining_cents: int | None


class OrgCostResponse(BaseModel):
    org_id: str
    days: int
    total_cents: int
    call_count: int
    by_day: dict[str, int]
    by_model: dict[str, int]
    by_task: dict[str, int]
    budget: OrgBudget


@router.get("/{org_id}/cost", response_model=OrgCostResponse)
def org_cost(
    org_id: str,
    days: int = Query(default=30, ge=1, le=366),
    user: CurrentUser = Depends(get_current_user),
) -> OrgCostResponse:
    """Per-org LLM cost breakdown over the trailing ``days`` window.

    404 when the org is unknown; 403 when the caller is not a member of any
    project in the org. The breakdown window is the trailing ``days`` (default
    30); the budget block is always the current UTC calendar month so it lines
    up with the monthly cap regardless of the breakdown window.
    """
    ensure_org_access(user, org_id)

    from redsim.db.models import LLMUsage, Organization
    from redsim.db.session import get_session

    window_start = datetime.now(UTC) - timedelta(days=days)

    with get_session() as sess:
        org = sess.get(Organization, org_id)
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"organization {org_id} not found")

        base = select(LLMUsage).where(LLMUsage.org_id == org_id)

        # Per-day (UTC date) breakdown. func.date over a tz-aware column gives
        # the calendar date on both Postgres and sqlite.
        day_rows = sess.execute(
            select(func.date(LLMUsage.created_at),
                   func.coalesce(func.sum(LLMUsage.cost_cents), 0))
            .where(LLMUsage.org_id == org_id,
                   LLMUsage.created_at >= window_start)
            .group_by(func.date(LLMUsage.created_at))
        ).all()
        by_day = {str(day): int(cents) for day, cents in day_rows}

        model_rows = sess.execute(
            select(LLMUsage.model,
                   func.coalesce(func.sum(LLMUsage.cost_cents), 0))
            .where(LLMUsage.org_id == org_id,
                   LLMUsage.created_at >= window_start)
            .group_by(LLMUsage.model)
        ).all()
        by_model = {str(model): int(cents) for model, cents in model_rows}

        task_rows = sess.execute(
            select(LLMUsage.task,
                   func.coalesce(func.sum(LLMUsage.cost_cents), 0))
            .where(LLMUsage.org_id == org_id,
                   LLMUsage.created_at >= window_start)
            .group_by(LLMUsage.task)
        ).all()
        by_task = {str(task): int(cents) for task, cents in task_rows}

        total_cents = int(sess.execute(
            select(func.coalesce(func.sum(LLMUsage.cost_cents), 0))
            .where(LLMUsage.org_id == org_id,
                   LLMUsage.created_at >= window_start)
        ).scalar_one())

        call_count = int(sess.execute(
            select(func.count())
            .select_from(base.where(LLMUsage.created_at >= window_start).subquery())
        ).scalar_one())

        cap = org.monthly_llm_budget_cents
        month_spent = int(sess.execute(
            select(func.coalesce(func.sum(LLMUsage.cost_cents), 0))
            .where(LLMUsage.org_id == org_id,
                   LLMUsage.created_at >= _start_of_utc_month())
        ).scalar_one())

    remaining = None if cap is None else int(cap) - month_spent
    budget = OrgBudget(monthly_cap_cents=cap,
                       month_spent_cents=month_spent,
                       remaining_cents=remaining)

    return OrgCostResponse(
        org_id=org_id,
        days=days,
        total_cents=total_cents,
        call_count=call_count,
        by_day=by_day,
        by_model=by_model,
        by_task=by_task,
        budget=budget,
    )
