"""DB-backed LLM budget checker.

Phase 3 M5 wires the ``route()`` budget hook to the real ``llm_usage``
table. ``DbBudgetChecker`` satisfies the ``BudgetChecker`` Protocol from
``aegis.llm.router``: ``remaining(project_id)`` returns the project's
remaining daily LLM budget in cents (``None`` == unlimited / no cap set).

The "daily" window is the current UTC calendar day; the
``ix_llm_usage_project_created`` ``(project_id, created_at)`` index backs
the ``created_at >= start_of_utc_day`` range scan.
"""

from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Callable, ContextManager

from sqlalchemy import func, or_, select

from aegis.db.models import LLMUsage, Organization, Project


def _start_of_utc_day(now: datetime | None = None) -> datetime:
    """Midnight (00:00:00) UTC of the current day, tz-aware."""
    now = now or datetime.now(timezone.utc)
    return datetime.combine(now.astimezone(timezone.utc).date(), time.min,
                            tzinfo=timezone.utc)


def _start_of_utc_month(now: datetime | None = None) -> datetime:
    """Midnight UTC of the first day of the current month, tz-aware."""
    today = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
    return datetime.combine(today.replace(day=1), time.min, tzinfo=timezone.utc)


class DbBudgetChecker:
    """``BudgetChecker`` reading ``Project.daily_llm_budget_cents`` minus the
    sum of today's ``LLMUsage.cost_cents`` for that project.

    The constructor takes a session factory — a zero-arg callable returning a
    context manager that yields a SQLAlchemy ``Session`` (the
    ``aegis.db.session.get_session`` shape). Defaulting to ``get_session``
    keeps callers terse while letting tests inject an sqlite-backed factory.
    """

    def __init__(self, session_factory: Callable[[], ContextManager] | None = None):
        if session_factory is None:
            from aegis.db.session import get_session
            session_factory = get_session
        self._session_factory = session_factory

    def remaining(self, project_id: str | None) -> int | None:
        """Remaining daily budget in cents, or ``None`` when uncapped.

        Returns ``None`` (unlimited) when ``project_id`` is missing, the
        project row is absent, or its ``daily_llm_budget_cents`` is unset.
        Otherwise returns ``cap - SUM(today's cost_cents)`` — which may be
        ``<= 0`` when the cap is exhausted.
        """
        if not project_id:
            return None
        with self._session_factory() as sess:
            cap = sess.execute(
                select(Project.daily_llm_budget_cents)
                .where(Project.id == project_id)
            ).scalar_one_or_none()
            if cap is None:
                return None
            spent = sess.execute(
                select(func.coalesce(func.sum(LLMUsage.cost_cents), 0))
                .where(
                    LLMUsage.project_id == project_id,
                    LLMUsage.created_at >= _start_of_utc_day(),
                )
            ).scalar_one()
            return int(cap) - int(spent or 0)

    def remaining_org(self, org_id: str | None) -> int | None:
        """Remaining *monthly* org budget in cents, or ``None`` when uncapped.

        Mirrors ``remaining()`` one tier up: ``Organization.monthly_llm_budget_cents``
        minus the sum of this UTC calendar month's ``LLMUsage.cost_cents`` for
        the org. Returns ``None`` (unlimited) when ``org_id`` is missing, the
        org row is absent, or its cap is unset; otherwise ``cap - SUM(spent)``,
        which may be ``<= 0`` when exhausted.

        Usage is matched on the denormalized ``LLMUsage.org_id`` (0005),
        falling back to the owning ``Project.org_id`` for any legacy rows that
        predate the denormalization (``org_id IS NULL``) — so historical spend
        still counts against the cap.
        """
        if not org_id:
            return None
        with self._session_factory() as sess:
            cap = sess.execute(
                select(Organization.monthly_llm_budget_cents)
                .where(Organization.id == org_id)
            ).scalar_one_or_none()
            if cap is None:
                return None
            spent = sess.execute(
                select(func.coalesce(func.sum(LLMUsage.cost_cents), 0))
                .select_from(LLMUsage)
                .join(Project, Project.id == LLMUsage.project_id)
                .where(
                    or_(
                        LLMUsage.org_id == org_id,
                        # Legacy rows: org_id not yet backfilled — fall back to
                        # the owning project's org_id so old spend still counts.
                        (LLMUsage.org_id.is_(None)) & (Project.org_id == org_id),
                    ),
                    LLMUsage.created_at >= _start_of_utc_month(),
                )
            ).scalar_one()
            return int(cap) - int(spent or 0)

    def model_override(self, org_id: str | None, task: str) -> str | None:
        """Per-tenant routing override for ``task``, or ``None``.

        Reads ``Organization.llm_model_overrides[task]`` for the org. Returns
        ``None`` when ``org_id`` is missing, the org row is absent, the
        overrides map is unset, or the task isn't mapped. The router uses this
        before falling back to the AegisConfig default.
        """
        if not org_id:
            return None
        with self._session_factory() as sess:
            overrides = sess.execute(
                select(Organization.llm_model_overrides)
                .where(Organization.id == org_id)
            ).scalar_one_or_none()
        if not isinstance(overrides, dict):
            return None
        model = overrides.get(task)
        return model if isinstance(model, str) and model else None
