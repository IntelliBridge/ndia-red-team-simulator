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

from sqlalchemy import func, select

from aegis.db.models import LLMUsage, Project


def _start_of_utc_day(now: datetime | None = None) -> datetime:
    """Midnight (00:00:00) UTC of the current day, tz-aware."""
    now = now or datetime.now(timezone.utc)
    return datetime.combine(now.astimezone(timezone.utc).date(), time.min,
                            tzinfo=timezone.utc)


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
