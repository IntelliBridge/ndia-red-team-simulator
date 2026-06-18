"""C3 (llm-budget-coverage) — the agent-run path enforces the LLM budget.

The CAI agents build their model directly (not through ``router.route``), so
the router's budget hook never sees an agent run. The ``agent_run`` worker is
the chokepoint that must enforce the project (and org) cap and fail-closed
under ``llm_budget_strict``.

These drive the *real* ``task_context`` + ``DbBudgetChecker`` against an
in-memory sqlite DB (JSONB→TEXT shim) seeding an Organization, a Project with a
daily cap, and ``LLMUsage`` rows — the pattern from tests/test_org_cost_api.py.
``aegis.db.session.get_session`` is patched to the test factory so both the
worker's ``task_context`` and the budget checker resolve through it.
"""

from __future__ import annotations

import contextlib
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from aegis.agents.registry import AgentResult
from aegis.config import AegisConfig
from aegis.llm.budget import enforce_budget_for_run
from aegis.llm.router import BudgetExceeded
from aegis.workers.tasks.agent import agent_run


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(t, c, **kw):  # noqa: ARG001
        return "TEXT"


def _seeded_session_cm(*, daily_cap_cents: int | None, spent_cents: int):
    """In-memory sqlite seeded with one org/project/job and ``spent_cents`` of
    today's LLM usage. Returns a ``get_session``-shaped context-manager factory.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    _patch_jsonb_for_sqlite()
    from aegis.db.models import (
        Base,
        Job,
        LLMUsage,
        Organization,
        Project,
        Run,
    )

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="org-1",
                           monthly_llm_budget_cents=None))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="proj-1",
                      daily_llm_budget_cents=daily_cap_cents))
        s.add(Run(id="run-1", project_id="proj-1", mode="api",
                  status="queued", scanner=None, created_by="user:alice",
                  stage_table={}))
        s.add(Job(id="job-1", run_id="run-1", project_id="proj-1",
                  type="agent.run", status="queued", created_by="user:alice",
                  detail={"agent": "code_agent", "prompt": "fix it",
                          "target": None, "execute": False}))
        if spent_cents:
            s.add(LLMUsage(project_id="proj-1", org_id="org-1", model="m/x",
                           task="patch", cost_cents=spent_cents, created_at=now))
        s.commit()

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        finally:
            sess.close()

    return session_cm


@contextlib.contextmanager
def _run_worker(session_cm, *, config: AegisConfig):
    """Drive the real ``task_context`` with sqlite-backed sessions; patch the
    remaining boundary deps. Yields the ``dispatch`` mock so the test can assert
    whether the agent actually ran.
    """
    dispatch_mock = MagicMock(return_value=AgentResult(status="ok", output="done"))
    with patch("aegis.db.session.get_session", session_cm), \
            patch("aegis.db.session.init_engine"), \
            patch("aegis.config.load_config", return_value=config), \
            patch("aegis.storage.open_blob_store", return_value=MagicMock()), \
            patch("aegis.state.PostgresRunState", return_value=MagicMock()), \
            patch("aegis.audit.chain.PostgresAuditWriter", return_value=MagicMock()), \
            patch("aegis.workers.events.publish_job_event"), \
            patch("aegis.safety.authorize"), \
            patch("aegis.agents.dispatch", dispatch_mock):
        yield dispatch_mock


class TestAgentRunBudgetGate(unittest.TestCase):
    def test_exhausted_project_budget_blocks_agent_dispatch(self):
        # cap 100c, already spent 100c → remaining 0 → BudgetExceeded, agent
        # never dispatched, job result carries the error.
        session_cm = _seeded_session_cm(daily_cap_cents=100, spent_cents=100)
        config = AegisConfig(llm_budget_strict=True)
        with _run_worker(session_cm, config=config) as dispatch_mock:
            result = agent_run.apply(args=["job-1"]).get()
        self.assertEqual(result["status"], "error")
        self.assertIn("BudgetExceeded", result.get("error", ""))
        dispatch_mock.assert_not_called()

    def test_within_budget_dispatches_agent(self):
        # cap 1000c, spent 100c → remaining 900 > 0 → agent runs normally.
        session_cm = _seeded_session_cm(daily_cap_cents=1000, spent_cents=100)
        config = AegisConfig(llm_budget_strict=True)
        with _run_worker(session_cm, config=config) as dispatch_mock:
            result = agent_run.apply(args=["job-1"]).get()
        self.assertEqual(result["status"], "ok")
        dispatch_mock.assert_called_once()

    def test_uncapped_project_dispatches_agent(self):
        # No daily cap set → remaining None (uncapped) → agent runs. A run with
        # no configured budget is allowed; strict only fail-closes when the cap
        # cannot be *verified*, not when it is simply unset.
        session_cm = _seeded_session_cm(daily_cap_cents=None, spent_cents=500)
        config = AegisConfig(llm_budget_strict=True)
        with _run_worker(session_cm, config=config) as dispatch_mock:
            result = agent_run.apply(args=["job-1"]).get()
        self.assertEqual(result["status"], "ok")
        dispatch_mock.assert_called_once()


class _RaisingChecker:
    """A checker whose ``remaining`` lookup errors (e.g. DB unreachable)."""

    def remaining(self, project_id):  # noqa: ARG002
        raise RuntimeError("db down")


class _ExhaustedOrgChecker:
    def remaining(self, project_id):  # noqa: ARG002
        return 50  # project still has headroom

    def remaining_org(self, org_id):  # noqa: ARG002
        return 0   # but the org monthly cap is blown


class TestEnforceBudgetForRunHelper(unittest.TestCase):
    def test_offline_run_is_noop(self):
        # project_id None → offline / filesystem path, never enforced even under
        # strict, and never constructs a checker.
        enforce_budget_for_run(
            None, config=AegisConfig(llm_budget_strict=True),
            checker=_RaisingChecker(),
        )  # must not raise

    def test_strict_denies_when_checker_errors(self):
        with self.assertRaises(BudgetExceeded):
            enforce_budget_for_run(
                "proj-1", config=AegisConfig(llm_budget_strict=True),
                checker=_RaisingChecker(),
            )

    def test_non_strict_allows_when_checker_errors(self):
        # strict off → a transient checker error degrades to "allow" so a DB
        # blip can't wedge a non-prod run.
        enforce_budget_for_run(
            "proj-1", config=AegisConfig(llm_budget_strict=False),
            checker=_RaisingChecker(),
        )  # must not raise

    def test_exhausted_org_cap_is_enforced(self):
        # The org monthly tier is enforced alongside the project daily tier.
        with self.assertRaises(BudgetExceeded):
            enforce_budget_for_run(
                "proj-1", org_id="org-1",
                config=AegisConfig(llm_budget_strict=False),
                checker=_ExhaustedOrgChecker(),
            )


if __name__ == "__main__":
    unittest.main()
