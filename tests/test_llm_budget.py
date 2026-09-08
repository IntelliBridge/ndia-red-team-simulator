"""Phase 3 M5 — LLM budget enforcement (offline, DB-free by default).

``DbBudgetChecker`` is exercised against an in-memory sqlite (the same
JSONB→TEXT compile shim ``tests/test_agents_api.py`` uses, since the
shared metadata pulls in JSONB columns). The ``route()`` gate is a pure
unit test with a fake checker — no DB, no CAI.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("sqlalchemy")

from redsim.config import RedsimConfig
from redsim.db.models import LLMUsage, Organization, Project
from redsim.llm.budget import DbBudgetChecker
from redsim.llm.router import BudgetExceeded, route
from tests.conftest import make_sqlite_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration


def _make_session_factory():
    """Return a ``(session_cm, Session)`` pair backed by in-memory sqlite.

    The shared ``make_sqlite_session_factory`` returns the
    ``(session_cm, engine, Session)`` triple; this module only needs the
    context manager + the maker, so drop the engine.
    """
    factory = make_sqlite_session_factory()
    return factory.session_cm, factory.Session


def _seed_project(Session, *, project_id: str, cap: int | None) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id=project_id, org_id="org-1", name="P", slug="p",
                      daily_llm_budget_cents=cap))
        s.commit()


def _seed_org(Session, *, org_id: str, monthly_cap: int | None,
              overrides: dict | None = None, project_id: str | None = None) -> None:
    """Seed an org (+ optional project) for the org-tier budget/override tests."""
    with Session() as s:
        s.add(Organization(id=org_id, name=org_id, slug=org_id,
                           monthly_llm_budget_cents=monthly_cap,
                           llm_model_overrides=overrides))
        if project_id is not None:
            s.add(Project(id=project_id, org_id=org_id, name="P", slug=project_id))
        s.commit()


def _add_usage(Session, *, project_id: str, cost_cents: int,
               created_at: datetime, org_id: str | None = None) -> None:
    with Session() as s:
        s.add(LLMUsage(project_id=project_id, org_id=org_id, run_id=None,
                       model="m", task="patch", prompt_tokens=0,
                       completion_tokens=0, cost_cents=cost_cents,
                       created_at=created_at))
        s.commit()


class TestDbBudgetChecker(unittest.TestCase):
    def test_remaining_none_when_cap_unset(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=None)
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining("proj-1"))

    def test_remaining_none_when_project_missing(self):
        session_cm, _ = _make_session_factory()
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining("nope"))

    def test_remaining_none_when_project_id_falsy(self):
        session_cm, _ = _make_session_factory()
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining(None))

    def test_remaining_is_cap_minus_todays_cost(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=1000)
        now = datetime.now(UTC)
        _add_usage(Session, project_id="proj-1", cost_cents=300, created_at=now)
        _add_usage(Session, project_id="proj-1", cost_cents=150, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # 1000 - (300 + 150) == 550
        self.assertEqual(checker.remaining("proj-1"), 550)

    def test_remaining_excludes_previous_days(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=1000)
        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)
        _add_usage(Session, project_id="proj-1", cost_cents=900,
                   created_at=yesterday)  # excluded
        _add_usage(Session, project_id="proj-1", cost_cents=200, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # only today's 200 counts → 1000 - 200 == 800
        self.assertEqual(checker.remaining("proj-1"), 800)

    def test_remaining_can_go_non_positive(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=100)
        now = datetime.now(UTC)
        _add_usage(Session, project_id="proj-1", cost_cents=250, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.remaining("proj-1"), -150)

    def test_remaining_excludes_other_projects(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=1000)
        with Session() as s:
            s.add(Project(id="proj-2", org_id="org-1", name="Q", slug="q",
                          daily_llm_budget_cents=1000))
            s.commit()
        now = datetime.now(UTC)
        _add_usage(Session, project_id="proj-2", cost_cents=400, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # proj-2's spend must not count against proj-1
        self.assertEqual(checker.remaining("proj-1"), 1000)


class TestDbBudgetCheckerOrg(unittest.TestCase):
    def test_remaining_org_none_when_cap_unset(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=None, project_id="p1")
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining_org("org-1"))

    def test_remaining_org_none_when_org_missing(self):
        session_cm, _ = _make_session_factory()
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining_org("nope"))

    def test_remaining_org_none_when_org_id_falsy(self):
        session_cm, _ = _make_session_factory()
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.remaining_org(None))

    def test_remaining_org_no_usage_is_full_cap(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=5000, project_id="p1")
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.remaining_org("org-1"), 5000)

    def test_remaining_org_under_cap(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=5000, project_id="p1")
        now = datetime.now(UTC)
        _add_usage(Session, project_id="p1", org_id="org-1",
                   cost_cents=1200, created_at=now)
        _add_usage(Session, project_id="p1", org_id="org-1",
                   cost_cents=800, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # 5000 - (1200 + 800) == 3000
        self.assertEqual(checker.remaining_org("org-1"), 3000)

    def test_remaining_org_over_cap_goes_non_positive(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=1000, project_id="p1")
        now = datetime.now(UTC)
        _add_usage(Session, project_id="p1", org_id="org-1",
                   cost_cents=1500, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.remaining_org("org-1"), -500)

    def test_remaining_org_excludes_other_orgs(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=1000, project_id="p1")
        _seed_org(Session, org_id="org-2", monthly_cap=1000, project_id="p2")
        now = datetime.now(UTC)
        _add_usage(Session, project_id="p2", org_id="org-2",
                   cost_cents=400, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # org-2's spend must not count against org-1.
        self.assertEqual(checker.remaining_org("org-1"), 1000)

    def test_remaining_org_excludes_previous_months(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=1000, project_id="p1")
        now = datetime.now(UTC)
        # A point firmly inside the previous month.
        last_month = (now.replace(day=1) - timedelta(days=2))
        _add_usage(Session, project_id="p1", org_id="org-1",
                   cost_cents=900, created_at=last_month)  # excluded
        _add_usage(Session, project_id="p1", org_id="org-1",
                   cost_cents=200, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.remaining_org("org-1"), 800)

    def test_remaining_org_counts_legacy_rows_via_project_join(self):
        # Rows that predate the org_id denormalization (org_id NULL) still
        # count via the owning project's org_id.
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=1000, project_id="p1")
        now = datetime.now(UTC)
        _add_usage(Session, project_id="p1", org_id=None,
                   cost_cents=300, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.remaining_org("org-1"), 700)

    def test_model_override_returns_mapped_model(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=None,
                  overrides={"patch": "anthropic/claude-opus-4-8"},
                  project_id="p1")
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertEqual(checker.model_override("org-1", "patch"),
                         "anthropic/claude-opus-4-8")

    def test_model_override_none_when_task_unmapped(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=None,
                  overrides={"patch": "x"}, project_id="p1")
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.model_override("org-1", "recon"))

    def test_model_override_none_when_unset(self):
        session_cm, Session = _make_session_factory()
        _seed_org(Session, org_id="org-1", monthly_cap=None, project_id="p1")
        checker = DbBudgetChecker(session_factory=session_cm)
        self.assertIsNone(checker.model_override("org-1", "patch"))


class _FakeChecker:
    def __init__(self, value: int | None):
        self._value = value
        self.calls: list[str | None] = []

    def remaining(self, project_id: str | None) -> int | None:
        self.calls.append(project_id)
        return self._value


class _FakeOrgChecker:
    """Checker exposing the Phase 6 surface for router gate/override tests."""

    def __init__(self, *, project_remaining: int | None = None,
                 org_remaining: int | None = None,
                 override: str | None = None):
        self._project_remaining = project_remaining
        self._org_remaining = org_remaining
        self._override = override
        self.project_calls: list[str | None] = []
        self.org_calls: list[str | None] = []
        self.override_calls: list[tuple[str | None, str]] = []

    def remaining(self, project_id: str | None) -> int | None:
        self.project_calls.append(project_id)
        return self._project_remaining

    def remaining_org(self, org_id: str | None) -> int | None:
        self.org_calls.append(org_id)
        return self._org_remaining

    def model_override(self, org_id: str | None, task: str) -> str | None:
        self.override_calls.append((org_id, task))
        return self._override


class TestRouteBudgetGate(unittest.TestCase):
    def setUp(self):
        self.config = RedsimConfig(model="gpt-test")

    def test_route_raises_when_exhausted(self):
        checker = _FakeChecker(0)
        with self.assertRaises(BudgetExceeded):
            route("patch", self.config, project_id="proj-1",
                  budget_checker=checker)
        self.assertEqual(checker.calls, ["proj-1"])

    def test_route_raises_when_negative(self):
        checker = _FakeChecker(-50)
        with self.assertRaises(BudgetExceeded):
            route("patch", self.config, project_id="proj-1",
                  budget_checker=checker)

    def test_route_allows_when_positive(self):
        checker = _FakeChecker(500)
        spec = route("patch", self.config, project_id="proj-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "gpt-test")
        self.assertEqual(spec.budget_remaining_cents, 500)

    def test_route_allows_when_unlimited(self):
        checker = _FakeChecker(None)
        spec = route("patch", self.config, project_id="proj-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "gpt-test")
        self.assertIsNone(spec.budget_remaining_cents)

    def test_route_noop_without_checker(self):
        # No checker supplied → true no-op, no budget fields populated.
        spec = route("patch", self.config, project_id="proj-1")
        self.assertEqual(spec.model, "gpt-test")
        self.assertIsNone(spec.budget_remaining_cents)

    def test_legacy_checker_without_org_methods_still_works(self):
        # A checker exposing only remaining() (the Phase 3 shape) must still
        # gate the project tier even when org_id is supplied.
        checker = _FakeChecker(0)
        with self.assertRaises(BudgetExceeded):
            route("patch", self.config, project_id="proj-1", org_id="org-1",
                  budget_checker=checker)


class TestRouteOrgRouting(unittest.TestCase):
    def setUp(self):
        self.config = RedsimConfig(model="gpt-test")

    def test_org_override_wins_over_config_default(self):
        checker = _FakeOrgChecker(project_remaining=100, org_remaining=100,
                                  override="anthropic/claude-opus-4-8")
        spec = route("patch", self.config, project_id="proj-1", org_id="org-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "anthropic/claude-opus-4-8")
        self.assertEqual(checker.override_calls, [("org-1", "patch")])

    def test_falls_back_to_config_when_no_override(self):
        checker = _FakeOrgChecker(project_remaining=100, org_remaining=100,
                                  override=None)
        spec = route("patch", self.config, project_id="proj-1", org_id="org-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "gpt-test")

    def test_org_budget_exhausted_raises(self):
        checker = _FakeOrgChecker(project_remaining=500, org_remaining=0)
        with self.assertRaises(BudgetExceeded) as ctx:
            route("patch", self.config, project_id="proj-1", org_id="org-1",
                  budget_checker=checker)
        self.assertIn("organization", str(ctx.exception))
        self.assertIn("monthly", str(ctx.exception))

    def test_project_budget_exhausted_raises(self):
        checker = _FakeOrgChecker(project_remaining=0, org_remaining=500)
        with self.assertRaises(BudgetExceeded) as ctx:
            route("patch", self.config, project_id="proj-1", org_id="org-1",
                  budget_checker=checker)
        self.assertIn("project", str(ctx.exception))
        self.assertIn("daily", str(ctx.exception))

    def test_both_fine_returns_tighter_remaining(self):
        checker = _FakeOrgChecker(project_remaining=500, org_remaining=120,
                                  override="anthropic/claude-opus-4-8")
        spec = route("patch", self.config, project_id="proj-1", org_id="org-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "anthropic/claude-opus-4-8")
        # Reports the tighter of the two remaining values.
        self.assertEqual(spec.budget_remaining_cents, 120)

    def test_org_none_is_legacy_behavior(self):
        # org_id=None → no override consulted, org budget not checked.
        checker = _FakeOrgChecker(project_remaining=300, org_remaining=0,
                                  override="should-not-be-used")
        spec = route("patch", self.config, project_id="proj-1",
                     budget_checker=checker)
        self.assertEqual(spec.model, "gpt-test")
        self.assertEqual(spec.budget_remaining_cents, 300)
        self.assertEqual(checker.org_calls, [])
        self.assertEqual(checker.override_calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
