"""Phase 3 M5 — LLM budget enforcement (offline, DB-free by default).

``DbBudgetChecker`` is exercised against an in-memory sqlite (the same
JSONB→TEXT compile shim ``tests/test_agents_api.py`` uses, since the
shared metadata pulls in JSONB columns). The ``route()`` gate is a pure
unit test with a fake checker — no DB, no CAI.
"""

from __future__ import annotations

import contextlib
import unittest
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")

from aegis.config import AegisConfig
from aegis.db.models import Base, LLMUsage, Organization, Project
from aegis.llm.budget import DbBudgetChecker
from aegis.llm.router import BudgetExceeded, route


def _patch_jsonb_for_sqlite() -> None:
    """Compile postgres JSONB → sqlite TEXT so create_all doesn't raise."""
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _compile_jsonb_sqlite(type_, compiler, **kw):  # noqa: ARG001
        return "TEXT"


def _make_session_factory():
    """Return a (session_cm, Session) pair backed by in-memory sqlite."""
    _patch_jsonb_for_sqlite()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:  # pragma: no cover - env-dependent
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    return session_cm, Session


def _seed_project(Session, *, project_id: str, cap: int | None) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id=project_id, org_id="org-1", name="P", slug="p",
                      daily_llm_budget_cents=cap))
        s.commit()


def _add_usage(Session, *, project_id: str, cost_cents: int,
               created_at: datetime) -> None:
    with Session() as s:
        s.add(LLMUsage(project_id=project_id, run_id=None, model="m",
                       task="patch", prompt_tokens=0, completion_tokens=0,
                       cost_cents=cost_cents, created_at=created_at))
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
        now = datetime.now(timezone.utc)
        _add_usage(Session, project_id="proj-1", cost_cents=300, created_at=now)
        _add_usage(Session, project_id="proj-1", cost_cents=150, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # 1000 - (300 + 150) == 550
        self.assertEqual(checker.remaining("proj-1"), 550)

    def test_remaining_excludes_previous_days(self):
        session_cm, Session = _make_session_factory()
        _seed_project(Session, project_id="proj-1", cap=1000)
        now = datetime.now(timezone.utc)
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
        now = datetime.now(timezone.utc)
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
        now = datetime.now(timezone.utc)
        _add_usage(Session, project_id="proj-2", cost_cents=400, created_at=now)
        checker = DbBudgetChecker(session_factory=session_cm)
        # proj-2's spend must not count against proj-1
        self.assertEqual(checker.remaining("proj-1"), 1000)


class _FakeChecker:
    def __init__(self, value: int | None):
        self._value = value
        self.calls: list[str | None] = []

    def remaining(self, project_id: str | None) -> int | None:
        self.calls.append(project_id)
        return self._value


class TestRouteBudgetGate(unittest.TestCase):
    def setUp(self):
        self.config = AegisConfig(model="gpt-test")

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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
