"""Shared pytest fixtures + DB-test helpers for the Redsim suite.

Historically every DB-backed test re-declared its own copy of
``_patch_jsonb_for_sqlite`` (compile postgres ``JSONB`` → sqlite ``TEXT``)
and ``_make_session_factory`` (an in-memory sqlite engine + ``sessionmaker``
+ a commit/rollback context manager). C12 (test-ci-hygiene) consolidates
those duplicates here so there is exactly one definition to maintain.

Two consumption styles are supported, matching the two test idioms in the
suite:

* **``unittest.TestCase`` classes** import the module-level helpers directly
  (``from tests.conftest import make_sqlite_session_factory``) — they cannot
  receive pytest fixtures as arguments.
* **Function-style pytest tests** request the ``sqlite_session_factory`` /
  ``db_session`` fixtures.

Both paths build the *same* sqlite harness, so behaviour is identical.

Markers
-------
DB-backed tests carry the ``integration`` marker (defined in
``pyproject.toml``). Two paths apply it automatically so no test has to
remember to:

* Function-style tests requesting ``db_session`` / ``sqlite_session_factory``
  are stamped ``integration`` by the ``pytest_collection_modifyitems`` hook
  below (fixture-name detection — reliable at collection time).
* ``unittest`` modules — which build the harness inside ``setUp`` *after*
  collection — declare a module-level ``pytestmark = pytest.mark.integration``
  (the standard pytest idiom). They import the shared helper for the harness
  itself.

This is what makes the CI ``unit`` job's ``-m 'not integration'`` filter
meaningful — the heavier ORM-backed tests run in the Postgres-equipped
``coverage`` / ``api-integration`` jobs instead.

Everything here is sqlite-based and offline; Postgres/Redis-backed tests are
validated separately. ``sqlalchemy`` is an optional extra, so the helpers
``importorskip`` it and ``skip`` cleanly when the in-memory schema cannot be
built (e.g. a stripped-down minimal-deps environment).
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple

import pytest

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy.orm import sessionmaker


def patch_jsonb_for_sqlite() -> None:
    """Compile postgres ``JSONB`` columns to sqlite ``TEXT``.

    ``Base.metadata.create_all`` against an in-memory sqlite engine raises
    otherwise, because sqlite has no native ``JSONB`` type. Registering the
    compiler is idempotent (re-registering simply overrides the dialect
    handler), so repeated calls across tests are harmless.
    """
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _compile_jsonb_sqlite(type_, compiler, **kw):  # type: ignore[no-untyped-def]  # noqa: ARG001
        return "TEXT"


class SqliteSessionFactory(NamedTuple):
    """A built sqlite harness.

    Unpacks positionally as ``(session_cm, engine, Session)`` to match the
    legacy ``_make_session_factory`` triple, and also exposes the same three
    objects by name for callers that only need one of them.
    """

    session_cm: Callable[[], "contextlib.AbstractContextManager[SASession]"]
    engine: "Engine"
    Session: "sessionmaker[SASession]"


def make_sqlite_session_factory() -> SqliteSessionFactory:
    """Build an in-memory sqlite engine hosting the full Redsim schema.

    Returns a :class:`SqliteSessionFactory` (a ``NamedTuple`` that unpacks to
    ``(session_cm, engine, Session)``):

    * ``session_cm`` — a ``contextmanager`` yielding a ``Session`` that
      commits on clean exit and rolls back on exception. This is the shape
      ``redsim.db.session.get_session`` has, so tests patch it straight in.
    * ``engine`` — the underlying sqlite ``Engine``.
    * ``Session`` — the ``sessionmaker``; call it for ad-hoc seeding.

    A ``StaticPool`` shares the single in-memory connection across threads so
    route tests (whose handler runs in Starlette's threadpool) observe the
    same DB the test thread seeded. Skips (rather than errors) when sqlite
    cannot host the schema, keeping minimal-deps environments green.
    """
    patch_jsonb_for_sqlite()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from redsim.db.models import Base

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:  # pragma: no cover - env-dependent
        pytest.skip(f"sqlite can't host the schema: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)

    @contextlib.contextmanager
    def session_cm() -> Iterator[SASession]:
        sess = Session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    return SqliteSessionFactory(session_cm=session_cm, engine=engine, Session=Session)


@pytest.fixture
def sqlite_session_factory() -> SqliteSessionFactory:
    """Function-scoped sqlite harness (see :func:`make_sqlite_session_factory`)."""
    pytest.importorskip("sqlalchemy")
    return make_sqlite_session_factory()


@pytest.fixture
def db_session(sqlite_session_factory: SqliteSessionFactory) -> Iterator[SASession]:
    """A ready-to-use sqlite ``Session`` that commits on clean exit.

    Thin wrapper over ``sqlite_session_factory.session_cm`` for tests that
    just want a session and don't need the engine or the maker.
    """
    with sqlite_session_factory.session_cm() as sess:
        yield sess


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Stamp ``integration`` onto every test that requests a DB fixture.

    Function-style tests get the marker here by fixture-name detection (which
    is resolved by collection time). ``unittest`` modules build the harness in
    ``setUp`` — too late for this hook — so they instead declare a module-level
    ``pytestmark = pytest.mark.integration``. Centralising the fixture path
    keeps the CI ``unit`` job's ``-m 'not integration'`` filter honest without
    every function test having to remember the decorator.
    """
    db_fixtures = {"db_session", "sqlite_session_factory"}
    for item in items:
        if db_fixtures & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.integration)
