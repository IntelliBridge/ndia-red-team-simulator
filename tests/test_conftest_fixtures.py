"""Regression tests for the shared DB-test harness in ``tests/conftest.py``.

C12 (test-ci-hygiene) consolidated the per-file ``_patch_jsonb_for_sqlite`` +
``_make_session_factory`` duplicates into one place. These tests pin the
behaviour the migrated suites rely on:

* ``make_sqlite_session_factory`` builds a usable in-memory sqlite harness and
  unpacks both positionally (the legacy ``(session_cm, engine, Session)``
  triple) and by name.
* the ``sqlite_session_factory`` / ``db_session`` fixtures hand back the same
  harness / a ready session.
* DB-backed tests carry the ``integration`` marker so the CI ``unit`` job's
  ``-m 'not integration'`` filter is meaningful (it was inert before C12).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("sqlalchemy")

from tests.conftest import (
    SqliteSessionFactory,
    make_sqlite_session_factory,
    patch_jsonb_for_sqlite,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session as SASession


def test_make_factory_unpacks_as_triple_and_by_name() -> None:
    factory = make_sqlite_session_factory()
    # NamedTuple: positional unpack matches the legacy (session_cm, engine,
    # Session) shape the migrated unittest classes still destructure.
    session_cm, engine, Session = factory
    assert callable(session_cm)
    assert engine.dialect.name == "sqlite"
    # ...and the same objects are reachable by name.
    assert isinstance(factory, SqliteSessionFactory)
    assert factory.session_cm is session_cm
    assert factory.engine is engine
    assert factory.Session is Session


def test_factory_session_cm_commits_and_persists() -> None:
    from redsim.db.models import Organization

    session_cm, _engine, Session = make_sqlite_session_factory()
    with session_cm() as sess:
        sess.add(Organization(id="org-1", name="A", slug="a"))
    # A fresh session sees the committed row (commit-on-clean-exit contract).
    with Session() as sess:
        assert sess.get(Organization, "org-1") is not None


def test_factory_session_cm_rolls_back_on_error() -> None:
    from redsim.db.models import Organization

    session_cm, _engine, Session = make_sqlite_session_factory()
    with pytest.raises(RuntimeError):
        with session_cm() as sess:
            sess.add(Organization(id="org-2", name="B", slug="b"))
            raise RuntimeError("boom")
    with Session() as sess:
        assert sess.get(Organization, "org-2") is None


def test_each_factory_call_is_isolated() -> None:
    from redsim.db.models import Organization

    first = make_sqlite_session_factory()
    with first.session_cm() as sess:
        sess.add(Organization(id="org-iso", name="A", slug="a"))
    # A separate harness is a separate engine — it must not see the other's row.
    second = make_sqlite_session_factory()
    with second.Session() as sess:
        assert sess.get(Organization, "org-iso") is None


def test_patch_jsonb_is_idempotent() -> None:
    # Re-registering the JSONB->TEXT compiler must not raise.
    patch_jsonb_for_sqlite()
    patch_jsonb_for_sqlite()


def test_sqlite_session_factory_fixture(sqlite_session_factory: SqliteSessionFactory) -> None:
    assert isinstance(sqlite_session_factory, SqliteSessionFactory)
    assert sqlite_session_factory.engine.dialect.name == "sqlite"


def test_db_session_fixture_is_usable(db_session: SASession) -> None:
    from redsim.db.models import Organization

    db_session.add(Organization(id="org-fix", name="A", slug="a"))
    db_session.flush()
    assert db_session.get(Organization, "org-fix") is not None


def test_db_session_request_is_marked_integration(
    db_session: SASession, request: pytest.FixtureRequest
) -> None:
    """A test requesting ``db_session`` is auto-marked ``integration``.

    This is the lever that makes the CI unit job's ``-m 'not integration'``
    filter real. The fixture must be requested via the signature (not
    ``getfixturevalue``) so it lands in ``item.fixturenames`` at collection
    time, when the ``pytest_collection_modifyitems`` hook stamps the marker.
    """
    assert db_session is not None
    assert "integration" in request.node.keywords


def test_sqlite_factory_request_is_marked_integration(
    sqlite_session_factory: SqliteSessionFactory, request: pytest.FixtureRequest
) -> None:
    """A test requesting ``sqlite_session_factory`` is auto-marked ``integration``."""
    assert sqlite_session_factory is not None
    assert "integration" in request.node.keywords


def test_non_db_test_is_not_marked_integration(request: pytest.FixtureRequest) -> None:
    """A test that requests no DB fixture stays out of the ``integration`` set."""
    assert "integration" not in request.node.keywords
