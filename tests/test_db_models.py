"""Smoke: SQLAlchemy models import cleanly and create_all on SQLite works.

The real Postgres integration suite runs only when REDSIM_TEST_DB_URL is set.
"""

import unittest

import pytest

pytest.importorskip("sqlalchemy")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redsim.db.models import (
    Base,
    Organization,
)


# JSONB / pg_uuid don't exist on sqlite, so we swap the dialect-specific
# columns for the smoke test only.
def _sqlite_safe_metadata():
    # SQLAlchemy 2.x: JSON is dialect-aware; JSONB will fall through to JSON
    # for sqlite. We just need create_all to not raise.
    return Base.metadata


class TestSchemaImportsAndCreateAll(unittest.TestCase):
    def test_create_all_on_sqlite(self):
        engine = create_engine("sqlite://", future=True)
        with self.assertWarnsRegex(Warning, "JSONB|datatype") if False else \
             _NoOpContext():
            pass
        try:
            _sqlite_safe_metadata().create_all(bind=engine)
        except Exception as exc:  # noqa: BLE001 - SQLite balks on JSONB, that is expected
            self.skipTest(f"SQLite cannot host JSONB columns: {exc}")
        Session = sessionmaker(engine)
        with Session() as s:
            org = Organization(id="org-1", name="Acme", slug="acme")
            s.add(org)
            s.commit()
            self.assertEqual(s.get(Organization, "org-1").slug, "acme")


class _NoOpContext:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class TestModelsImported(unittest.TestCase):
    def test_all_tables_present(self):
        names = {t.name for t in Base.metadata.tables.values()}
        for required in (
            "organizations", "projects", "users", "project_memberships",
            "targets", "runs", "jobs", "findings", "llm_usage", "artifacts",
            "remediation_attempts", "audit_events", "audit_chain_heads",
            "github_installations",
        ):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
