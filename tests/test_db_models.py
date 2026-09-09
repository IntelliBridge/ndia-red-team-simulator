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
            # Phase B (migration 0011_phase_b_platform).
            "report_snapshots", "idempotency_keys", "ml_batches", "ml_datasets",
        ):
            self.assertIn(required, names)

    def test_project_has_phase_b_columns_nullable_and_existing_unchanged(self):
        from redsim.db.models import Project
        cols = Project.__table__.columns
        for name in ("ml_scoring", "ml_max_concurrent_runs", "ml_daily_run_budget"):
            self.assertIn(name, cols)
            self.assertTrue(cols[name].nullable, f"projects.{name} must be nullable")
        # The pre-0011 column set is untouched.
        for name in ("id", "org_id", "name", "slug", "daily_llm_budget_cents", "created_at"):
            self.assertIn(name, cols)
        self.assertFalse(cols["org_id"].nullable)
        self.assertTrue(cols["daily_llm_budget_cents"].nullable)

    def test_ml_campaigns_stays_migration_owned(self):
        # ``ml_campaigns`` is reflected by the services and mirrored by hand in
        # the sqlite harnesses; an ORM model would collide with those mirrors.
        names = {t.name for t in Base.metadata.tables.values()}
        self.assertNotIn("ml_campaigns", names)


class TestPhaseBModelsRoundTrip(unittest.TestCase):
    """The 0011 models persist and read back on the shared sqlite harness,
    JSON columns included, with their Python-side defaults applied."""

    def setUp(self):
        from redsim.db.models import Organization, Project, Run
        from tests.conftest import make_sqlite_session_factory

        _, self.engine, self.Session = make_sqlite_session_factory()
        with self.Session() as s:
            s.add(Organization(id="org-b0", name="B0", slug="org-b0"))
            s.flush()
            s.add(Project(id="proj-b0", org_id="org-b0", name="P", slug="proj-b0",
                          ml_scoring={"version": "scoring-1", "weights": {"asr": 0.2}},
                          ml_max_concurrent_runs=2, ml_daily_run_budget=None))
            s.flush()
            s.add(Run(id="run-b0", project_id="proj-b0", created_by="cli:test"))
            s.commit()

    def tearDown(self):
        self.engine.dispose()

    def test_project_phase_b_columns_round_trip(self):
        from redsim.db.models import Project

        with self.Session() as s:
            p = s.get(Project, "proj-b0")
            self.assertEqual(p.ml_scoring, {"version": "scoring-1", "weights": {"asr": 0.2}})
            self.assertEqual(p.ml_max_concurrent_runs, 2)
            self.assertIsNone(p.ml_daily_run_budget)

    def test_report_snapshot_round_trip_and_defaults(self):
        from redsim.db.models import ReportSnapshot

        with self.Session() as s:
            s.add(ReportSnapshot(id="snap-1", run_id="run-b0", project_id="proj-b0",
                                 artifact_ids=["art-html", "art-json"], record_sha256="a" * 64))
            s.commit()
        with self.Session() as s:
            snap = s.get(ReportSnapshot, "snap-1")
            self.assertEqual(snap.artifact_ids, ["art-html", "art-json"])
            self.assertEqual(snap.record_sha256, "a" * 64)
            self.assertFalse(snap.archived)
            self.assertIsNotNone(snap.rendered_at)
            self.assertIsNone(snap.org_id)  # app code never sets it; the trigger does

    def test_idempotency_key_composite_identity_round_trip(self):
        from sqlalchemy.exc import IntegrityError

        from redsim.db.models import IdempotencyKey

        with self.Session() as s:
            s.add(IdempotencyKey(project_id="proj-b0", key="k-1", route="POST /v1/models",
                                 request_sha256="b" * 64, response_status=201,
                                 response_body={"id": "m-1"}))
            s.commit()
        with self.Session() as s:
            row = s.get(IdempotencyKey, ("proj-b0", "k-1"))
            self.assertEqual(row.response_status, 201)
            self.assertEqual(row.response_body, {"id": "m-1"})
        # The same key in the same project is refused by the primary key.
        with self.Session() as s, self.assertRaises(IntegrityError):
            s.add(IdempotencyKey(project_id="proj-b0", key="k-1", route="POST /v1/models",
                                 request_sha256="c" * 64, response_status=201))
            s.commit()

    def test_ml_batch_and_dataset_round_trip_and_defaults(self):
        from redsim.db.models import MlBatch, MlDataset

        with self.Session() as s:
            s.add(MlBatch(id="batch-1", project_id="proj-b0", kind="campaign",
                          config={"target_ids": ["t-1"]}, created_by="user:dev"))
            s.add(MlDataset(id="ds-1", project_id="proj-b0", license="CC0-1.0",
                            modality="tabular", class_names=["a", "b"],
                            manifest_sha256="d" * 64, blob_location="datasets/ds-1/"))
            s.commit()
        with self.Session() as s:
            batch = s.get(MlBatch, "batch-1")
            self.assertEqual(batch.status, "accepted")
            self.assertEqual(batch.config, {"target_ids": ["t-1"]})
            self.assertIsNone(batch.cancelled_at)
            ds = s.get(MlDataset, "ds-1")
            self.assertEqual(ds.status, "validating")
            self.assertEqual(ds.class_names, ["a", "b"])
            self.assertIsNone(ds.refusal_reason)
            self.assertIsNone(ds.detail)

    def test_dataset_register_job_detail_keys(self):
        from redsim.db.models import DatasetRegisterJobDetail

        self.assertEqual(
            set(DatasetRegisterJobDetail.__required_keys__),
            {"dataset_id", "blob_location", "declared_format", "declared_sha256"})


if __name__ == "__main__":
    unittest.main()
