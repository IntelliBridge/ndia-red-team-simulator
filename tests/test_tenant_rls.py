"""Postgres Row-Level Security for cross-ORG tenant isolation (migration 0005).

Two test surfaces:

* ``TestTenantSeamSqlite`` — runs everywhere (offline unit path included). It
  pins the sqlite no-op behaviour: ``set_current_tenants`` / ``get_session``
  must not error or filter when the engine isn't Postgres, and the ORM must
  carry the new ``org_id`` column on every scoped table. This keeps coverage of
  the session seam + models on the DB-less CI job.
* ``TestTenantRLS`` — Postgres-gated (mirrors ``tests/test_audit_append_only``
  and ``tests/test_state_pg_coverage``): the policies only exist once
  ``alembic upgrade head`` has run against a real Postgres, so these run in the
  CI coverage / api-integration jobs and skip on the offline path.

  IMPORTANT — RLS and superusers: a Postgres **superuser always bypasses RLS**,
  even with ``FORCE ROW LEVEL SECURITY`` (FORCE only subjects the table *owner*,
  not superusers). The CI/dev Postgres connects as the ``redsim`` superuser, so to
  exercise the policies faithfully these tests ``SET ROLE`` to a dedicated
  NON-superuser, non-owner role (``redsim_rls_test``) before the tenant-scoped
  queries — which is exactly the production posture: the app must connect as the
  restricted ``redsim_app`` role (see migration 0004 + the deploy runbook) or RLS
  is a no-op. The GUC set by ``get_session`` survives ``SET ROLE`` within the
  same transaction.

``TestTenantRLS`` also covers the tables that joined the RLS set later:
``ml_campaigns`` (0010_ml_vertical) and the Phase B tables of
``0011_phase_b_platform`` (``report_snapshots``, ``idempotency_keys``,
``ml_batches``, ``ml_datasets``), each through the same four checks: the
insert trigger backfills ``org_id``, ``FORCE ROW LEVEL SECURITY`` is set, a
session scoped to another org sees nothing, the update guard rejects drift.
``TestTenantReconcileSqlite`` scans all thirteen tables (the reconciler's
``_SCOPED_TABLES`` covers the 0006, 0010 and 0011 sets), with the
migration-owned ``ml_campaigns`` mirrored by hand as the worker harnesses do.

NB: sqlalchemy / redsim.db imports are deferred into methods. The offline unit
job installs without the api/worker extras (no sqlalchemy), and a module-level
import would fail at *collection* time — the class-level skipUnless only guards
execution. Mirror tests/test_state_pg_coverage.py.
"""

from __future__ import annotations

import os
import unittest
from contextlib import contextmanager
from uuid import uuid4

import pytest

pytest.importorskip("sqlalchemy")

REDSIM_DB = os.environ.get("REDSIM_DB_URL")

# Tables that gained a denormalized org_id + RLS in 0005/0006 (ORM models).
_P0_SCOPED_TABLES = (
    "targets", "runs", "jobs", "findings", "llm_usage", "artifacts",
    "remediation_attempts", "application_logs",
)

# Tables that gained the same denormalized org_id + RLS parity in 0011 (ORM
# models); ``ml_campaigns`` (0010) is migration-owned and has no ORM model.
_PHASE_B_SCOPED_TABLES = (
    "report_snapshots", "idempotency_keys", "ml_batches", "ml_datasets",
)
_ML_CAMPAIGNS_TABLE = "ml_campaigns"

# Everything the tenant reconciler (``redsim.workers.tasks.tenant_reconcile``)
# scans: the 0006 eight, ml_campaigns and the four Phase B tables.
_SCOPED_TABLES = (*_P0_SCOPED_TABLES, _ML_CAMPAIGNS_TABLE, *_PHASE_B_SCOPED_TABLES)


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(type_, compiler, **kw):
        return "TEXT"


def _make_sqlite_session():
    """Return a (Session, engine) pair backed by an in-memory sqlite engine.

    Mirrors ``tests/test_reaper.py``'s harness so the reconciliation logic can
    be exercised offline (no Postgres). The 0009 UPDATE trigger is Postgres-only
    and absent here, which is exactly what lets us *seed* a drifted ``org_id``
    row to assert the detective scan catches it.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    _patch_jsonb_for_sqlite()
    from redsim.db.models import Base

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
        _ml_campaigns_mirror(engine)
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    return sessionmaker(engine, expire_on_commit=False, future=True), engine


def _ml_campaigns_mirror(engine):
    """``ml_campaigns`` as migration 0010 (plus 0011's ``batch_id``) shapes it: migration-owned, no ORM model,
    so the sqlite harness creates it by hand (mirrors tests/ml/test_tasks.py) under its own MetaData."""
    from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text

    Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True),
        Column("project_id", String, nullable=False),
        Column("org_id", String),
        Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False),
        Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False),
        Column("settings_hash", String),
        Column("provenance", JSON),
        Column("score", JSON),
        Column("limitations", JSON, nullable=False),
        Column("baseline_run_id", String),
        Column("parent_run_id", String),
        Column("batch_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    ).create(engine)


class TestTenantSeamSqlite(unittest.TestCase):
    """Non-Postgres path: the seam is a harmless no-op and the models carry
    org_id. Runs on the offline unit job (no DB required)."""

    def test_models_declare_org_id_on_scoped_tables(self):
        from redsim.db.models import Base
        for table in _P0_SCOPED_TABLES:
            cols = Base.metadata.tables[table].columns
            self.assertIn("org_id", cols, f"{table} missing org_id")
            # Nullable on the ORM — the DB trigger backfills it.
            self.assertTrue(cols["org_id"].nullable, f"{table}.org_id not nullable")

    def test_phase_b_models_declare_org_id_and_project_id(self):
        # 0011_phase_b_platform: every new table carries the tenant pair. The
        # ORM org_id is nullable (trigger-backfilled); project_id is NOT NULL
        # so the BEFORE UPDATE drift guard always has an owning org to check.
        from redsim.db.models import Base
        for table in _PHASE_B_SCOPED_TABLES:
            cols = Base.metadata.tables[table].columns
            self.assertIn("org_id", cols, f"{table} missing org_id")
            self.assertTrue(cols["org_id"].nullable, f"{table}.org_id not nullable")
            self.assertIn("project_id", cols, f"{table} missing project_id")
            self.assertFalse(cols["project_id"].nullable, f"{table}.project_id nullable")

    def test_set_current_tenants_normalizes_and_roundtrips(self):
        from redsim.db import session as sess_mod
        # None and empty both mean system; a real list is preserved.
        tok = sess_mod.set_current_tenants(None)
        self.assertIsNone(sess_mod.current_tenants())
        sess_mod.reset_current_tenants(tok)

        tok = sess_mod.set_current_tenants([])
        self.assertIsNone(sess_mod.current_tenants())
        sess_mod.reset_current_tenants(tok)

        tok = sess_mod.set_current_tenants(["org-a", "org-b"])
        self.assertEqual(sess_mod.current_tenants(), ["org-a", "org-b"])
        sess_mod.reset_current_tenants(tok)
        # Reset restores the prior (default) value.
        self.assertIsNone(sess_mod.current_tenants())

    def test_get_session_is_noop_on_sqlite_even_with_tenants_set(self):
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        _patch_jsonb_for_sqlite()
        from redsim.db import session as sess_mod
        from redsim.db.models import Base, Organization, Project

        engine = create_engine(
            "sqlite://", future=True,
            connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
            raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")

        # Point the module-global session factory at the sqlite engine.
        sess_mod._ENGINE = engine
        sess_mod.Session = sessionmaker(engine, expire_on_commit=False, future=True)
        self.addCleanup(setattr, sess_mod, "_ENGINE", None)
        self.addCleanup(setattr, sess_mod, "Session", None)

        with sess_mod.get_session() as s:
            s.add(Organization(id="org-x", name="X", slug="org-x"))
            s.flush()
            s.add(Project(id="proj-x", org_id="org-x", name="P", slug="proj-x"))

        # Even with a tenant set, get_session must not attempt set_config (which
        # would raise on sqlite) and must not filter — the row is still visible.
        tok = sess_mod.set_current_tenants(["org-other"])
        self.addCleanup(sess_mod.reset_current_tenants, tok)
        with sess_mod.get_session() as s:
            rows = s.execute(select(Project.id)).scalars().all()
        self.assertIn("proj-x", rows)


class TestTenantReconcileSqlite(unittest.TestCase):
    """Offline coverage of the ``verify_tenant_integrity`` reconciliation logic
    (``redsim.workers.tasks.tenant_reconcile``). Runs on the DB-less unit job:
    the scan is plain SQL (``IS DISTINCT FROM`` works on sqlite), and the lack
    of the 0009 trigger lets us seed a drifted row to detect."""

    def setUp(self):
        from sqlalchemy import text

        from redsim.db.models import (
            Finding,
            IdempotencyKey,
            MlBatch,
            MlDataset,
            Organization,
            Project,
            ReportSnapshot,
            Run,
        )

        self.Session, self.engine = _make_sqlite_session()
        self.Finding = Finding
        self.Run = Run
        self.MlBatch = MlBatch
        self.ReportSnapshot = ReportSnapshot
        self.IdempotencyKey = IdempotencyKey
        # Two orgs, two projects, one run+finding each (org-matched, clean), plus one clean row in every table
        # that joined the scan later: ml_campaigns (0010) and the four Phase B tables (0011).
        with self.Session() as s:
            for org, proj in (("org-a", "proj-a"), ("org-b", "proj-b")):
                s.add(Organization(id=org, name=org, slug=org))
                s.add(Project(id=proj, org_id=org, name=proj, slug=proj))
            s.flush()
            s.add(Run(id="run-a", project_id="proj-a", org_id="org-a",
                      created_by="cli:test"))
            s.add(Run(id="run-b", project_id="proj-b", org_id="org-b",
                      created_by="cli:test"))
            s.add(Finding(
                id="find-a", scanner_finding_id="s-a", run_id="run-a",
                project_id="proj-a", org_id="org-a",
                schema_blob={"id": "s-a"}, severity="high"))
            s.flush()
            s.add(ReportSnapshot(id="snap-a", run_id="run-a", project_id="proj-a", org_id="org-a",
                                 artifact_ids=["art-1"], record_sha256="0" * 64))
            s.add(MlBatch(id="batch-a", project_id="proj-a", org_id="org-a", kind="campaign", config={}))
            s.add(MlDataset(id="ds-a", project_id="proj-a", org_id="org-a", status="available"))
            # The same idempotency key in both projects: the primary key is (project_id, key).
            for proj, org in (("proj-a", "org-a"), ("proj-b", "org-b")):
                s.add(IdempotencyKey(project_id=proj, key="k1", org_id=org, route="POST /v1/x",
                                     request_sha256="1" * 64, response_status=202))
            s.execute(text(
                "INSERT INTO ml_campaigns (run_id, project_id, org_id, target_id, kind, modality, config, limitations) "
                "VALUES ('run-a', 'proj-a', 'org-a', 'tgt-a', 'campaign', 'image', '{}', '[]')"))
            s.commit()

    def test_clean_db_reports_no_drift(self):
        from redsim.workers.tasks.tenant_reconcile import (
            _SCOPED_TABLES as RECONCILED,
        )
        from redsim.workers.tasks.tenant_reconcile import (
            row_id_column,
            verify_tenant_integrity_in_session,
        )
        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s)
        self.assertTrue(report.ok)
        self.assertEqual(report.total, 0)
        # Every scoped table was scanned (count 0 each): the 0006 eight, ml_campaigns and the four 0011 tables.
        self.assertEqual(set(report.per_table), set(_SCOPED_TABLES))
        self.assertEqual(set(RECONCILED), set(_SCOPED_TABLES))
        self.assertEqual(len(report.per_table), 13)
        self.assertTrue(all(v == 0 for v in report.per_table.values()))
        # The identifying column follows each table's key.
        self.assertEqual(row_id_column("ml_campaigns"), "run_id")
        self.assertEqual(row_id_column("idempotency_keys"), "key")
        for table in (*_P0_SCOPED_TABLES, "report_snapshots", "ml_batches", "ml_datasets"):
            self.assertEqual(row_id_column(table), "id", table)

    def test_reconciliation_finds_drift_in_ml_campaigns_and_the_phase_b_tables(self):
        from sqlalchemy import text

        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        # No trigger on sqlite: seed one drifted row per later-joined table (out-of-band writes).
        with self.Session() as s:
            s.get(self.MlBatch, "batch-a").org_id = "org-b"
            s.get(self.ReportSnapshot, "snap-a").org_id = None
            s.execute(text("UPDATE ml_campaigns SET org_id = 'org-b' WHERE run_id = 'run-a'"))
            s.commit()

        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s)
        self.assertFalse(report.ok)
        self.assertEqual(report.total, 3)
        self.assertEqual(report.per_table["ml_batches"], 1)
        self.assertEqual(report.per_table["report_snapshots"], 1)
        self.assertEqual(report.per_table["ml_campaigns"], 1)
        self.assertEqual(report.per_table["runs"], 0)
        by_table = {d.table: d for d in report.drifts}
        self.assertEqual((by_table["ml_batches"].row_id, by_table["ml_batches"].stored_org_id,
                          by_table["ml_batches"].expected_org_id), ("batch-a", "org-b", "org-a"))
        self.assertEqual((by_table["report_snapshots"].row_id, by_table["report_snapshots"].stored_org_id),
                         ("snap-a", None))
        # ml_campaigns is keyed by run_id: that is what the report names.
        self.assertEqual((by_table["ml_campaigns"].row_id, by_table["ml_campaigns"].project_id), ("run-a", "proj-a"))

        # Repair rewrites exactly those rows from their projects; a second scan is clean.
        with self.Session() as s:
            repaired = verify_tenant_integrity_in_session(s, repair=True)
            s.commit()
        self.assertEqual(repaired.total, 3)
        with self.Session() as s:
            self.assertEqual(s.get(self.MlBatch, "batch-a").org_id, "org-a")
            self.assertEqual(s.get(self.ReportSnapshot, "snap-a").org_id, "org-a")
            self.assertEqual(s.execute(text("SELECT org_id FROM ml_campaigns WHERE run_id = 'run-a'")).scalar_one(),
                             "org-a")
            self.assertTrue(verify_tenant_integrity_in_session(s).ok)

    def test_repair_of_idempotency_keys_is_scoped_by_project_and_key(self):
        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        # proj-b's "k1" drifts to org-a; proj-a's "k1" (same key, other project) is clean and must stay untouched.
        with self.Session() as s:
            s.get(self.IdempotencyKey, ("proj-b", "k1")).org_id = "org-a"
            s.commit()
        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s)
        self.assertEqual(report.total, 1)
        drift = report.drifts[0]
        self.assertEqual((drift.table, drift.row_id, drift.project_id, drift.stored_org_id, drift.expected_org_id),
                         ("idempotency_keys", "k1", "proj-b", "org-a", "org-b"))
        with self.Session() as s:
            verify_tenant_integrity_in_session(s, repair=True)
            s.commit()
        with self.Session() as s:
            self.assertEqual(s.get(self.IdempotencyKey, ("proj-b", "k1")).org_id, "org-b")
            self.assertEqual(s.get(self.IdempotencyKey, ("proj-a", "k1")).org_id, "org-a")
            self.assertTrue(verify_tenant_integrity_in_session(s).ok)

    def test_reconciliation_finds_seeded_mismatch(self):
        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        # Drive run-a's org_id out of sync with its project (proj-a -> org-a).
        # No 0009 trigger on sqlite, so this mismatch persists — exactly the
        # out-of-band drift the reconciler exists to catch.
        with self.Session() as s:
            s.get(self.Run, "run-a").org_id = "org-b"
            s.commit()

        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s)
        self.assertFalse(report.ok)
        self.assertEqual(report.total, 1)
        self.assertEqual(report.per_table["runs"], 1)
        drift = report.drifts[0]
        self.assertEqual(drift.table, "runs")
        self.assertEqual(drift.row_id, "run-a")
        self.assertEqual(drift.stored_org_id, "org-b")
        self.assertEqual(drift.expected_org_id, "org-a")

    def test_repair_backfills_org_id_from_project(self):
        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        with self.Session() as s:
            s.get(self.Run, "run-a").org_id = "org-b"  # drift
            s.commit()

        # The function mutates but does not commit (its production caller,
        # ``verify_tenant_integrity``, runs inside ``get_session`` which
        # commits) — so the test commits the repair session itself.
        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s, repair=True)
            s.commit()
        self.assertEqual(report.total, 1)  # the report still records the drift

        # After repair the stored org_id matches the project's org, and a
        # follow-up scan is clean.
        with self.Session() as s:
            self.assertEqual(s.get(self.Run, "run-a").org_id, "org-a")
            self.assertTrue(verify_tenant_integrity_in_session(s).ok)

    def test_to_dict_is_serializable_and_secret_free(self):
        import json

        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        with self.Session() as s:
            s.get(self.Run, "run-a").org_id = "org-b"
            s.commit()
        with self.Session() as s:
            payload = verify_tenant_integrity_in_session(s).to_dict()
        # Round-trips through JSON (no datetimes / ORM objects leak in).
        json.dumps(payload)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["drifts"][0]["table"], "runs")


@unittest.skipUnless(REDSIM_DB, "needs Postgres (REDSIM_DB_URL)")
class TestTenantRLS(unittest.TestCase):
    def setUp(self):
        from redsim.db import session as sess_mod
        from redsim.db.models import Finding, Organization, Project, Run

        sess_mod.init_engine(REDSIM_DB)
        self.sess_mod = sess_mod
        self.Finding = Finding
        self.Run = Run

        self._ensure_rls_role()

        suffix = uuid4().hex[:8]
        self.org_a = "org-a-" + suffix
        self.org_b = "org-b-" + suffix
        self.proj_a = "proj-a-" + suffix
        self.proj_b = "proj-b-" + suffix
        self.run_a = "run-a-" + suffix
        self.run_b = "run-b-" + suffix
        self.find_a = "find-a-" + suffix
        self.find_b = "find-b-" + suffix

        # Seed as system (no tenant set) so both orgs land regardless of RLS.
        with sess_mod.get_session() as s:
            for org, proj in ((self.org_a, self.proj_a), (self.org_b, self.proj_b)):
                s.add(Organization(id=org, name=org, slug=org))
                s.flush()
                s.add(Project(id=proj, org_id=org, name=proj, slug=proj))
                s.flush()
            # Insert runs/findings WITHOUT org_id — the trigger must backfill it.
            s.add(Run(id=self.run_a, project_id=self.proj_a, created_by="cli:test"))
            s.add(Run(id=self.run_b, project_id=self.proj_b, created_by="cli:test"))
            s.flush()
            s.add(Finding(
                id=self.find_a, scanner_finding_id="s-a", run_id=self.run_a,
                project_id=self.proj_a, schema_blob={"id": "s-a"},
                severity="high"))
            s.add(Finding(
                id=self.find_b, scanner_finding_id="s-b", run_id=self.run_b,
                project_id=self.proj_b, schema_blob={"id": "s-b"},
                severity="high"))

    # A non-superuser, non-owner role so RLS actually binds (superusers bypass
    # it). Mirrors the production posture where the app runs as ``redsim_app``.
    _RLS_ROLE = "redsim_rls_test"

    def _ensure_rls_role(self):
        from sqlalchemy import text
        with self.sess_mod.get_session() as s:  # system scope; runs as owner
            s.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles "
                f"WHERE rolname = '{self._RLS_ROLE}') THEN "
                f"CREATE ROLE {self._RLS_ROLE} NOLOGIN; END IF; END $$;"))
            s.execute(text(f"GRANT USAGE ON SCHEMA public TO {self._RLS_ROLE}"))
            s.execute(text(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                f"IN SCHEMA public TO {self._RLS_ROLE}"))
            s.execute(text(
                "GRANT USAGE, SELECT ON ALL SEQUENCES "
                f"IN SCHEMA public TO {self._RLS_ROLE}"))

    @contextmanager
    def _scoped_session(self, org_ids):
        """A session scoped to ``org_ids`` AND running as the non-superuser
        role, so the RLS policies are actually enforced."""
        from sqlalchemy import text
        tok = self.sess_mod.set_current_tenants(org_ids)
        try:
            with self.sess_mod.get_session() as s:
                # get_session has already set app.current_tenants for this tx;
                # drop to the restricted role so RLS binds.
                s.execute(text(f"SET ROLE {self._RLS_ROLE}"))
                yield s
        finally:
            self.sess_mod.reset_current_tenants(tok)

    def test_trigger_backfills_org_id_from_project(self):
        # Inserted with org_id NULL above; the BEFORE INSERT trigger sets it.
        with self.sess_mod.get_session() as s:  # system scope
            fa = s.get(self.Finding, self.find_a)
            fb = s.get(self.Finding, self.find_b)
            ra = s.get(self.Run, self.run_a)
            self.assertEqual(fa.org_id, self.org_a)
            self.assertEqual(fb.org_id, self.org_b)
            self.assertEqual(ra.org_id, self.org_a)

    def test_tenant_scope_hides_other_orgs_rows(self):
        from sqlalchemy import select

        # Scope to org_b (as the non-superuser role): only org_b findings/runs
        # are visible — the RLS policy filters org_a out at the database.
        with self._scoped_session([self.org_b]) as s:
            find_ids = set(s.execute(
                select(self.Finding.id).where(
                    self.Finding.id.in_([self.find_a, self.find_b]))
            ).scalars().all())
            run_ids = set(s.execute(
                select(self.Run.id).where(
                    self.Run.id.in_([self.run_a, self.run_b]))
            ).scalars().all())
        self.assertEqual(find_ids, {self.find_b})
        self.assertEqual(run_ids, {self.run_b})

    def test_system_scope_sees_all_orgs(self):
        from sqlalchemy import select

        tok = self.sess_mod.set_current_tenants(None)
        try:
            with self.sess_mod.get_session() as s:
                find_ids = set(s.execute(
                    select(self.Finding.id).where(
                        self.Finding.id.in_([self.find_a, self.find_b]))
                ).scalars().all())
        finally:
            self.sess_mod.reset_current_tenants(tok)
        self.assertEqual(find_ids, {self.find_a, self.find_b})

    def test_cross_tenant_write_rejected_by_with_check(self):
        from sqlalchemy.exc import DBAPIError

        # Scoped to org_b (non-superuser role), try to insert a finding into
        # project_a (org_a). The trigger sets org_id = org_a, which violates the
        # WITH CHECK predicate for the org_b scope -> the write is rejected.
        with self.assertRaises(DBAPIError), self._scoped_session([self.org_b]) as s:
            s.add(self.Finding(
                id="x-" + uuid4().hex[:8], scanner_finding_id="x",
                run_id=self.run_a, project_id=self.proj_a,
                schema_blob={"id": "x"}, severity="low"))
            s.flush()

    def test_insert_within_scope_is_allowed(self):
        # Same-org write under the matching scope succeeds (positive control,
        # as the non-superuser role so the WITH CHECK predicate is enforced).
        new_id = "ok-" + uuid4().hex[:8]
        with self._scoped_session([self.org_b]) as s:
            s.add(self.Finding(
                id=new_id, scanner_finding_id="ok", run_id=self.run_b,
                project_id=self.proj_b, schema_blob={"id": "ok"},
                severity="low"))
        with self.sess_mod.get_session() as s:  # system: confirm it persisted
            row = s.get(self.Finding, new_id)
            self.assertIsNotNone(row)
            self.assertEqual(row.org_id, self.org_b)

    def test_update_org_id_drift_rejected_by_trigger(self):
        # System scope (no tenant GUC) bypasses the RLS WITH CHECK, but the 0009
        # BEFORE UPDATE trigger still fires: rewriting find_a's org_id to org_b
        # (mismatched against proj_a -> org_a) must raise.
        from sqlalchemy.exc import DBAPIError

        with self.assertRaises(DBAPIError), self.sess_mod.get_session() as s:
            fa = s.get(self.Finding, self.find_a)
            fa.org_id = self.org_b
            s.flush()

        # The rejected UPDATE left the row untouched.
        with self.sess_mod.get_session() as s:
            self.assertEqual(s.get(self.Finding, self.find_a).org_id, self.org_a)

    def test_update_to_matching_org_id_is_allowed(self):
        # Re-stamping org_id with the *correct* value (its existing org) passes
        # the trigger — positive control proving it only rejects mismatches.
        with self.sess_mod.get_session() as s:
            fa = s.get(self.Finding, self.find_a)
            fa.org_id = self.org_a
            s.flush()
        with self.sess_mod.get_session() as s:
            self.assertEqual(s.get(self.Finding, self.find_a).org_id, self.org_a)

    def test_ml_campaigns_has_rls_parity_and_hides_other_orgs_rows(self):
        """0010_ml_vertical: ``ml_campaigns`` joins the RLS-scoped tables.

        Insert without ``org_id`` (the trigger backfills it), then a session
        scoped to org B sees nothing while org A sees its row. Raw SQL because
        the ORM model for the table lands with its service in a later slice.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError

        from redsim.db.models import Target

        target_id = "tgt-" + self.run_a
        with self.sess_mod.get_session() as s:
            s.add(Target(id=target_id, project_id=self.proj_a, kind="ml_model_artifact",
                         value="bundled:tiny"))
            s.flush()
            s.execute(text(
                "INSERT INTO ml_campaigns (run_id, project_id, target_id, kind, modality, config) "
                "VALUES (:run_id, :project_id, :target_id, 'attack', 'image', '{}'::jsonb)"),
                {"run_id": self.run_a, "project_id": self.proj_a, "target_id": target_id})
        with self.sess_mod.get_session() as s:
            org = s.execute(text("SELECT org_id FROM ml_campaigns WHERE run_id = :r"),
                            {"r": self.run_a}).scalar_one()
            self.assertEqual(org, self.org_a)
            forced = s.execute(text(
                "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'ml_campaigns'")).scalar_one()
            self.assertTrue(forced)
        with self._scoped_session([self.org_b]) as s:
            rows = s.execute(text("SELECT run_id FROM ml_campaigns WHERE run_id = :r"),
                             {"r": self.run_a}).all()
            self.assertEqual(rows, [])
        with self._scoped_session([self.org_a]) as s:
            rows = s.execute(text("SELECT run_id FROM ml_campaigns WHERE run_id = :r"),
                             {"r": self.run_a}).all()
            self.assertEqual([r[0] for r in rows], [self.run_a])
        # The BEFORE UPDATE guard rejects org_id drift, as on the other tables.
        with self.assertRaises(DBAPIError), self.sess_mod.get_session() as s:
            s.execute(text("UPDATE ml_campaigns SET org_id = :o WHERE run_id = :r"),
                      {"o": self.org_b, "r": self.run_a})

    def _assert_phase_b_rls_parity(self, model, make_row, pk):
        """The four 0010 checks for a Phase B table, through its ORM model.

        ``make_row(project_id)`` builds an instance WITHOUT ``org_id``; ``pk``
        is the identity ``Session.get`` takes. Insert into project A as the
        system, then: the trigger set ``org_id``; the table is FORCE RLS; a
        session scoped to org B sees nothing while org A sees the row; an
        UPDATE that drifts ``org_id`` is rejected by the 0009-style guard.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError

        table = model.__tablename__
        with self.sess_mod.get_session() as s:  # system scope
            s.add(make_row(self.proj_a))
        with self.sess_mod.get_session() as s:
            row = s.get(model, pk)
            self.assertIsNotNone(row, f"{table} row not persisted")
            self.assertEqual(row.org_id, self.org_a, f"{table}.org_id not backfilled")
            enabled, forced = s.execute(text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = :t"), {"t": table}).one()
            self.assertTrue(enabled and forced, f"{table} is not FORCE RLS")
            policies = {r[0] for r in s.execute(text(
                "SELECT policyname FROM pg_policies WHERE tablename = :t"), {"t": table})}
            self.assertEqual(policies, {"redsim_tenant_isolation"})
        with self._scoped_session([self.org_b]) as s:
            self.assertIsNone(s.get(model, pk), f"{table}: org B can read org A's row")
        with self._scoped_session([self.org_a]) as s:
            self.assertIsNotNone(s.get(model, pk), f"{table}: org A cannot read its own row")
        with self.assertRaises(DBAPIError), self.sess_mod.get_session() as s:
            row = s.get(model, pk)
            row.org_id = self.org_b
            s.flush()
        with self.sess_mod.get_session() as s:
            self.assertEqual(s.get(model, pk).org_id, self.org_a)

    def test_report_snapshots_has_rls_parity_and_hides_other_orgs_rows(self):
        from redsim.db.models import ReportSnapshot

        snap_id = "snap-" + self.run_a
        self._assert_phase_b_rls_parity(
            ReportSnapshot,
            lambda project_id: ReportSnapshot(
                id=snap_id, run_id=self.run_a, project_id=project_id,
                artifact_ids=["art-1"], record_sha256="0" * 64),
            snap_id)

    def test_idempotency_keys_has_rls_parity_and_hides_other_orgs_rows(self):
        from redsim.db.models import IdempotencyKey

        key = "idem-" + self.run_a
        self._assert_phase_b_rls_parity(
            IdempotencyKey,
            lambda project_id: IdempotencyKey(
                project_id=project_id, key=key, route="POST /v1/models/{id}/attacks",
                request_sha256="1" * 64, response_status=202, response_body={"run_id": self.run_a}),
            (self.proj_a, key))

    def test_ml_batches_has_rls_parity_and_hides_other_orgs_rows(self):
        from redsim.db.models import MlBatch

        batch_id = "batch-" + self.run_a
        self._assert_phase_b_rls_parity(
            MlBatch,
            lambda project_id: MlBatch(
                id=batch_id, project_id=project_id, kind="campaign",
                config={"target_ids": ["t-1", "t-2"]}, created_by="cli:test"),
            batch_id)

    def test_ml_datasets_cross_org_read_returns_nothing(self):
        from redsim.db.models import MlDataset

        dataset_id = "ds-" + self.run_a
        self._assert_phase_b_rls_parity(
            MlDataset,
            lambda project_id: MlDataset(
                id=dataset_id, project_id=project_id, license="CC-BY-4.0",
                modality="tabular", class_names=["benign", "malicious"],
                manifest_sha256="2" * 64, created_by="cli:test"),
            dataset_id)

    def test_update_project_less_log_row_allowed(self):
        # application_logs.project_id is nullable (system-scoped logs). The 0009
        # BEFORE UPDATE trigger must NOT reject an UPDATE on such a project-less
        # row: with no owning project there is no org to enforce against
        # (expected_org IS NULL). Regression for the original over-broad guard,
        # which rejected ANY update to a project-less row carrying a non-NULL
        # org_id (expected_org NULL -> NEW.org_id IS DISTINCT FROM NULL -> RAISE).
        from sqlalchemy import text

        with self.sess_mod.get_session() as s:  # system scope
            # A real org (org_id FKs to organizations) but NO project — a
            # system-scoped log attributed to an org. Any UPDATE fires the 0009
            # trigger, which reads the row's non-NULL org_id against expected_org
            # (NULL, since project_id is NULL). The old guard raised here; the
            # fix leaves the write alone.
            s.execute(text(
                "INSERT INTO application_logs "
                "(ts, severity, service, message, project_id, org_id, attrs, "
                " created_at) VALUES (now(), 'info', 'sys', 'pl-log', NULL, "
                ":org, '{}'::jsonb, now())"), {"org": self.org_a})
            s.execute(text(
                "UPDATE application_logs SET message = 'pl-log-upd' "
                "WHERE message = 'pl-log' AND project_id IS NULL"))
            msg = s.execute(text(
                "SELECT message FROM application_logs "
                "WHERE project_id IS NULL AND org_id = :org"), {"org": self.org_a}
            ).scalar_one()
            self.assertEqual(msg, "pl-log-upd")
            s.execute(text(
                "DELETE FROM application_logs WHERE message = 'pl-log-upd'"))

    def test_reconciliation_finds_seeded_mismatch(self):
        # Seed real drift on Postgres by disabling the 0009 trigger for one
        # UPDATE (simulating a row written before the trigger / out-of-band),
        # then assert the reconciler reports exactly that row.
        from sqlalchemy import text

        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )

        with self.sess_mod.get_session() as s:
            s.execute(text("ALTER TABLE findings DISABLE TRIGGER "
                           "trg_check_org_id_findings"))
            try:
                s.execute(
                    text("UPDATE findings SET org_id = :o WHERE id = :i"),
                    {"o": self.org_b, "i": self.find_a},
                )
            finally:
                s.execute(text("ALTER TABLE findings ENABLE TRIGGER "
                               "trg_check_org_id_findings"))

        try:
            with self.sess_mod.get_session() as s:
                report = verify_tenant_integrity_in_session(s)
            self.assertFalse(report.ok)
            drift_ids = {(d.table, d.row_id) for d in report.drifts}
            self.assertIn(("findings", self.find_a), drift_ids)
            seeded = next(d for d in report.drifts
                          if d.row_id == self.find_a)
            self.assertEqual(seeded.stored_org_id, self.org_b)
            self.assertEqual(seeded.expected_org_id, self.org_a)
        finally:
            # Repair so the seeded drift doesn't leak into sibling tests / runs.
            with self.sess_mod.get_session() as s:
                s.execute(
                    text("UPDATE findings SET org_id = :o WHERE id = :i"),
                    {"o": self.org_a, "i": self.find_a},
                )


if __name__ == "__main__":
    unittest.main()
