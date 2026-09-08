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

# Tables that gained a denormalized org_id + RLS in 0005.
_SCOPED_TABLES = (
    "targets", "runs", "jobs", "findings", "llm_usage", "artifacts",
    "remediation_attempts", "application_logs",
)


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(type_, compiler, **kw):  # noqa: ARG001
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
    except Exception as exc:  # pragma: no cover - defensive
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    return sessionmaker(engine, expire_on_commit=False, future=True), engine


class TestTenantSeamSqlite(unittest.TestCase):
    """Non-Postgres path: the seam is a harmless no-op and the models carry
    org_id. Runs on the offline unit job (no DB required)."""

    def test_models_declare_org_id_on_scoped_tables(self):
        from redsim.db.models import Base
        for table in _SCOPED_TABLES:
            cols = Base.metadata.tables[table].columns
            self.assertIn("org_id", cols, f"{table} missing org_id")
            # Nullable on the ORM — the DB trigger backfills it.
            self.assertTrue(cols["org_id"].nullable, f"{table}.org_id not nullable")

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
        except Exception as exc:  # pragma: no cover - defensive
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
        from redsim.db.models import Finding, Organization, Project, Run

        self.Session, self.engine = _make_sqlite_session()
        self.Finding = Finding
        self.Run = Run
        # Two orgs, two projects, one run+finding each (org-matched, clean).
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
            s.commit()

    def test_clean_db_reports_no_drift(self):
        from redsim.workers.tasks.tenant_reconcile import (
            verify_tenant_integrity_in_session,
        )
        with self.Session() as s:
            report = verify_tenant_integrity_in_session(s)
        self.assertTrue(report.ok)
        self.assertEqual(report.total, 0)
        # Every scoped table was scanned (count 0 each).
        self.assertEqual(set(report.per_table), set(_SCOPED_TABLES))
        self.assertTrue(all(v == 0 for v in report.per_table.values()))

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
        with self.assertRaises(DBAPIError):
            with self._scoped_session([self.org_b]) as s:
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

        with self.assertRaises(DBAPIError):
            with self.sess_mod.get_session() as s:
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
