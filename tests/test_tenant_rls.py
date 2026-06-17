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
  not superusers). The CI/dev Postgres connects as the ``aegis`` superuser, so to
  exercise the policies faithfully these tests ``SET ROLE`` to a dedicated
  NON-superuser, non-owner role (``aegis_rls_test``) before the tenant-scoped
  queries — which is exactly the production posture: the app must connect as the
  restricted ``aegis_app`` role (see migration 0004 + the deploy runbook) or RLS
  is a no-op. The GUC set by ``get_session`` survives ``SET ROLE`` within the
  same transaction.

NB: sqlalchemy / aegis.db imports are deferred into methods. The offline unit
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

AEGIS_DB = os.environ.get("AEGIS_DB_URL")

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


class TestTenantSeamSqlite(unittest.TestCase):
    """Non-Postgres path: the seam is a harmless no-op and the models carry
    org_id. Runs on the offline unit job (no DB required)."""

    def test_models_declare_org_id_on_scoped_tables(self):
        from aegis.db.models import Base
        for table in _SCOPED_TABLES:
            cols = Base.metadata.tables[table].columns
            self.assertIn("org_id", cols, f"{table} missing org_id")
            # Nullable on the ORM — the DB trigger backfills it.
            self.assertTrue(cols["org_id"].nullable, f"{table}.org_id not nullable")

    def test_set_current_tenants_normalizes_and_roundtrips(self):
        from aegis.db import session as sess_mod
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
        from aegis.db import session as sess_mod
        from aegis.db.models import Base, Organization, Project

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


@unittest.skipUnless(AEGIS_DB, "needs Postgres (AEGIS_DB_URL)")
class TestTenantRLS(unittest.TestCase):
    def setUp(self):
        from aegis.db import session as sess_mod
        from aegis.db.models import Finding, Organization, Project, Run

        sess_mod.init_engine(AEGIS_DB)
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
    # it). Mirrors the production posture where the app runs as ``aegis_app``.
    _RLS_ROLE = "aegis_rls_test"

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


if __name__ == "__main__":
    unittest.main()
