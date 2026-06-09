"""DB-side append-only enforcement on ``audit_events`` (migration 0004).

Postgres-gated (mirrors ``tests/test_state_pg_coverage.py``): the
row-immutability trigger only exists once ``alembic upgrade head`` has run
against a real Postgres, so these run in the CI ``coverage`` /
``api-integration`` jobs and skip on the offline unit path.

The trigger fires for everyone — including the CI superuser ``aegis`` — so
this exercises the *enforcement* without needing the deploy-time role split.
"""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

AEGIS_DB = os.environ.get("AEGIS_DB_URL")


@unittest.skipUnless(AEGIS_DB, "needs Postgres (AEGIS_DB_URL)")
class TestAuditAppendOnly(unittest.TestCase):
    def setUp(self):
        from aegis.audit.chain import PostgresAuditWriter
        from aegis.db import session as sess_mod
        from aegis.db.models import Organization, Project, Run

        sess_mod.init_engine(AEGIS_DB)
        self.sess_mod = sess_mod
        self.writer = PostgresAuditWriter(session_factory=sess_mod.get_session)

        # A unique run gives this test an isolated hash chain. The run row is
        # required because audit_events.run_id is an FK to runs.id. These rows
        # cannot be cleaned up afterward — the trigger blocks DELETE on
        # audit_events and the run FK pins them — so keep ids unique per run.
        suffix = uuid4().hex[:8]
        self.run_id = "audit-ao-" + suffix
        self.chain_id = f"run:{self.run_id}"
        org_id = "org-ao-" + suffix
        project_id = "proj-ao-" + suffix
        with sess_mod.get_session() as s:
            s.add(Organization(id=org_id, name="T", slug=org_id))
            s.flush()
            s.add(Project(id=project_id, org_id=org_id, name=project_id,
                          slug=project_id))
            s.flush()
            s.add(Run(id=self.run_id, project_id=project_id,
                      created_by="cli:test"))

    def _append(self, action: str):
        return self.writer.append(
            action=action, actor="cli:test", target=None,
            allowlist_check="n/a", override=False, success=True,
            detail={"k": "v"}, run_id=self.run_id,
        )

    def _raw(self, sql: str):
        """Run a raw statement in its own session; roll back afterward."""
        sess = self.sess_mod.Session()
        try:
            sess.execute(text(sql))
            sess.flush()
        finally:
            sess.rollback()
            sess.close()

    def test_update_delete_truncate_blocked_append_and_verify_ok(self):
        from aegis.audit.chain import verify_chain

        ev = self._append("scan.start")
        self.assertEqual(ev.seq, 1)

        # UPDATE is rejected by the trigger.
        with self.assertRaises(DBAPIError):
            self._raw(
                f"UPDATE audit_events SET this_hash = E'\\\\xdeadbeef' "
                f"WHERE chain_id = '{self.chain_id}'")

        # DELETE is rejected.
        with self.assertRaises(DBAPIError):
            self._raw(
                f"DELETE FROM audit_events WHERE chain_id = '{self.chain_id}'")

        # TRUNCATE is rejected (statement-level trigger).
        with self.assertRaises(DBAPIError):
            self._raw("TRUNCATE audit_events")

        # A second append still succeeds (INSERT + head UPDATE both work).
        ev2 = self._append("scan.execute.strix")
        self.assertEqual(ev2.seq, 2)

        # Cryptographic verification still passes — layers are intact.
        result = verify_chain(list(self.writer.read_chain(self.chain_id)))
        self.assertTrue(result.verified, result.reason)
        self.assertEqual(result.count, 2)


if __name__ == "__main__":
    unittest.main()
