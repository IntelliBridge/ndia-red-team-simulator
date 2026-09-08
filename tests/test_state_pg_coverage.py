"""Postgres-backed state + fs->pg migration coverage.

These exercise the real Postgres paths (``redsim.state.postgres``,
``redsim.state.factory``, ``redsim.migrate.fs_to_pg``) and so are guarded by
``REDSIM_DB_URL``: they run in the CI coverage job (which brings up Postgres)
and skip on the offline unit path, keeping ``pytest -q`` green with no DB.

Isolation: ``PostgresRunState`` tests use a raw Session that is never
committed, so close() rolls the transaction back. Migration tests must
commit (the code uses ``get_session()``), so they use unique run/project ids.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

# Postgres-backed (real ``redsim.state.postgres`` / migration paths, gated by
# REDSIM_DB_URL); excluded from the CI unit job's "not integration" filter.
pytestmark = pytest.mark.integration

REDSIM_DB = os.environ.get("REDSIM_DB_URL")


def _finding(scanner_id: str, *, severity: str = "high",
             status: str = "open", tool: str = "strix") -> dict:
    return {
        "id": scanner_id,
        "title": f"finding {scanner_id}",
        "severity": severity,
        "finding_type": "sast",
        "description": "synthetic",
        "source_tool": tool,
        "source_run_id": "run-x",
        "affected_component": "app/x.py",
        "confidence": "high",
        "status": status,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }


@unittest.skipUnless(REDSIM_DB, "needs Postgres (REDSIM_DB_URL)")
class TestPostgresRunState(unittest.TestCase):
    def setUp(self):
        from redsim.db import session as sess_mod
        sess_mod.init_engine(REDSIM_DB)
        self.sess = sess_mod.Session()
        self.addCleanup(self.sess.close)

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        from redsim.db.models import Organization, Project
        self.org_id = "org-" + uuid4().hex[:8]
        self.project_id = "proj-" + uuid4().hex[:8]
        self.sess.add(Organization(id=self.org_id, name="T", slug=self.org_id))
        self.sess.flush()
        self.sess.add(Project(id=self.project_id, org_id=self.org_id,
                              name=self.project_id, slug=self.project_id))
        self.sess.flush()

    def _state(self, run_id: str | None = None):
        from redsim.state import PostgresRunState
        return PostgresRunState(
            self.sess, run_id=run_id or ("run-" + uuid4().hex[:8]),
            project_id=self.project_id, output_dir=self.tmp,
            created_by="cli:test",
        )

    def test_init_creates_run_and_is_idempotent(self):
        from redsim.db.models import Run
        rid = "run-" + uuid4().hex[:8]
        self._state(rid)
        self.assertIsNotNone(self.sess.get(Run, rid))
        # Re-opening the same run_id must not insert a duplicate.
        self._state(rid)
        self.assertIsNotNone(self.sess.get(Run, rid))

    def test_path_properties(self):
        st = self._state()
        self.assertEqual(st.findings_path.name, "findings.json")
        self.assertEqual(st.artifacts_path.name, "artifacts")
        self.assertEqual(st.remediation_log_path.name, "remediation-log.json")
        self.assertEqual(st.report_path.name, "report.md")
        self.assertTrue(st.run_path.exists())

    def test_save_and_load_findings(self):
        st = self._state()
        st.save_findings([_finding("vuln-1"), _finding("vuln-2", severity="low")])
        loaded = st.load_findings()
        ids = {f["id"] for f in loaded}
        self.assertEqual(ids, {"vuln-1", "vuln-2"})

    def test_save_findings_updates_existing_row(self):
        from sqlalchemy import select

        from redsim.db.models import Finding
        st = self._state()
        st.save_findings([_finding("vuln-1", severity="low", status="open")])
        st.save_findings([_finding("vuln-1", severity="critical", status="fixed")])
        rows = self.sess.execute(
            select(Finding).where(Finding.scanner_finding_id == "vuln-1")
        ).scalars().all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].severity, "critical")
        self.assertEqual(rows[0].status, "fixed")

    def test_update_finding_status_by_scanner_id_and_uuid(self):
        from sqlalchemy import select

        from redsim.db.models import Finding
        st = self._state()
        st.save_findings([_finding("vuln-9")])
        row = self.sess.execute(
            select(Finding).where(Finding.scanner_finding_id == "vuln-9")
        ).scalar_one()

        # By the upstream scanner id (UUID lookup misses, falls back).
        st.update_finding_status("vuln-9", "triaged")
        self.sess.refresh(row)
        self.assertEqual(row.status, "triaged")
        self.assertEqual(row.schema_blob["status"], "triaged")

        # By the internal UUID.
        st.update_finding_status(row.id, "fixed")
        self.sess.refresh(row)
        self.assertEqual(row.status, "fixed")

        # Unknown id is a graceful no-op.
        st.update_finding_status("does-not-exist", "open")

    def test_save_artifact_writes_file(self):
        st = self._state()
        p = st.save_artifact("note.txt", "hello")
        self.assertTrue(Path(p).exists())
        self.assertEqual(Path(p).read_text(), "hello")
        pb = st.save_artifact("blob.bin", b"\x00\x01")
        self.assertEqual(Path(pb).read_bytes(), b"\x00\x01")

    def test_record_artifact_persists_blob_and_row(self):
        from sqlalchemy import select

        from redsim.db.models import Artifact
        st = self._state()
        ref = st.record_artifact("report", "abc", content_type="text/plain")
        self.assertEqual(ref.size_bytes, 3)
        self.assertTrue(Path(ref.location).exists())
        rows = self.sess.execute(
            select(Artifact).where(Artifact.run_id == st.run_id)
        ).scalars().all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "report")

    def test_record_artifact_is_idempotent_for_identical_content(self):
        # The (run_id, kind, sha256) UNIQUE constraint means re-recording the
        # same content must not raise; it returns the existing row's ref.
        from sqlalchemy import select

        from redsim.db.models import Artifact
        st = self._state()
        ref1 = st.record_artifact("report", "abc", content_type="text/plain")
        ref2 = st.record_artifact("report", "abc", content_type="text/plain")
        self.assertEqual(ref1.sha256, ref2.sha256)
        self.assertEqual(ref1.location, ref2.location)
        self.assertEqual(ref1.size_bytes, ref2.size_bytes)
        rows = self.sess.execute(
            select(Artifact).where(Artifact.run_id == st.run_id)
        ).scalars().all()
        self.assertEqual(len(rows), 1)

    def test_append_remediation_log(self):
        from sqlalchemy import select

        from redsim.db.models import Finding, RemediationAttempt
        st = self._state()
        st.save_findings([_finding("vuln-rem")])
        fid = self.sess.execute(
            select(Finding.id).where(Finding.scanner_finding_id == "vuln-rem")
        ).scalar_one()
        st.append_remediation_log(fid, "patch.commit", "ok", True)
        rows = self.sess.execute(
            select(RemediationAttempt).where(RemediationAttempt.finding_id == fid)
        ).scalars().all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].action, "patch.commit")
        self.assertTrue(rows[0].success)

    def test_append_remediation_log_by_scanner_id_resolves_uuid(self):
        # Callers pass the scanner id (e.g. ``bumblebee:CVE-1``), but
        # RemediationAttempt.finding_id is a FK to findings.id (the UUID). The
        # scanner id must resolve to the row UUID first, or the insert fails the
        # FK constraint (the H1 bug).
        from sqlalchemy import select

        from redsim.db.models import Finding, RemediationAttempt
        st = self._state()
        st.save_findings([_finding("bumblebee:CVE-1")])
        row = self.sess.execute(
            select(Finding).where(Finding.scanner_finding_id == "bumblebee:CVE-1")
        ).scalar_one()

        st.append_remediation_log("bumblebee:CVE-1", "agentic_fix", "done", True)

        attempts = self.sess.execute(
            select(RemediationAttempt).where(
                RemediationAttempt.project_id == self.project_id)
        ).scalars().all()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].finding_id, row.id)
        self.assertNotEqual(row.id, "bumblebee:CVE-1")

    def test_append_remediation_log_unknown_finding_is_noop(self):
        from sqlalchemy import select

        from redsim.db.models import RemediationAttempt
        st = self._state()
        st.append_remediation_log("does-not-exist", "x", "y", False)
        rows = self.sess.execute(
            select(RemediationAttempt).where(
                RemediationAttempt.project_id == self.project_id)
        ).scalars().all()
        self.assertEqual(rows, [])


@unittest.skipUnless(REDSIM_DB, "needs Postgres (REDSIM_DB_URL)")
class TestStateFactory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_open_run_state_postgres_branch(self):
        from redsim.config import RedsimConfig
        from redsim.db import session as sess_mod
        from redsim.db.models import Organization, Project
        from redsim.state import PostgresRunState, open_run_state
        # open_run_state does not create the project, so commit one first.
        sess_mod.init_engine(REDSIM_DB)
        oid = "org-" + uuid4().hex[:8]
        pid = "proj-" + uuid4().hex[:8]
        with sess_mod.get_session() as s:
            s.add(Organization(id=oid, name="T", slug=oid))
            s.flush()
            s.add(Project(id=pid, org_id=oid, name=pid, slug=pid))
        cfg = RedsimConfig(output_dir=self.tmp)
        with patch.dict(os.environ, {"REDSIM_DB_URL": REDSIM_DB}):
            state = open_run_state(cfg, project_id=pid)
        self.assertIsInstance(state, PostgresRunState)
        # The factory generates a run id when none is passed.
        self.assertTrue(state.run_id)
        # Caller owns the session; release it via the public helper.
        self.addCleanup(state.close)

    def test_open_run_state_releases_session_on_init_failure(self):
        from redsim.config import RedsimConfig
        from redsim.state import open_run_state
        cfg = RedsimConfig(output_dir=self.tmp)
        with patch.dict(os.environ, {"REDSIM_DB_URL": REDSIM_DB}), \
                patch("redsim.state.postgres.PostgresRunState",
                      side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                open_run_state(cfg, project_id="default")

    def test_open_run_state_filesystem_branch(self):
        from redsim.config import RedsimConfig
        from redsim.state import FilesystemRunState, open_run_state
        cfg = RedsimConfig(output_dir=self.tmp)
        env = {k: v for k, v in os.environ.items() if k != "REDSIM_DB_URL"}
        with patch.dict(os.environ, env, clear=True):
            state = open_run_state(cfg, run_id="run-fs")
        self.assertIsInstance(state, FilesystemRunState)


@unittest.skipUnless(REDSIM_DB, "needs Postgres (REDSIM_DB_URL)")
class TestMigrateFsToPg(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.blobs = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.blobs, ignore_errors=True)

    def _run_dir(self, run_id: str, *, with_findings: bool) -> Path:
        runs = Path(self.tmp) / "runs"
        rd = runs / run_id
        rd.mkdir(parents=True)
        (rd / "stage_table.json").write_text(json.dumps({"scan": "done"}))
        # Artifacts
        art = rd / "artifacts" / "report"
        art.mkdir(parents=True)
        (art / "out.txt").write_text("artifact-bytes")
        # Audit log (one marker + two legacy lines get re-anchored)
        (rd / "audit.jsonl").write_text(
            "\n".join(json.dumps(r) for r in [
                {"ts": "2026-01-01T00:00:00+00:00", "actor": "cli",
                 "action": "scan.start", "success": True},
                {"action": "patch.commit", "success": True},
            ]) + "\n"
        )
        if with_findings:
            (rd / "findings.json").write_text(json.dumps([_finding("vuln-1")]))
            (rd / "remediation-log.json").write_text(json.dumps(
                [{"finding_id": "vuln-1", "action": "patch.commit",
                  "result": "ok", "success": True}]))
        return rd

    def test_no_runs_dir_records_failure(self):
        from redsim.migrate.fs_to_pg import migrate
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        summary = migrate(source_dir=empty, db_url=REDSIM_DB)
        self.assertTrue(any("no runs dir" in f for f in summary.failures))

    def test_dry_run_walks_all_branches_without_writing(self):
        from redsim.migrate.fs_to_pg import migrate
        self._run_dir("dry-" + uuid4().hex[:8], with_findings=True)
        with patch.dict(os.environ, {"REDSIM_BLOB_FS_PATH": self.blobs}):
            summary = migrate(source_dir=self.tmp,
                              project_id="proj-" + uuid4().hex[:8],
                              db_url=REDSIM_DB, dry_run=True)
        self.assertEqual(summary.failures, [])
        self.assertEqual(summary.runs_imported, 1)
        self.assertEqual(summary.findings_imported, 1)
        self.assertEqual(summary.remediation_attempts_imported, 1)
        self.assertGreaterEqual(summary.artifacts_imported, 1)
        # marker + 2 legacy lines
        self.assertEqual(summary.audit_events_reanchored, 3)

    def test_malformed_inputs_are_tolerated(self):
        from redsim.migrate.fs_to_pg import migrate
        runs = Path(self.tmp) / "runs"
        rd = runs / ("bad-" + uuid4().hex[:8])
        rd.mkdir(parents=True)
        # Stray non-dir entry directly under runs/ is skipped.
        (runs / "stray.txt").write_text("not a run")
        # Malformed stage_table, audit (blank + non-JSON line), remediation.
        (rd / "stage_table.json").write_text("{not json")
        (rd / "audit.jsonl").write_text("\n{not json\n")
        (rd / "remediation-log.json").write_text("{not json")
        with patch.dict(os.environ, {"REDSIM_BLOB_FS_PATH": self.blobs}):
            summary = migrate(source_dir=self.tmp,
                              project_id="proj-" + uuid4().hex[:8],
                              db_url=REDSIM_DB, dry_run=True)
        self.assertEqual(summary.failures, [])
        self.assertEqual(summary.runs_imported, 1)
        self.assertEqual(summary.to_dict()["runs_imported"], 1)

    def test_real_import_then_idempotent_rerun(self):
        from redsim.migrate.fs_to_pg import migrate
        run_id = "imp-" + uuid4().hex[:8]
        project_id = "proj-" + uuid4().hex[:8]
        self._run_dir(run_id, with_findings=False)
        with patch.dict(os.environ, {"REDSIM_BLOB_FS_PATH": self.blobs}):
            first = migrate(source_dir=self.tmp, project_id=project_id,
                            db_url=REDSIM_DB)
        self.assertEqual(first.failures, [])
        self.assertEqual(first.runs_imported, 1)
        self.assertGreaterEqual(first.artifacts_imported, 1)
        self.assertEqual(first.audit_events_reanchored, 3)

        # Re-running on the same source is a no-op for the existing run.
        with patch.dict(os.environ, {"REDSIM_BLOB_FS_PATH": self.blobs}):
            second = migrate(source_dir=self.tmp, project_id=project_id,
                             db_url=REDSIM_DB)
        self.assertEqual(second.runs_imported, 0)
        self.assertGreaterEqual(second.skipped_duplicates, 1)


if __name__ == "__main__":
    unittest.main()
