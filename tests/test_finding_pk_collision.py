"""Phase 4 v0.3.1 F9 — two runs may emit the same scanner identifier.

Confirms the UUID PK + UNIQUE(run_id, scanner_finding_id) design lets
parallel runs coexist instead of colliding on the old String(128) PK.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

import pytest

pytest.importorskip("sqlalchemy")

from redsim.db.models import (
    Base,
    Finding,
    Organization,
    Project,
    Run,
)


def _make_engine():
    from sqlalchemy import create_engine
    engine = create_engine("sqlite://", future=True)
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:  # noqa: BLE001 - skip on any sqlite failure
        raise unittest.SkipTest(f"sqlite can't host the schema: {exc}")
    return engine


class TestParallelRunsSameScannerId(unittest.TestCase):
    def test_two_runs_same_scanner_id_coexist(self):
        from sqlalchemy.orm import sessionmaker
        engine = _make_engine()
        Session = sessionmaker(engine)
        with Session() as s:
            s.add(Organization(id="org-1", name="A", slug="a"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
            s.flush()
            for run_id in ("run-1", "run-2"):
                s.add(Run(id=run_id, project_id="proj-1", mode="live",
                          status="running", stage_table={}))
            s.flush()
            for run_id in ("run-1", "run-2"):
                s.add(Finding(
                    id=str(uuid4()),
                    scanner_finding_id="vuln-0001",
                    run_id=run_id, project_id="proj-1",
                    schema_blob={"id": "vuln-0001", "title": "SQLi"},
                    severity="critical",
                ))
            s.commit()
            rows = s.query(Finding).all()
        self.assertEqual(len(rows), 2)
        ids = {r.id for r in rows}
        self.assertEqual(len(ids), 2, "UUIDs distinct across runs")
        scanner_ids = {r.scanner_finding_id for r in rows}
        self.assertEqual(scanner_ids, {"vuln-0001"})

    def test_same_run_same_scanner_id_collides(self):
        from sqlalchemy.exc import IntegrityError
        from sqlalchemy.orm import sessionmaker
        engine = _make_engine()
        Session = sessionmaker(engine)
        with Session() as s:
            s.add(Organization(id="org-1", name="A", slug="a"))
            s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
            s.add(Run(id="run-1", project_id="proj-1", mode="live",
                      status="running", stage_table={}))
            s.flush()
            s.add(Finding(
                id=str(uuid4()),
                scanner_finding_id="vuln-0001",
                run_id="run-1", project_id="proj-1",
                schema_blob={"id": "vuln-0001"},
                severity="critical",
            ))
            s.commit()
            s.add(Finding(
                id=str(uuid4()),
                scanner_finding_id="vuln-0001",
                run_id="run-1", project_id="proj-1",
                schema_blob={"id": "vuln-0001"},
                severity="critical",
            ))
            with self.assertRaises(IntegrityError):
                s.commit()


if __name__ == "__main__":
    unittest.main()
