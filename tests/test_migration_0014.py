"""Migration ``0014_audit_run_id_no_fk`` (2026-09-10): the audit row may name a run that does not exist yet.

* the chain has one head and it is 0014, directly above 0013;
* the offline Postgres SQL drops ``audit_events_run_id_fkey`` and the downgrade re-adds it ``NOT VALID``;
* the ORM ``AuditEvent.run_id`` carries no foreign key, so ``PostgresAuditWriter`` can append the admission
  row before the ``Run`` row on a database that enforces constraints (sqlite with ``PRAGMA foreign_keys=ON``
  stands in for Postgres here).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from redsim.db.models import AuditEvent, Base, Organization, Project
from tests.conftest import patch_jsonb_for_sqlite

ROOT = Path(__file__).resolve().parents[1]
REVISION = "0014_audit_run_id_no_fk"
DOWN_REVISION = "0013_foundry_auto_push"


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_0014_is_the_single_head_above_0013():
    script = _script_dir()
    assert script.get_heads() == [REVISION]
    assert script.get_revision(REVISION).down_revision == DOWN_REVISION


def _offline_sql(direction: str) -> str:
    env = {**os.environ, "REDSIM_DB_URL": "postgresql+psycopg://x:x@localhost/x"}
    env.pop("REDSIM_DB_OWNER_URL", None)
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), *direction.split(), "--sql"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_offline_sql_drops_and_readds_the_constraint():
    up = _offline_sql(f"upgrade {DOWN_REVISION}:{REVISION}")
    assert "ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_run_id_fkey" in up
    down = _offline_sql(f"downgrade {REVISION}:{DOWN_REVISION}")
    assert "ADD CONSTRAINT audit_events_run_id_fkey FOREIGN KEY (run_id) REFERENCES runs (id) NOT VALID" in down


def test_orm_audit_row_may_name_a_run_that_does_not_exist_yet(tmp_path: Path):
    """The admission order of spec 6.7 invariant 4, on a database that enforces foreign keys."""
    assert not AuditEvent.__table__.c.run_id.foreign_keys, "audit_events.run_id must not reference runs"
    engine = create_engine(f"sqlite:///{tmp_path / 'fk.db'}", future=True)

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    patch_jsonb_for_sqlite()
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as sess:
        sess.add(Organization(id="org", name="Org", slug="org"))
        sess.add(Project(id="proj", org_id="org", name="P", slug="proj"))
        sess.flush()
        sess.add(AuditEvent(chain_id="run:run-not-yet", seq=1, project_id="proj", run_id="run-not-yet",
                            actor="user:x", action="attack.run", target=None, allowlist_check="n/a",
                            override=False, success=True, detail={}, schema_version=1,
                            prev_hash=None, this_hash=b"\x00" * 32))
        sess.commit()
        assert sess.query(AuditEvent).filter_by(run_id="run-not-yet").count() == 1


@pytest.mark.integration
def test_postgres_round_trip():
    url = os.environ.get("REDSIM_DB_URL", "")
    if not url.startswith("postgresql"):
        pytest.skip("REDSIM_DB_URL is not a Postgres database")
    from alembic import command
    from sqlalchemy import inspect

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    engine = create_engine(url, future=True)

    def fk_names() -> set[str]:
        return {fk["name"] for fk in inspect(engine).get_foreign_keys("audit_events")}

    command.upgrade(cfg, "head")
    assert "audit_events_run_id_fkey" not in fk_names()
    command.downgrade(cfg, DOWN_REVISION)
    assert "audit_events_run_id_fkey" in fk_names()
    command.upgrade(cfg, "head")
    assert "audit_events_run_id_fkey" not in fk_names()
