"""Migration ``0013_foundry_auto_push`` (owner request, 2026-09-10): one nullable column.

* the chain has one head and it is 0013, directly above 0012;
* the offline upgrade SQL adds ``projects.ml_integrations`` and the downgrade drops it;
* an in-process sqlite round trip (stamp 0012, upgrade head, downgrade, upgrade)
  adds, drops and re-adds the column, and the migrated ``projects`` shape carries
  every ORM column.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from redsim.db.models import Project

ROOT = Path(__file__).resolve().parents[1]
REVISION = "0013_foundry_auto_push"
DOWN_REVISION = "0012_remove_verify_paradigm"


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_0013_is_the_single_head_above_0012():
    # 0014_audit_run_id_no_fk (2026-09-10) sits above 0013; tests/test_migration_0014.py pins that head.
    script = _script_dir()
    assert script.get_heads() == ["0014_audit_run_id_no_fk"]
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


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _offline_sql(f"upgrade {DOWN_REVISION}:{REVISION}")


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    return _offline_sql(f"downgrade {REVISION}:{DOWN_REVISION}")


def test_offline_upgrade_adds_the_column_as_jsonb(upgrade_sql: str):
    assert "ALTER TABLE projects ADD COLUMN ml_integrations JSONB" in upgrade_sql
    assert "DROP" not in upgrade_sql.split("ADD COLUMN ml_integrations")[1].split(";")[0]


def test_offline_downgrade_drops_the_column(downgrade_sql: str):
    assert "ALTER TABLE projects DROP COLUMN ml_integrations" in downgrade_sql


def test_sqlite_round_trip_matches_the_orm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    url = f"sqlite:///{tmp_path / 'm0013.db'}"
    monkeypatch.setenv("REDSIM_DB_URL", url)
    monkeypatch.delenv("REDSIM_DB_OWNER_URL", raising=False)
    engine = create_engine(url, future=True)
    # The 0012 shape of ``projects``: every ORM column but the one this revision adds.
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, name VARCHAR(256) "
            "NOT NULL, slug VARCHAR(128) NOT NULL, daily_llm_budget_cents INTEGER, ml_scoring JSON, "
            "ml_max_concurrent_runs INTEGER, ml_daily_run_budget INTEGER, created_at DATETIME)"))

    def columns() -> set[str]:
        return {c["name"] for c in inspect(engine).get_columns("projects")}

    assert "ml_integrations" not in columns()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    command.stamp(cfg, DOWN_REVISION)
    command.upgrade(cfg, "head")
    assert "ml_integrations" in columns()
    assert columns() == {c.name for c in Project.__table__.columns}
    command.downgrade(cfg, DOWN_REVISION)
    assert "ml_integrations" not in columns()
    command.upgrade(cfg, "head")
    assert "ml_integrations" in columns()
