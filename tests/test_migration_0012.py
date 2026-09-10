"""Migration ``0012_remove_verify_paradigm`` (product owner decision, 2026-09-09).

* the chain has one head and it is 0012, directly above 0011;
* the offline upgrade SQL drops exactly ``findings.validation_state``,
  ``findings.validated_at`` and ``ml_campaigns.baseline_run_id`` and creates
  nothing; the offline downgrade re-adds the three columns;
* the ORM no longer maps the two finding columns.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from redsim.db.models import Finding

ROOT = Path(__file__).resolve().parents[1]
REVISION = "0012_remove_verify_paradigm"
DOWN_REVISION = "0011_phase_b_platform"


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_0012_is_the_single_head_above_0011():
    # 0013_foundry_auto_push (2026-09-10) sits above 0012; tests/test_migration_0013.py pins that head.
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


def test_upgrade_drops_the_three_columns_and_nothing_else(upgrade_sql: str):
    drops = re.findall(r"ALTER TABLE (\w+) DROP COLUMN (\w+)", upgrade_sql)
    assert sorted(drops) == [
        ("findings", "validated_at"), ("findings", "validation_state"), ("ml_campaigns", "baseline_run_id"),
    ]
    assert "CREATE TABLE" not in upgrade_sql
    assert "DROP TABLE" not in upgrade_sql
    assert "ADD COLUMN" not in upgrade_sql


def test_downgrade_restores_the_three_columns(downgrade_sql: str):
    adds = re.findall(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", downgrade_sql)
    assert sorted(adds) == [
        ("findings", "validated_at"), ("findings", "validation_state"), ("ml_campaigns", "baseline_run_id"),
    ]
    assert "DROP COLUMN" not in downgrade_sql


def test_orm_no_longer_maps_the_finding_validation_columns():
    columns = {c.name for c in Finding.__table__.columns}
    assert "validation_state" not in columns
    assert "validated_at" not in columns


@pytest.mark.skipif(__import__("sqlite3").sqlite_version_info < (3, 35),
                    reason="the upgrade drops columns; sqlite < 3.35 has no DROP COLUMN")
def test_sqlite_upgrade_downgrade_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from alembic import command
    from sqlalchemy import create_engine, inspect, text

    db = tmp_path / "verify_removed.sqlite"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("REDSIM_DB_URL", url)
    monkeypatch.delenv("REDSIM_DB_OWNER_URL", raising=False)

    engine = create_engine(url, future=True)
    # The 0011 shape of the two tables, reduced to the columns this revision touches
    # plus a neighbour each, in raw SQL: the ORM no longer maps the dropped columns.
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE findings (id VARCHAR(36) PRIMARY KEY, status VARCHAR(32), "
                          "validation_state VARCHAR(32) DEFAULT 'unvalidated', validated_at DATETIME)"))
        conn.execute(text("CREATE TABLE ml_campaigns (run_id VARCHAR(64) PRIMARY KEY, project_id VARCHAR(64), "
                          "baseline_run_id VARCHAR(64), kind VARCHAR(16), batch_id VARCHAR(64))"))

    def columns(table: str) -> set[str]:
        return {c["name"] for c in inspect(engine).get_columns(table)}

    assert {"validation_state", "validated_at"} <= columns("findings")
    assert "baseline_run_id" in columns("ml_campaigns")

    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    command.stamp(cfg, DOWN_REVISION)
    command.upgrade(cfg, "head")
    assert not {"validation_state", "validated_at"} & columns("findings")
    assert "baseline_run_id" not in columns("ml_campaigns")
    assert {"run_id", "project_id", "kind", "batch_id"} <= columns("ml_campaigns")

    command.downgrade(cfg, DOWN_REVISION)
    assert {"validation_state", "validated_at"} <= columns("findings")
    assert "baseline_run_id" in columns("ml_campaigns")
