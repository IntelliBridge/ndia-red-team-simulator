"""Migration ``0010_ml_vertical``: revision chain, DDL shape and RLS parity.

Two tiers:

* Offline (default): the Alembic script directory resolves ``0010`` as the
  single head above ``0009``, and the generated offline SQL for
  ``0009 -> 0010`` on the Postgres dialect carries the column, the table, the
  trigger pair, ``FORCE ROW LEVEL SECURITY`` and the tenant policy, and the
  downgrade SQL reverses them.
* Postgres (``REDSIM_DB_URL`` set): ``alembic upgrade head`` then
  ``downgrade -1`` then ``upgrade head`` against a live database, with the
  catalog inspected between steps. This is the M0 exit check.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("alembic")
pytest.importorskip("sqlalchemy")

from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[1]
REDSIM_DB = os.environ.get("REDSIM_DB_URL")


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_0010_is_the_single_head_above_0009():
    script = _script_dir()
    assert script.get_heads() == ["0010_ml_vertical"]
    rev = script.get_revision("0010_ml_vertical")
    assert rev.down_revision == "0009_tenant_org_id_guard"


def _offline_sql(direction: str) -> str:
    env = {**os.environ, "REDSIM_DB_URL": "postgresql+psycopg://x:x@localhost/x"}
    env.pop("REDSIM_DB_OWNER_URL", None)
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), *direction.split(), "--sql"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_offline_upgrade_sql_has_column_table_triggers_and_rls():
    sql = _offline_sql("upgrade 0009_tenant_org_id_guard:0010_ml_vertical")
    assert "ALTER TABLE targets ADD COLUMN detail JSONB" in sql
    assert "CREATE TABLE ml_campaigns" in sql
    for col in ("run_id", "project_id", "org_id", "target_id", "kind", "modality", "baseline_run_id",
                "parent_run_id", "settings_hash", "config", "provenance", "score", "limitations",
                "reviewer_notes", "created_at", "completed_at"):
        assert col in sql
    assert "FUNCTION redsim_set_org_id_ml_campaigns()" in sql
    assert "BEFORE INSERT ON ml_campaigns" in sql
    assert "FUNCTION redsim_check_org_id_ml_campaigns()" in sql
    assert "BEFORE UPDATE ON ml_campaigns" in sql
    assert "ALTER TABLE ml_campaigns ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE ml_campaigns FORCE ROW LEVEL SECURITY" in sql
    assert "CREATE POLICY redsim_tenant_isolation ON ml_campaigns" in sql
    assert "current_setting('app.current_tenants', true)" in sql
    assert "ix_ml_campaigns_settings_hash" in sql


def test_offline_downgrade_sql_reverses_everything():
    sql = _offline_sql("downgrade 0010_ml_vertical:0009_tenant_org_id_guard")
    assert "DROP POLICY IF EXISTS redsim_tenant_isolation ON ml_campaigns" in sql
    assert "DROP TRIGGER IF EXISTS trg_check_org_id_ml_campaigns" in sql
    assert "DROP TRIGGER IF EXISTS trg_set_org_id_ml_campaigns" in sql
    assert "DROP TABLE ml_campaigns" in sql
    assert "ALTER TABLE targets DROP COLUMN detail" in sql


# --- Live Postgres tier ---------------------------------------------------------------

def _alembic(*args: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), *args],
        cwd=ROOT, capture_output=True, text=True, timeout=300, check=False,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.integration
@pytest.mark.skipif(not REDSIM_DB, reason="needs Postgres (REDSIM_DB_URL)")
def test_upgrade_head_downgrade_one_upgrade_head_on_postgres():
    from sqlalchemy import create_engine, inspect, text

    engine = create_engine(REDSIM_DB, future=True)

    def state() -> dict:
        insp = inspect(engine)
        with engine.connect() as conn:
            triggers = {r[0] for r in conn.execute(text(
                "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                "WHERE c.relname = 'ml_campaigns' AND NOT t.tgisinternal"))}
            rls = conn.execute(text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'ml_campaigns'"
            )).first()
            policies = {r[0] for r in conn.execute(text(
                "SELECT policyname FROM pg_policies WHERE tablename = 'ml_campaigns'"))}
        return {
            "has_table": insp.has_table("ml_campaigns"),
            "target_cols": {c["name"] for c in insp.get_columns("targets")},
            "triggers": triggers, "rls": tuple(rls) if rls else None, "policies": policies,
        }

    _alembic("upgrade", "head")
    up = state()
    assert up["has_table"] and "detail" in up["target_cols"]
    assert up["triggers"] == {"trg_set_org_id_ml_campaigns", "trg_check_org_id_ml_campaigns"}
    assert up["rls"] == (True, True)
    assert up["policies"] == {"redsim_tenant_isolation"}

    _alembic("downgrade", "-1")
    down = state()
    assert not down["has_table"] and "detail" not in down["target_cols"]

    _alembic("upgrade", "head")
    assert state() == up
