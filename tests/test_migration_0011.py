"""Migration ``0011_phase_b_platform``: revision chain, DDL shape, RLS parity, round trip.

Three tiers:

* Offline (default): the Alembic script directory resolves ``0011`` as the
  single head above ``0010``; the generated offline SQL for ``0010 -> 0011``
  on the Postgres dialect carries the four tables, the ``projects`` and
  ``ml_campaigns`` columns, and for every new tenant-scoped table the trigger
  pair, ``FORCE ROW LEVEL SECURITY`` and the tenant policy whose text is,
  token for token, 0010's ``ml_campaigns`` text with the table name
  substituted; the downgrade SQL reverses all of it.
* Sqlite round trip (default): a database at the 0010 shape of the tables
  0011 touches is stamped ``0010`` and driven ``upgrade head``,
  ``downgrade 0010``, ``upgrade head`` in-process. The table and column DDL
  runs on sqlite (the RLS SQL is Postgres-only and skipped), so this proves
  the create, drop and re-create paths and that the migrated shape matches
  the ORM models column for column.
* Postgres (``REDSIM_DB_URL`` set, ``integration``): ``alembic upgrade head``
  then ``downgrade -1`` then ``upgrade head`` against a live database with the
  catalog inspected between steps, as ``tests/test_migration_0010.py`` does.
"""

from __future__ import annotations

import os
import sqlite3
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

REVISION = "0011_phase_b_platform"
DOWN_REVISION = "0010_ml_vertical"

# The four new tenant-scoped tables and the columns the ORM declares for them.
NEW_TABLES = ("report_snapshots", "idempotency_keys", "ml_batches", "ml_datasets")
PROJECT_COLUMNS = ("ml_scoring", "ml_max_concurrent_runs", "ml_daily_run_budget")


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_0011_is_the_single_head_above_0010():
    script = _script_dir()
    assert script.get_heads() == [REVISION]
    rev = script.get_revision(REVISION)
    assert rev.down_revision == DOWN_REVISION


# --- Offline SQL tier -----------------------------------------------------------------

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


def test_offline_upgrade_sql_creates_the_four_tables(upgrade_sql: str):
    for table in NEW_TABLES:
        assert f"CREATE TABLE {table}" in upgrade_sql
    # report_snapshots: the snapshot row shape.
    for col in ("run_id", "artifact_ids", "record_sha256", "rendered_at", "archived"):
        assert col in upgrade_sql
    assert "archived BOOLEAN DEFAULT false NOT NULL" in upgrade_sql
    # idempotency_keys: (project_id, key) is the primary key, so it is unique.
    assert "CONSTRAINT pk_idempotency_keys PRIMARY KEY (project_id, key)" in upgrade_sql
    for col in ("route", "request_sha256", "response_status", "response_body"):
        assert col in upgrade_sql
    # ml_batches and ml_datasets.
    for col in ("kind", "config", "status", "created_by", "cancelled_at", "idempotency_key",
                "refusal_reason", "license", "modality", "class_names", "manifest_sha256",
                "blob_location"):
        assert col in upgrade_sql
    assert "status VARCHAR(32) DEFAULT 'accepted' NOT NULL" in upgrade_sql
    assert "status VARCHAR(16) DEFAULT 'validating' NOT NULL" in upgrade_sql
    assert "ix_ml_datasets_manifest_sha256" in upgrade_sql


def test_offline_upgrade_sql_adds_the_project_and_campaign_columns(upgrade_sql: str):
    assert "ALTER TABLE projects ADD COLUMN ml_scoring JSONB" in upgrade_sql
    assert "ALTER TABLE projects ADD COLUMN ml_max_concurrent_runs INTEGER" in upgrade_sql
    assert "ALTER TABLE projects ADD COLUMN ml_daily_run_budget INTEGER" in upgrade_sql
    assert "ALTER TABLE ml_campaigns ADD COLUMN batch_id VARCHAR(64)" in upgrade_sql
    assert "CREATE INDEX ix_ml_campaigns_batch_id ON ml_campaigns (batch_id)" in upgrade_sql
    # Additive only: no existing column is altered or dropped on the way up.
    assert "DROP COLUMN" not in upgrade_sql
    assert "ALTER COLUMN" not in upgrade_sql


@pytest.mark.parametrize("table", NEW_TABLES)
def test_offline_upgrade_sql_has_rls_parity_on_every_new_table(upgrade_sql: str, table: str):
    assert f"FUNCTION redsim_set_org_id_{table}()" in upgrade_sql
    assert f"BEFORE INSERT ON {table}" in upgrade_sql
    assert f"FUNCTION redsim_check_org_id_{table}()" in upgrade_sql
    assert f"BEFORE UPDATE ON {table}" in upgrade_sql
    assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in upgrade_sql
    assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in upgrade_sql
    assert f"CREATE POLICY redsim_tenant_isolation ON {table}" in upgrade_sql
    assert "current_setting('app.current_tenants', true)" in upgrade_sql
    # Role separation: the enumerated redsim_app grant of 0004/0005.
    assert f"ON TABLE {table} TO redsim_app" in upgrade_sql


def _tokens(sql: str) -> str:
    return " ".join(sql.split())


def _rls_block(sql: str, table: str) -> str:
    """The trigger-to-policy text for ``table``, whitespace-normalised."""
    start = sql.index(f"CREATE OR REPLACE FUNCTION redsim_set_org_id_{table}()")
    end_marker = f"CREATE POLICY redsim_tenant_isolation ON {table}"
    end = sql.index(";", sql.index("WITH CHECK", sql.index(end_marker))) + 1
    return _tokens(sql[start:end])


@pytest.mark.parametrize("table", NEW_TABLES)
def test_rls_sql_is_0010_text_with_only_the_table_name_substituted(upgrade_sql: str, table: str):
    """The plan asks for 0010's RLS parity copied verbatim: prove it against 0010's own output."""
    sql_0010 = _offline_sql(f"upgrade 0009_tenant_org_id_guard:{DOWN_REVISION}")
    reference = _rls_block(sql_0010, "ml_campaigns")
    # Plain replace, not a \b regex: the name also sits inside
    # ``redsim_set_org_id_ml_campaigns`` where ``_`` is a word character.
    expected = reference.replace("ml_campaigns", table)
    assert "ml_campaigns" not in expected
    assert _rls_block(upgrade_sql, table) == expected


def test_offline_downgrade_sql_reverses_everything(downgrade_sql: str):
    for table in NEW_TABLES:
        assert f"DROP POLICY IF EXISTS redsim_tenant_isolation ON {table}" in downgrade_sql
        assert f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY" in downgrade_sql
        assert f"DROP TRIGGER IF EXISTS trg_check_org_id_{table}" in downgrade_sql
        assert f"DROP FUNCTION IF EXISTS redsim_check_org_id_{table}()" in downgrade_sql
        assert f"DROP TRIGGER IF EXISTS trg_set_org_id_{table}" in downgrade_sql
        assert f"DROP FUNCTION IF EXISTS redsim_set_org_id_{table}()" in downgrade_sql
        assert f"DROP TABLE {table}" in downgrade_sql
    assert "DROP INDEX IF EXISTS ix_ml_campaigns_batch_id" in downgrade_sql
    assert "ALTER TABLE ml_campaigns DROP COLUMN batch_id" in downgrade_sql
    for column in PROJECT_COLUMNS:
        assert f"ALTER TABLE projects DROP COLUMN {column}" in downgrade_sql
    # Policies and triggers go before the tables that carry them.
    assert downgrade_sql.index("DROP POLICY IF EXISTS redsim_tenant_isolation ON ml_datasets") \
        < downgrade_sql.index("DROP TABLE ml_datasets")
    # No existing 0010 object is touched on the way down.
    assert "DROP TABLE ml_campaigns" not in downgrade_sql
    assert "targets" not in downgrade_sql


# --- Sqlite round-trip tier -----------------------------------------------------------

def _baseline_0010(engine) -> None:  # type: ignore[no-untyped-def]
    """Create the 0010 shape of every table 0011 touches or references.

    Hand-declared rather than taken from the ORM because the ORM now carries
    the 0011 additions. Foreign keys are declared but sqlite does not enforce
    them without a pragma, matching the harness mirrors in ``tests/e2e``.
    """
    from sqlalchemy import (
        JSON,
        Column,
        DateTime,
        ForeignKey,
        Integer,
        MetaData,
        String,
        Table,
        Text,
    )

    md = MetaData()
    Table("organizations", md,
          Column("id", String(64), primary_key=True),
          Column("name", String(256), nullable=False),
          Column("slug", String(128), nullable=False, unique=True))
    Table("projects", md,
          Column("id", String(64), primary_key=True),
          Column("org_id", String(64), ForeignKey("organizations.id"), nullable=False),
          Column("name", String(256), nullable=False),
          Column("slug", String(128), nullable=False),
          Column("daily_llm_budget_cents", Integer, nullable=True),
          Column("created_at", DateTime(timezone=True)))
    Table("targets", md,
          Column("id", String(64), primary_key=True),
          Column("project_id", String(64), ForeignKey("projects.id"), nullable=False),
          Column("org_id", String(64), nullable=True),
          Column("kind", String(32), nullable=False),
          Column("value", String(1024), nullable=False),
          Column("detail", JSON, nullable=True))
    Table("runs", md,
          Column("id", String(64), primary_key=True),
          Column("project_id", String(64), ForeignKey("projects.id"), nullable=False),
          Column("org_id", String(64), nullable=True),
          Column("status", String(32)))
    Table("ml_campaigns", md,
          Column("run_id", String(64), ForeignKey("runs.id"), primary_key=True),
          Column("project_id", String(64), ForeignKey("projects.id"), nullable=False, index=True),
          Column("org_id", String(64), nullable=True, index=True),
          Column("target_id", String(64), ForeignKey("targets.id"), nullable=False, index=True),
          Column("kind", String(16), nullable=False),
          Column("modality", String(16), nullable=False),
          Column("baseline_run_id", String(64), nullable=True),
          Column("parent_run_id", String(64), nullable=True),
          Column("settings_hash", String(64), nullable=True, index=True),
          Column("config", JSON, nullable=False),
          Column("provenance", JSON, nullable=True),
          Column("score", JSON, nullable=True),
          Column("limitations", JSON, nullable=False),
          Column("reviewer_notes", Text, nullable=True),
          Column("created_at", DateTime(timezone=True)),
          Column("completed_at", DateTime(timezone=True), nullable=True))
    md.create_all(engine)


def _sqlite_state(engine) -> dict:  # type: ignore[no-untyped-def]
    from sqlalchemy import inspect

    insp = inspect(engine)
    tables = set(insp.get_table_names())
    return {
        "tables": tables,
        "columns": {t: {c["name"] for c in insp.get_columns(t)} for t in sorted(tables)},
        "indexes": {t: {ix["name"] for ix in insp.get_indexes(t)} for t in sorted(tables)},
    }


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 35, 0),
                    reason="the downgrade drops columns; sqlite < 3.35 has no DROP COLUMN")
def test_sqlite_upgrade_downgrade_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from alembic import command
    from sqlalchemy import create_engine, text

    from redsim.db.models import Base

    db = tmp_path / "phase_b.sqlite"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("REDSIM_DB_URL", url)
    monkeypatch.delenv("REDSIM_DB_OWNER_URL", raising=False)

    engine = create_engine(url, future=True)
    _baseline_0010(engine)
    before = _sqlite_state(engine)
    for table in NEW_TABLES:
        assert table not in before["tables"]
    assert not set(PROJECT_COLUMNS) & before["columns"]["projects"]
    assert "batch_id" not in before["columns"]["ml_campaigns"]

    # No ini file: alembic.ini's logging fileConfig would reconfigure the
    # pytest process. The script location is all env.py needs.
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "redsim" / "db" / "migrations"))

    command.stamp(cfg, DOWN_REVISION)
    command.upgrade(cfg, "head")
    up = _sqlite_state(engine)
    for table in NEW_TABLES:
        assert table in up["tables"]
        # The migrated shape is the ORM shape, column for column.
        assert up["columns"][table] == set(Base.metadata.tables[table].columns.keys()), table
    assert set(PROJECT_COLUMNS) <= up["columns"]["projects"]
    assert set(PROJECT_COLUMNS) <= set(Base.metadata.tables["projects"].columns.keys())
    assert "batch_id" in up["columns"]["ml_campaigns"]
    assert "ix_ml_campaigns_batch_id" in up["indexes"]["ml_campaigns"]
    # Untouched 0010 shape survives.
    assert up["columns"]["ml_campaigns"] - {"batch_id"} == before["columns"]["ml_campaigns"]
    assert up["columns"]["projects"] - set(PROJECT_COLUMNS) == before["columns"]["projects"]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == REVISION

    command.downgrade(cfg, DOWN_REVISION)
    down = _sqlite_state(engine)
    down["tables"].discard("alembic_version")
    down["columns"].pop("alembic_version", None)
    down["indexes"].pop("alembic_version", None)
    assert down == before
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == DOWN_REVISION

    command.upgrade(cfg, "head")
    again = _sqlite_state(engine)
    again["tables"].discard("alembic_version")
    again["columns"].pop("alembic_version", None)
    again["indexes"].pop("alembic_version", None)
    up["tables"].discard("alembic_version")
    up["columns"].pop("alembic_version", None)
    up["indexes"].pop("alembic_version", None)
    assert again == up
    engine.dispose()


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
        tables = set(insp.get_table_names())
        out: dict = {
            "tables": {t for t in NEW_TABLES if t in tables},
            "project_cols": {c["name"] for c in insp.get_columns("projects")},
            "campaign_cols": {c["name"] for c in insp.get_columns("ml_campaigns")},
            "rls": {},
        }
        with engine.connect() as conn:
            for table in NEW_TABLES:
                if table not in tables:
                    continue
                triggers = {r[0] for r in conn.execute(text(
                    "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE c.relname = :t AND NOT t.tgisinternal"), {"t": table})}
                rls = conn.execute(text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
                    {"t": table}).first()
                policies = {r[0] for r in conn.execute(text(
                    "SELECT policyname FROM pg_policies WHERE tablename = :t"), {"t": table})}
                out["rls"][table] = {
                    "triggers": triggers, "rls": tuple(rls) if rls else None, "policies": policies,
                }
        return out

    _alembic("upgrade", "head")
    up = state()
    assert up["tables"] == set(NEW_TABLES)
    assert set(PROJECT_COLUMNS) <= up["project_cols"]
    assert "batch_id" in up["campaign_cols"]
    for table in NEW_TABLES:
        assert up["rls"][table]["triggers"] == {
            f"trg_set_org_id_{table}", f"trg_check_org_id_{table}"}, table
        assert up["rls"][table]["rls"] == (True, True), table
        assert up["rls"][table]["policies"] == {"redsim_tenant_isolation"}, table

    _alembic("downgrade", "-1")
    down = state()
    assert down["tables"] == set()
    assert not set(PROJECT_COLUMNS) & down["project_cols"]
    assert "batch_id" not in down["campaign_cols"]

    _alembic("upgrade", "head")
    assert state() == up
