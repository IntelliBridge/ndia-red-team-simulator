"""Real Postgres advisory locks and count-only RLS scope restoration.

Set REDSIM_TEST_CAPACITY_POSTGRES_URL to a disposable local Postgres database.
The fixture creates an isolated schema and a non-superuser role, and removes
both on exit. It never changes application tables.
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

pytest.importorskip("sqlalchemy")
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from redsim.services.llm_capacity import count_gateway_active, gateway_lock

pytestmark = pytest.mark.integration


@pytest.fixture
def pg_capacity():
    url = os.environ.get("REDSIM_TEST_CAPACITY_POSTGRES_URL")
    if not url:
        pytest.skip("disposable Postgres URL not configured")
    suffix = uuid4().hex[:12]
    schema, role = f"capacity_{suffix}", f"capacity_role_{suffix}"
    admin = create_engine(url)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOBYPASSRLS'))
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        conn.execute(text(f'''CREATE TABLE "{schema}".jobs (
            id text PRIMARY KEY, type text, status text, detail jsonb, org_id text)'''))
        conn.execute(text(f'ALTER TABLE "{schema}".jobs ENABLE ROW LEVEL SECURITY'))
        conn.execute(text(f'''CREATE POLICY tenant ON "{schema}".jobs USING (
            coalesce(current_setting('app.current_tenants', true), '') = ''
            OR org_id = current_setting('app.current_tenants', true))'''))
        conn.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"'))
        conn.execute(text(f'GRANT SELECT, INSERT ON "{schema}".jobs TO "{role}"'))
    engine = create_engine(url, connect_args={"options": f"-c role={role} -c search_path={schema}"})
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            conn.execute(text(f'DROP ROLE "{role}"'))
        admin.dispose()


def insert_job(session, job_id, org="other"):
    session.execute(text("INSERT INTO jobs VALUES (:id, 'llm.probe', 'queued', CAST(:detail AS jsonb), :org)"),
                    {"id": job_id, "org": org,
                     "detail": json.dumps({"gateway_host": "gateway.invalid", "persona": "default"})})


def test_global_count_restores_tenant_rls_scope(pg_capacity):
    with Session(pg_capacity) as session:
        insert_job(session, "other-tenant-job")
        session.commit()
        session.execute(text("SELECT set_config('app.current_tenants', 'mine', true)"))
        assert session.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0
        assert count_gateway_active(session, "gateway.invalid", None) == 1
        assert session.execute(text("SELECT current_setting('app.current_tenants')")).scalar_one() == "mine"
        assert session.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0


def test_advisory_lock_prevents_concurrent_overreservation(pg_capacity):
    def reserve(i):
        with Session(pg_capacity) as session, gateway_lock(session, "gateway.invalid", "default"):
            if count_gateway_active(session, "gateway.invalid", "default") >= 2:
                session.commit()
                return False
            time.sleep(0.02)  # Force overlapping contenders to expose a missing lock.
            insert_job(session, f"job-{i}")
            session.commit()
            return True
    with ThreadPoolExecutor(max_workers=5) as pool:
        assert sum(pool.map(reserve, range(5))) == 2
