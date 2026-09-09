"""One-off ECS migration; master credentials never belong to serving tasks."""
import os
import subprocess
from urllib.parse import quote

import psycopg
from psycopg import sql

host = os.environ['REDSIM_DB_HOST']
admin = os.environ['REDSIM_DB_ADMIN_USERNAME']
password = os.environ['REDSIM_DB_ADMIN_PASSWORD']
kwargs = dict(host=host, user=admin, password=password, sslmode='require')
with psycopg.connect(dbname='postgres', autocommit=True, **kwargs) as conn:
    for name, key in [('redsim_app', 'REDSIM_APP_DB_PASSWORD'), ('redsim_identity', 'REDSIM_IDENTITY_DB_PASSWORD')]:
        if not conn.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (name,)).fetchone():
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD {}').format(
                sql.Identifier(name), sql.Literal(os.environ[key])))
    if not conn.execute("SELECT 1 FROM pg_database WHERE datname = 'redsim_identity'").fetchone():
        conn.execute('CREATE DATABASE redsim_identity OWNER redsim_identity')
os.environ['REDSIM_DB_URL'] = f'postgresql+psycopg://{quote(admin, safe="")}:{quote(password, safe="")}@{host}:5432/redsim?sslmode=require'
subprocess.run(['alembic', 'upgrade', 'head'], check=True)
with psycopg.connect(dbname='redsim', autocommit=True, **kwargs) as conn:
    conn.execute('GRANT CONNECT ON DATABASE redsim TO redsim_app')
    conn.execute('GRANT USAGE ON SCHEMA public TO redsim_app')
    for (name,) in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'"):
        permissions = 'SELECT, INSERT' if name == 'audit_events' else 'SELECT, INSERT, UPDATE, DELETE'
        conn.execute(sql.SQL('GRANT '+permissions+' ON TABLE {} TO redsim_app').format(sql.Identifier(name)))
    conn.execute('GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO redsim_app')
    # Check the runtime role does not inherit a superuser or RLS-bypass role.
    role = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='redsim_app'").fetchone()
    assert role == (False, False), 'Unsafe application role'
    assert not conn.execute("SELECT has_table_privilege('redsim_app', 'audit_events', 'UPDATE')").fetchone()[0]
    assert not conn.execute("SELECT has_table_privilege('redsim_app', 'audit_events', 'DELETE')").fetchone()[0]
print('Migration and application-role grants completed.')
