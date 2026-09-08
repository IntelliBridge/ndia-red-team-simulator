"""Alembic env for Redsim."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from redsim.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _db_url() -> str:
    # Migrations run DDL + GRANTs, so they connect as the schema owner when
    # role separation is deployed (REDSIM_DB_OWNER_URL); the runtime app uses
    # the restricted REDSIM_DB_URL. When the owner URL is unset (CI, local
    # single-role dev) this falls back to REDSIM_DB_URL — unchanged behavior.
    url = (
        os.environ.get("REDSIM_DB_OWNER_URL")
        or os.environ.get("REDSIM_DB_URL")
        or config.get_main_option("sqlalchemy.url")
    )
    if not url:
        raise RuntimeError(
            "neither REDSIM_DB_OWNER_URL nor REDSIM_DB_URL is set and "
            "sqlalchemy.url is missing in alembic.ini"
        )
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(_db_url(), future=True)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
