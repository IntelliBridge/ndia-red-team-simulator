"""Sync engine + session factory."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as _Session
from sqlalchemy.orm import sessionmaker


_ENGINE: Engine | None = None
Session: sessionmaker | None = None


def init_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Create (or replace) the global engine. Returns it."""
    global _ENGINE, Session
    db_url = url or os.environ.get("AEGIS_DB_URL")
    if not db_url:
        raise RuntimeError("AEGIS_DB_URL is not set and no url was provided")
    _ENGINE = create_engine(db_url, echo=echo, future=True, pool_pre_ping=True)
    Session = sessionmaker(_ENGINE, expire_on_commit=False, future=True)
    return _ENGINE


def engine() -> Engine:
    if _ENGINE is None:
        init_engine()
    assert _ENGINE is not None
    return _ENGINE


@contextmanager
def get_session() -> Iterator[_Session]:
    if Session is None:
        init_engine()
    assert Session is not None
    sess = Session()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
