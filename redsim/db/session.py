"""Sync engine + session factory.

Tenant isolation seam (Phase 6, multi-tenancy): ``get_session`` sets the
Postgres GUC ``app.current_tenants`` for the transaction from a request-scoped
``ContextVar``. The RLS policies installed by migration 0005 read that GUC to
filter rows by ``org_id``. An empty / unset list means *system* (full access),
which is the worker / migration path. The GUC is only set on Postgres —
``set_config`` is Postgres-only — so sqlite-based unit tests are unaffected.
"""

from __future__ import annotations

import contextvars
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as _Session
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

_ENGINE: Engine | None = None
Session: sessionmaker | None = None

# One-time guard for the "RLS is bypassed by superusers" warning below.
_rls_bypass_warned = False

# Request/worker-scoped list of org ids the caller may see. ``None`` (the
# default) means system / full access — the GUC is set to '' so RLS lets every
# row through. Set per-request by the tenant middleware; cleared (reset) after.
_current_tenants: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar(
    "redsim_current_tenants", default=None
)


def set_current_tenants(org_ids: list[str] | None) -> contextvars.Token:
    """Set the caller's accessible org ids for the current context.

    ``None`` or an empty list both mean *system* (full access / RLS bypass).
    Returns the ``contextvars.Token`` so the caller can ``reset`` it when the
    scope ends (the middleware does this in a ``finally``).
    """
    normalized = org_ids if org_ids else None
    return _current_tenants.set(normalized)


def reset_current_tenants(token: contextvars.Token) -> None:
    """Restore the previous tenant scope (pair with ``set_current_tenants``)."""
    _current_tenants.reset(token)


def current_tenants() -> list[str] | None:
    """The org ids in scope, or ``None`` for system / full access."""
    return _current_tenants.get()


def init_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Create (or replace) the global engine. Returns it."""
    global _ENGINE, Session
    db_url = url or os.environ.get("REDSIM_DB_URL")
    if not db_url:
        raise RuntimeError("REDSIM_DB_URL is not set and no url was provided")
    _ENGINE = create_engine(db_url, echo=echo, future=True, pool_pre_ping=True)
    Session = sessionmaker(_ENGINE, expire_on_commit=False, future=True)
    return _ENGINE


def engine() -> Engine:
    if _ENGINE is None:
        init_engine()
    assert _ENGINE is not None
    return _ENGINE


def _apply_tenant_guc(sess: _Session) -> None:
    """Set ``app.current_tenants`` for this transaction (Postgres only).

    Uses ``set_config(..., is_local => true)`` so the setting is scoped to the
    transaction and reset on commit / rollback — no leakage across pooled
    connections. The value is bound as a parameter (never interpolated). On
    non-Postgres dialects this is a no-op (``set_config`` doesn't exist).
    """
    if sess.bind is None or sess.bind.dialect.name != "postgresql":
        return
    tenants = _current_tenants.get()
    value = ",".join(tenants) if tenants else ""
    sess.execute(
        text("SELECT set_config('app.current_tenants', :v, true)"),
        {"v": value},
    )
    # Defense-in-depth alarm: a Postgres *superuser* bypasses RLS unconditionally
    # (FORCE only binds the table owner), so org isolation silently degrades to a
    # no-op if the app connects as one. Production must use the restricted
    # ``redsim_app`` role (migration 0004 + deploy runbook). Warn once, only when a
    # real tenant scope is in effect, so dev/superuser setups still function.
    global _rls_bypass_warned
    if tenants and not _rls_bypass_warned:
        _rls_bypass_warned = True
        try:
            is_super = sess.execute(text("SHOW is_superuser")).scalar()
        except Exception:  # noqa: BLE001  # pragma: no cover - defensive
            is_super = None
        if str(is_super).lower() == "on":
            logger.warning(
                "DB role is a superuser; Postgres RLS tenant isolation is "
                "BYPASSED. Connect as the non-superuser redsim_app role in "
                "production (see the multi-tenancy / deploy docs)."
            )


@contextmanager
def get_session() -> Iterator[_Session]:
    if Session is None:
        init_engine()
    assert Session is not None
    sess = Session()
    try:
        _apply_tenant_guc(sess)
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
