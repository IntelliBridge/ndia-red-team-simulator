"""Phase 3 database layer.

Sync SQLAlchemy 2.x; the engine and session factory are created lazily so
the offline CLI (which doesn't pull these imports) is unaffected.
"""

from aegis.db.session import Session, engine, get_session, init_engine

__all__ = ["Session", "engine", "get_session", "init_engine"]
