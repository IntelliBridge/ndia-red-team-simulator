"""Select the appropriate ``RunStateAPI`` backend per environment.

When ``AEGIS_DB_URL`` is set the Postgres backend is used; otherwise the
filesystem backend (Phase 2 default) keeps running.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

from aegis.config import AegisConfig


def open_run_state(config: AegisConfig, *,
                   run_id: str | None = None,
                   project_id: str | None = None,
                   created_by: str | None = None):
    """Return the active ``RunStateAPI`` implementation.

    Filesystem path is the offline default. Postgres path requires
    ``AEGIS_DB_URL`` (or a pre-initialised engine).
    """
    db_url = os.environ.get("AEGIS_DB_URL")
    if not db_url:
        from aegis.state import FilesystemRunState
        return FilesystemRunState(config.output_dir, run_id=run_id)

    from aegis.db.session import get_session, init_engine
    init_engine(db_url)
    rid = run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        + "-" + uuid4().hex[:6]
    )
    pid = project_id or "default"
    session_ctx = get_session()
    sess = session_ctx.__enter__()
    try:
        from aegis.state_pg import PostgresRunState
        state = PostgresRunState(
            sess, run_id=rid, project_id=pid,
            output_dir=config.output_dir, created_by=created_by,
        )
        # Caller is responsible for the session lifetime; expose a close()
        # helper so worker bootstrap can release it cleanly.
        state._session_ctx = session_ctx
        return state
    except Exception:
        session_ctx.__exit__(None, None, None)
        raise
