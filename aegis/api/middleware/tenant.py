"""Tenant-scope middleware (Phase 6, multi-tenancy).

After auth resolves the caller, compute the set of Organization ids they may
see (the distinct orgs of the projects they're a member of) and pin them on the
request-scoped ``ContextVar`` consumed by ``aegis.db.session.get_session``.
Postgres RLS (migration 0005) then enforces org isolation at the database — a
forgotten ``WHERE`` clause can no longer leak rows across tenants.

System principals (``is_system`` — workers, service accounts) get ``None`` =
full access (RLS bypass). Unauthenticated / unresolvable requests also get
``None``: the route's own auth dependency will reject them, and leaving the GUC
unset keeps health checks and the login flow working.

The org lookup needs the DB. To avoid a chicken-and-egg (querying memberships
while tenant-scoped), the lookup session runs as *system* — ``get_session``
sees ``None`` because we set the scope only after the lookup returns.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request, Response

    from aegis.api.auth import CurrentUser
    from aegis.api.settings import APISettings


def _resolve_user(request: "Request",
                  settings: "APISettings") -> "CurrentUser | None":
    """Resolve the caller the same way the route dependencies do.

    Bearer token wins over the session cookie (matching ``get_current_user``).
    Returns ``None`` when no credential is present or it fails to validate —
    the downstream auth dependency still gates the actual route.
    """
    from aegis.api.auth import _resolve_from_cookie, _resolve_from_token
    try:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            return _resolve_from_token(token, settings)
        cookie = request.cookies.get(settings.api_session_cookie_name)
        if cookie:
            return _resolve_from_cookie(cookie, settings)
    except Exception:
        return None
    return None


def _accessible_org_ids(user: "CurrentUser") -> list[str] | None:
    """Distinct org ids for the caller's member projects, or ``None``.

    ``None`` (full access) for system principals and for callers with no
    memberships — the latter can't see any tenant rows anyway, and an empty
    GUC is the documented system value, so we use ``None`` to mean "let auth
    decide" rather than risk an over-broad empty-list edge. Read-side RLS is
    belt-and-suspenders behind the route auth dependency.

    Runs one short-lived *system* session (tenant scope is still ``None`` at
    this point, so ``get_session`` leaves the GUC empty and the query sees all
    rows it needs to resolve the membership -> org mapping).
    """
    if user.is_system:
        return None
    project_ids = list(user.project_memberships)
    if not project_ids:
        return None
    from sqlalchemy import select

    from aegis.db.models import Project
    from aegis.db.session import get_session
    with get_session() as sess:
        rows = sess.execute(
            select(Project.org_id)
            .where(Project.id.in_(project_ids))
            .distinct()
        ).scalars().all()
    orgs = [o for o in rows if o]
    return orgs or None


def tenant_middleware(settings: "APISettings") -> Callable:
    """Return an ASGI middleware closure that pins the request's tenant scope."""

    async def middleware(
        request: "Request",
        call_next: Callable[["Request"], Awaitable["Response"]],
    ) -> "Response":
        from aegis.db.session import reset_current_tenants, set_current_tenants

        org_ids: list[str] | None = None
        user = _resolve_user(request, settings)
        if user is not None:
            try:
                org_ids = _accessible_org_ids(user)
            except Exception:
                # The org lookup needs a configured DB. If it isn't available
                # (no engine / DB down), fall back to system scope rather than
                # failing the request: RLS is defense-in-depth *behind* the
                # route's own auth dependency, which still gates access. On
                # Postgres an unset GUC only forgoes the extra DB-layer filter.
                org_ids = None
        token = set_current_tenants(org_ids)
        try:
            return await call_next(request)
        finally:
            reset_current_tenants(token)

    return middleware
