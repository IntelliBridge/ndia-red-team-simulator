"""FastAPI app factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis import __version__
from aegis.api.settings import APISettings, load_settings
from aegis.api.v1 import (
    agents,
    audit,
    auth_profiles,
    exports,
    findings,
    fix,
    health,
    logs,
    projects,
    reports,
    runs,
    runs_cancel,
    scans,
    targets,
    tools,
    verify,
)


def create_app(settings: APISettings | None = None) -> FastAPI:
    settings = settings or load_settings()

    app = FastAPI(
        title="Aegis API",
        version=__version__,
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None if settings.is_prod else "/redoc",
    )

    # F14b: CORS allow_credentials=True is only legal against an
    # explicit, finite origin list. The web origin is added defensively
    # if it's not already in the configured list.
    cors_origins = list(settings.cors_origins or [])
    if settings.web_origin and settings.web_origin not in cors_origins:
        cors_origins.append(settings.web_origin)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type",
                       settings.api_csrf_header_name,
                       "X-Aegis-Request-ID"],
        expose_headers=["X-Aegis-Request-ID"],
    )

    # F14b: double-submit CSRF on cookie-authenticated mutations.
    from aegis.api.middleware.csrf import csrf_middleware
    app.middleware("http")(csrf_middleware(settings))

    # Rate-limit middleware on write routes.
    from aegis.api.middleware.rate_limit import rate_limit_middleware
    app.middleware("http")(rate_limit_middleware(
        user_per_min=settings.rate_limit_per_user_per_min,
        project_per_min=settings.rate_limit_per_project_per_min,
        settings=settings,
    ))

    # Correlation-id propagation + OTel + Prometheus.
    from aegis.observability import (
        configure_otel,
        configure_structlog,
        metrics_handler,
        request_id_middleware,
    )
    configure_otel(service_name="aegis-api")
    configure_structlog()
    app.middleware("http")(request_id_middleware())
    app.get("/metrics")(metrics_handler())

    app.include_router(health.router, prefix="")
    app.include_router(runs.router, prefix="/v1")
    app.include_router(runs_cancel.router, prefix="/v1")
    app.include_router(findings.router, prefix="/v1")
    app.include_router(audit.router, prefix="/v1")
    app.include_router(reports.router, prefix="/v1")
    app.include_router(exports.router, prefix="/v1")
    app.include_router(tools.router, prefix="/v1")
    app.include_router(scans.router, prefix="/v1")
    app.include_router(agents.router, prefix="/v1")
    app.include_router(fix.router, prefix="/v1")
    app.include_router(verify.router, prefix="/v1")
    app.include_router(targets.router, prefix="/v1")
    app.include_router(auth_profiles.router, prefix="/v1")
    app.include_router(projects.router, prefix="/v1")
    app.include_router(logs.router, prefix="/v1")

    # GitHub webhook receiver.
    from aegis.integrations.github_webhooks import router as gh_router
    app.include_router(gh_router, prefix="/v1")

    # WebSocket stream for live UI updates.
    from aegis.api.ws import router as ws_router
    app.include_router(ws_router, prefix="/v1")

    @app.get("/v1/__settings")
    def _debug_settings():
        if settings.is_prod:
            return {"detail": "hidden in production"}
        return {
            "env": settings.env, "auth_mode": settings.auth_mode,
            "cors_origins": settings.cors_origins,
            "db_configured": bool(settings.db_url),
        }

    return app
