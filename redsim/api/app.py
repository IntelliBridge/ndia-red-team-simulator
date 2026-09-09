"""FastAPI app factory."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redsim import __version__
from redsim.api.settings import APISettings, load_settings
from redsim.api.v1 import (
    artifacts,
    attacks,
    audit,
    auth_profiles,
    batches,
    compare,
    datasets,
    defenses,
    exports,
    findings,
    health,
    integrations,
    llm,
    logs,
    ml_capabilities,
    ml_findings,
    models,
    models_bulk,
    org_cost,
    projects,
    reports,
    runs,
    runs_cancel,
    scanners,
    targets,
    verify,
)


def create_app(settings: APISettings | None = None) -> FastAPI:
    settings = settings or load_settings()

    app = FastAPI(
        title="Redsim API",
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
                       "X-Redsim-Request-ID"],
        expose_headers=["X-Redsim-Request-ID"],
    )

    # Phase 6: pin the request's tenant scope (accessible org ids) so Postgres
    # RLS isolates rows per Organization. Registered before CSRF/rate-limit so
    # it ends up *inner* (Starlette runs the last-added middleware outermost):
    # the scope is set just around route handling and reset right after, and a
    # rejected CSRF / rate-limit request never opens a tenant-scoped session.
    # Phase B (wave B2, reports-compare-weights): ``Idempotency-Key`` on the mutating
    # ML routes. Added first so it runs innermost, inside the tenant scope.
    from redsim.api.middleware.idempotency import IdempotencyMiddleware
    app.add_middleware(IdempotencyMiddleware, settings=settings)

    from redsim.api.middleware.tenant import tenant_middleware
    app.middleware("http")(tenant_middleware(settings))

    # F14b: double-submit CSRF on cookie-authenticated mutations.
    from redsim.api.middleware.csrf import csrf_middleware
    app.middleware("http")(csrf_middleware(settings))

    # Rate-limit middleware on write routes.
    from redsim.api.middleware.rate_limit import rate_limit_middleware
    app.middleware("http")(rate_limit_middleware(
        user_per_min=settings.rate_limit_per_user_per_min,
        project_per_min=settings.rate_limit_per_project_per_min,
        settings=settings,
    ))

    # Correlation-id propagation + OTel + Prometheus. The direct-mode
    # log-ingest shipper is env-gated (REDSIM_LOG_INGEST_URL) and a no-op
    # otherwise.
    from redsim.observability import (
        configure_log_shipper,
        configure_otel,
        configure_structlog,
        metrics_handler,
        request_id_middleware,
    )
    configure_otel(service_name="redsim-api")
    configure_structlog(service_name="redsim-api")
    configure_log_shipper(service_name="redsim-api")
    app.middleware("http")(request_id_middleware())
    app.get("/metrics")(metrics_handler())

    app.include_router(health.router, prefix="")
    app.include_router(ml_capabilities.router, prefix="/v1")
    app.include_router(attacks.router, prefix="/v1")
    app.include_router(datasets.router, prefix="/v1")
    app.include_router(defenses.router, prefix="/v1")
    app.include_router(models.router, prefix="/v1")
    # Phase B wave B3 (bulk-upload-capacity-cli): POST /v1/models/bulk and GET /v1/ml/capacity, the
    # only router serving those two paths (the B0 stubs left batches.py with the B3 integration).
    app.include_router(models_bulk.router, prefix="/v1")
    app.include_router(artifacts.router, prefix="/v1")
    app.include_router(compare.router, prefix="/v1")
    app.include_router(ml_findings.router, prefix="/v1")
    app.include_router(runs.router, prefix="/v1")
    app.include_router(runs_cancel.router, prefix="/v1")
    app.include_router(findings.router, prefix="/v1")
    app.include_router(audit.router, prefix="/v1")
    app.include_router(reports.router, prefix="/v1")
    app.include_router(exports.router, prefix="/v1")
    app.include_router(scanners.router, prefix="/v1")
    app.include_router(verify.router, prefix="/v1")
    app.include_router(targets.router, prefix="/v1")
    app.include_router(auth_profiles.router, prefix="/v1")
    app.include_router(projects.router, prefix="/v1")
    app.include_router(logs.router, prefix="/v1")
    app.include_router(org_cost.router, prefix="/v1")
    # Phase B routes (docs/plans/12-phase-b-plan.md): mounted as truthful 501 stubs in wave B0, real
    # handlers since waves B2 and B3 (batch campaigns and bulk verify; ATLAS coverage, the roster and
    # the Foundry push; the LLM probes). tests/ml/test_phase_b_stubs.py pins the surface.
    app.include_router(batches.router, prefix="/v1")
    app.include_router(integrations.router, prefix="/v1")
    app.include_router(llm.router, prefix="/v1")

    # WebSocket stream for live UI updates.
    from redsim.api.ws import router as ws_router
    app.include_router(ws_router, prefix="/v1")

    @app.get("/v1/__settings")
    def _debug_settings() -> dict[str, Any]:
        if settings.is_prod:
            return {"detail": "hidden in production"}
        return {
            "env": settings.env, "auth_mode": settings.auth_mode,
            "cors_origins": settings.cors_origins,
            "db_configured": bool(settings.db_url),
        }

    return app
