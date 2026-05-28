"""Liveness / readiness."""

from __future__ import annotations

import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "env": os.environ.get("AEGIS_ENV", "dev"),
        "db_configured": bool(os.environ.get("AEGIS_DB_URL")),
    }
