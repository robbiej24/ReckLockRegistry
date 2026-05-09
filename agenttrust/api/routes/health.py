"""Health & readiness probes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness: process is running (no external checks)."""
    return {"status": "ok", "service": "agenttrust-api"}


@router.get("/ready", response_model=None)
def ready(request: Request) -> dict[str, Any] | JSONResponse:
    """Readiness: verify persistence by issuing a trivial DB round-trip."""
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "database_engine_missing"},
        )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "database_unreachable", "detail": str(exc)},
        )
    dialect = getattr(engine.dialect, "name", "unknown")
    return {"status": "ready", "database": dialect}
