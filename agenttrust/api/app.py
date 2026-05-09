"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from agenttrust.api.routes import (
    agents,
    approvals,
    audit,
    connectors,
    credentials,
    execution,
    health,
    observation,
    policies,
    trust,
)
from agenttrust.web.routes import router as web_router
from agenttrust.api.settings import ApiSettings
from agenttrust.db.session import create_engine_from_settings


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    resolved = getattr(app.state, "api_settings", None)
    settings = resolved if isinstance(resolved, ApiSettings) else ApiSettings()
    engine = create_engine_from_settings(settings)
    app.state.engine = engine
    app.state.SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    yield
    engine.dispose()


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    """Build the ASGI app. Pass *settings* in tests; otherwise env / cwd defaults apply."""
    app = FastAPI(
        title="ReckLock Registry API",
        version="0.1.0",
        lifespan=_lifespan,
    )
    app.state.api_settings = settings if settings is not None else ApiSettings()

    app.include_router(health.router, tags=["health"])
    app.include_router(agents.router, prefix="/agents", tags=["agents"])
    app.include_router(policies.router, prefix="/policies", tags=["policies"])
    app.include_router(execution.router, prefix="/execution", tags=["execution"])
    app.include_router(connectors.router, prefix="/connectors", tags=["connectors"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    app.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
    app.include_router(trust.router, prefix="/trust", tags=["trust"])
    app.include_router(credentials.router, prefix="/credentials", tags=["credentials"])
    app.include_router(observation.router, tags=["observation"])

    web_static = Path(__file__).resolve().parent.parent / "web" / "static"
    app.mount("/ui/static", StaticFiles(directory=str(web_static)), name="ui_static")
    app.include_router(web_router)
    return app


# Uvicorn default import target — uses environment-driven settings via deps.
app = create_app()


def reset_cached_settings_for_tests() -> None:
    """Clear lru_cache between tests if env changed."""
    from agenttrust.api.deps import _cached_settings

    _cached_settings.cache_clear()
