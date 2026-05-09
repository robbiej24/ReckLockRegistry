"""FastAPI dependencies — paths & settings."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from recklock.api.settings import ApiSettings, ResolvedPaths, resolve_paths


def get_settings(request: Request) -> ApiSettings:
    """Use app-local settings when present (tests), else cached env settings."""
    st = getattr(request.app.state, "api_settings", None)
    if isinstance(st, ApiSettings):
        return st
    return _cached_settings()


@lru_cache
def _cached_settings() -> ApiSettings:
    return ApiSettings()


def get_paths(
    settings: Annotated[ApiSettings, Depends(get_settings)],
) -> ResolvedPaths:
    return resolve_paths(settings)


def get_db(request: Request) -> Iterator[Session]:
    """Transactional SQLAlchemy session (commits on success)."""
    factory = getattr(request.app.state, "SessionLocal", None)
    if factory is None:
        raise RuntimeError("SessionLocal missing — application lifespan did not initialize the database.")
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
