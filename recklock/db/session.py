"""Engine and session factory."""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from recklock.api.settings import ApiSettings


def effective_database_url(settings: ApiSettings) -> str:
    """Prefer plain ``DATABASE_URL``, then prefixed env, then configured default."""
    return (
        os.environ.get("DATABASE_URL")
        or os.environ.get("RECKLOCK_DATABASE_URL")
        or os.environ.get("RECKLOCKBLOCK_DATABASE_URL")
        or os.environ.get("AGENTTRUST_DATABASE_URL")
        or settings.database_url
    )


def create_engine_from_settings(settings: ApiSettings) -> Engine:
    url = effective_database_url(settings)
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(url, future=True, connect_args=connect_args)

    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn: Any, _connection_record: Any) -> None:
        if engine.dialect.name == "sqlite":
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine
