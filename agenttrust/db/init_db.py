"""Idempotent schema initialization from explicit SQL files."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import Engine

from agenttrust.api.settings import ApiSettings
from agenttrust.db.session import create_engine_from_settings


def _schema_paths() -> tuple[Path, Path]:
    """Resolve ``db/schema.sql`` and ``db/seed.sql`` (development tree or wheel layout)."""
    dev_root = Path(__file__).resolve().parents[2]
    dev_schema = dev_root / "db" / "schema.sql"
    dev_seed = dev_root / "db" / "seed.sql"
    if dev_schema.is_file():
        return dev_schema, dev_seed
    installed_schema = Path(__file__).resolve().parents[2] / "db" / "schema.sql"
    installed_seed = Path(__file__).resolve().parents[2] / "db" / "seed.sql"
    if installed_schema.is_file():
        return installed_schema, installed_seed
    raise FileNotFoundError(
        "Could not locate db/schema.sql (expected project db/ or packaged wheel db/)."
    )


def apply_sql_file(engine: Engine, sql_path: Path) -> None:
    """Execute a SQL file statement-by-statement (handles multiple DDL statements)."""
    raw = sql_path.read_text(encoding="utf-8")
    statements: list[str] = []
    buf: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        buf.append(line)
        if ";" in line:
            chunk = "\n".join(buf)
            for part in chunk.split(";"):
                stmt = part.strip()
                if stmt:
                    statements.append(stmt)
            buf = []
    rest = "\n".join(buf).strip()
    if rest:
        statements.append(rest)

    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def _engine_for_url(database_url: str) -> Engine:
    from sqlalchemy import create_engine as ce

    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = ce(database_url, future=True, connect_args=connect_args)

    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn: object, _connection_record: object) -> None:
        if engine.dialect.name == "sqlite":
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def init_database(
    database_url: str | None = None,
    *,
    settings: ApiSettings | None = None,
    run_seed: bool = True,
) -> None:
    """Create tables if missing. Safe to call repeatedly."""
    if database_url is None:
        if settings is None:
            settings = ApiSettings()
        engine = create_engine_from_settings(settings)
    else:
        engine = _engine_for_url(database_url)

    schema_path, seed_path = _schema_paths()
    apply_sql_file(engine, schema_path)
    if run_seed and seed_path.is_file():
        seed_text = seed_path.read_text(encoding="utf-8")
        executable = any(
            ln.strip() and not ln.strip().startswith("--") for ln in seed_text.splitlines()
        )
        if executable:
            apply_sql_file(engine, seed_path)
    engine.dispose()


def init_engine_schema(engine: Engine, *, run_seed: bool = False) -> None:
    """Apply schema (and optional seed) to an existing engine."""
    schema_path, seed_path = _schema_paths()
    apply_sql_file(engine, schema_path)
    if run_seed and seed_path.is_file():
        apply_sql_file(engine, seed_path)
