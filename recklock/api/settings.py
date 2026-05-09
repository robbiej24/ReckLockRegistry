"""Runtime configuration for the ReckLock Registry API server."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from recklock.audit import DEFAULT_AUDIT_LOG_PATH
from recklock.constants import (
    DEFAULT_APPROVAL_LOG_PATH,
    DEFAULT_EVIDENCE_DIR,
    DEFAULT_INDEX_PATH,
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_TRUST_PROFILES_PATH,
)

# Prefer RECKLOCK_*; mirror legacy AGENTTRUST_* and RECKLOCKBLOCK_* when the new name is absent.
for _k, _v in list(os.environ.items()):
    if not _k.startswith("AGENTTRUST_"):
        continue
    _dest = "RECKLOCK_" + _k[len("AGENTTRUST_") :]
    if _dest not in os.environ:
        os.environ[_dest] = _v

for _k, _v in list(os.environ.items()):
    if not _k.startswith("RECKLOCKBLOCK_"):
        continue
    _dest = "RECKLOCK_" + _k[len("RECKLOCKBLOCK_") :]
    if _dest not in os.environ:
        os.environ[_dest] = _v


class ApiSettings(BaseSettings):
    """Resolved from environment with prefix ``RECKLOCK_``."""

    model_config = SettingsConfigDict(
        env_prefix="RECKLOCK_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="sqlite:///./recklock.local.db",
        description="SQLAlchemy URL (override with DATABASE_URL or RECKLOCK_DATABASE_URL).",
    )
    env: str = Field(
        default="development",
        description="Deployment environment label (RECKLOCK_ENV).",
    )
    api_host: str = Field(
        default="127.0.0.1",
        description="Default bind address for ``recklock-registry serve`` (RECKLOCK_API_HOST).",
    )
    api_port: int = Field(
        default=8080,
        description="Default TCP port for ``recklock-registry serve`` (RECKLOCK_API_PORT).",
    )
    secret_key: str | None = Field(
        default=None,
        description="Optional signing secret reserved for future use (RECKLOCK_SECRET_KEY).",
    )
    registry_root: Path = Field(
        default_factory=lambda: Path.cwd(),
        description="Working root for registry paths & manifest resolution.",
    )
    index_path: Path | None = Field(
        default=None,
        description="Path to registry/index.json (relative paths resolve against registry_root).",
    )
    audit_log_path: Path | None = Field(
        default=None,
        description="Append-only audit NDJSON log.",
    )
    approval_log_path: Path | None = Field(
        default=None,
        description="Approval lifecycle JSONL store.",
    )
    trust_profiles_path: Path | None = Field(
        default=None,
        description="Trust profile snapshots JSONL.",
    )
    incidents_path: Path | None = Field(
        default=None,
        description="Incident log JSONL.",
    )
    evidence_dir: Path | None = Field(
        default=None,
        description="Evidence directory for discovery exports & passive telemetry (Phase 4A).",
    )
    observation_mode: bool = Field(
        default=False,
        description="When True, API telemetry endpoints persist events (RECKLOCK_OBSERVATION_MODE).",
    )

    def resolve_under_root(self, path: Path | None, default_relative: str | Path) -> Path:
        """Join relative paths to registry_root; leave absolute paths unchanged."""
        if path is None:
            rel = Path(default_relative)
        else:
            rel = Path(path)
        if rel.is_absolute():
            return rel.resolve()
        return (self.registry_root / rel).resolve()


class ResolvedPaths(BaseModel):
    """Concrete filesystem targets for one server instance."""

    registry_root: Path
    index_path: Path
    audit_log_path: Path
    approval_log_path: Path
    trust_profiles_path: Path
    incidents_path: Path
    evidence_dir: Path


def resolve_paths(settings: ApiSettings) -> ResolvedPaths:
    root = settings.registry_root.resolve()
    return ResolvedPaths(
        registry_root=root,
        index_path=settings.resolve_under_root(settings.index_path, DEFAULT_INDEX_PATH),
        audit_log_path=settings.resolve_under_root(settings.audit_log_path, DEFAULT_AUDIT_LOG_PATH),
        approval_log_path=settings.resolve_under_root(
            settings.approval_log_path, DEFAULT_APPROVAL_LOG_PATH
        ),
        trust_profiles_path=settings.resolve_under_root(
            settings.trust_profiles_path, DEFAULT_TRUST_PROFILES_PATH
        ),
        incidents_path=settings.resolve_under_root(settings.incidents_path, DEFAULT_INCIDENTS_PATH),
        evidence_dir=settings.resolve_under_root(settings.evidence_dir, DEFAULT_EVIDENCE_DIR),
    )
