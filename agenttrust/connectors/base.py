"""Connector framework — shared models & base class (Phase 3D)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field


class ConnectorConfig(BaseModel):
    """Connector-specific configuration (tokens belong here — never log raw values)."""

    model_config = ConfigDict(extra="allow")


class ConnectorRequest(BaseModel):
    """Normalized invocation passed to ``dry_run`` / ``execute``."""

    connector_id: str
    action: str
    agent_id: str
    capability: str
    permission_scope: str
    config: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    request_id: str | None = None


class ConnectorResponse(BaseModel):
    """Outcome of a connector invocation (safe for audit & API responses)."""

    connector_id: str
    action: str
    dry_run: bool
    success: bool
    message: str
    external_reference: str | None = None
    metadata: dict[str, Any] | None = None


_SECRET_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
)


def sanitize_for_audit(obj: Any) -> Any:
    """Redact likely secret material from nested dict/list structures."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in _SECRET_SUBSTRINGS):
                out[str(k)] = "[redacted]"
            else:
                out[str(k)] = sanitize_for_audit(v)
        return out
    if isinstance(obj, list):
        return [sanitize_for_audit(x) for x in obj]
    return obj


class BaseConnector(ABC):
    """Contract for outbound system connectors."""

    connector_id: ClassVar[str]
    name: ClassVar[str]
    supported_capabilities: ClassVar[list[str]]
    required_permission_scopes: ClassVar[list[str]]

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> None:
        """Raise ``ValueError`` when configuration is unusable."""

    @abstractmethod
    def dry_run(self, request: ConnectorRequest) -> ConnectorResponse:
        """Validate intent without performing irreversible external effects."""

    @abstractmethod
    def execute(self, request: ConnectorRequest) -> ConnectorResponse:
        """Perform the external action when enabled by environment guardrails."""


def real_connectors_enabled() -> bool:
    """Global switch for non-mock external side effects."""
    import os

    return os.environ.get("AGENTTRUST_ENABLE_REAL_CONNECTORS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
