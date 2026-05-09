"""Shared request bodies for connector HTTP & CLI (Phase 3D)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ConnectorInvokeBody(BaseModel):
    """Wire-format for ``POST /connectors/dry-run`` & ``POST /connectors/execute``."""

    connector_id: str
    action: str
    agent_id: str = Field(default="api", min_length=1)
    capability: str = Field(default="connector.invoke", min_length=1)
    permission_scope: str = Field(default="*", min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
