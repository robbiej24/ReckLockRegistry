"""Mock connector for tests & safe demos."""

from __future__ import annotations

from typing import Any, ClassVar

from agenttrust.connectors.base import (
    BaseConnector,
    ConnectorRequest,
    ConnectorResponse,
    sanitize_for_audit,
)


class MockConnector(BaseConnector):
    connector_id: ClassVar[str] = "mock"
    name: ClassVar[str] = "Mock"
    supported_capabilities: ClassVar[list[str]] = ["echo", "noop"]
    required_permission_scopes: ClassVar[list[str]] = ["*"]

    def validate_config(self, config: dict[str, Any]) -> None:
        _ = config  # mock accepts any config; echo sanitizes at response time

    def dry_run(self, request: ConnectorRequest) -> ConnectorResponse:
        act = request.action
        if act == "noop":
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=act,
                dry_run=True,
                success=True,
                message="Dry-run: noop",
                metadata={"phase": "dry_run"},
            )
        if act == "echo":
            safe = sanitize_for_audit(dict(request.config))
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=act,
                dry_run=True,
                success=True,
                message="Dry-run: echo",
                metadata={"echo_config": safe},
            )
        raise ValueError(f"Unsupported action {act!r}")

    def execute(self, request: ConnectorRequest) -> ConnectorResponse:
        act = request.action
        if act == "noop":
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=act,
                dry_run=False,
                success=True,
                message="Executed noop",
                metadata={"phase": "execute"},
            )
        if act == "echo":
            safe = sanitize_for_audit(dict(request.config))
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=act,
                dry_run=False,
                success=True,
                message="Executed echo",
                metadata={"echo_config": safe},
            )
        raise ValueError(f"Unsupported action {act!r}")
