"""Slack connector — message dry-run & guarded send (Phase 3D)."""

from __future__ import annotations

from typing import Any, ClassVar

from recklock.connectors.base import BaseConnector, ConnectorRequest, ConnectorResponse, real_connectors_enabled


class SlackConnector(BaseConnector):
    connector_id: ClassVar[str] = "slack"
    name: ClassVar[str] = "Slack"
    supported_capabilities: ClassVar[list[str]] = ["send_message"]
    required_permission_scopes: ClassVar[list[str]] = ["integrations.slack", "workspace.notify", "*"]

    def validate_config(self, config: dict[str, Any]) -> None:
        channel = config.get("channel")
        text = config.get("text")
        if not channel or not isinstance(channel, str):
            raise ValueError("send_message requires string 'channel'")
        if text is None or (isinstance(text, str) and not text.strip()):
            raise ValueError("send_message requires non-empty 'text'")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResponse:
        self.validate_config(request.config)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=True,
            success=True,
            message="Dry-run: Slack message validated (no network I/O).",
            metadata={"channel": request.config.get("channel")},
        )

    def execute(self, request: ConnectorRequest) -> ConnectorResponse:
        if not real_connectors_enabled():
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=request.action,
                dry_run=False,
                success=False,
                message="Real Slack execution disabled (set RECKLOCK_ENABLE_REAL_CONNECTORS=true to enable).",
            )
        self.validate_config(request.config)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=False,
            success=False,
            message="Slack Web API execution is not wired in this build.",
            metadata={"channel": request.config.get("channel")},
        )
