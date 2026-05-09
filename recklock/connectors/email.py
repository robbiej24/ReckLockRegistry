"""Email connector — dry-run validation & guarded send (Phase 3D)."""

from __future__ import annotations

from typing import Any, ClassVar

from recklock.connectors.base import BaseConnector, ConnectorRequest, ConnectorResponse, real_connectors_enabled


class EmailConnector(BaseConnector):
    connector_id: ClassVar[str] = "email"
    name: ClassVar[str] = "Email"
    supported_capabilities: ClassVar[list[str]] = ["send_email"]
    required_permission_scopes: ClassVar[list[str]] = ["notifications.email", "workspace.notify", "*"]

    def validate_config(self, config: dict[str, Any]) -> None:
        to_addr = config.get("to")
        subject = config.get("subject")
        if not to_addr or not isinstance(to_addr, str):
            raise ValueError("send_email requires string 'to'")
        if not subject or not isinstance(subject, str):
            raise ValueError("send_email requires string 'subject'")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResponse:
        self.validate_config(request.config)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=True,
            success=True,
            message="Dry-run: email envelope validated (no SMTP).",
            metadata={"to": request.config.get("to"), "subject": request.config.get("subject")},
        )

    def execute(self, request: ConnectorRequest) -> ConnectorResponse:
        if not real_connectors_enabled():
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=request.action,
                dry_run=False,
                success=False,
                message="Real email execution disabled (set RECKLOCK_ENABLE_REAL_CONNECTORS=true to enable).",
            )
        self.validate_config(request.config)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=False,
            success=False,
            message="SMTP delivery is not wired in this build.",
            metadata={"to": request.config.get("to")},
        )
