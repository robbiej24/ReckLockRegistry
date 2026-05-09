"""Outbound connectors — enforcement layer before external systems (Phase 3D)."""

from __future__ import annotations

from agenttrust.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRequest,
    ConnectorResponse,
    real_connectors_enabled,
    sanitize_for_audit,
)
from agenttrust.connectors.registry import get_connector, list_connector_descriptors, register
from agenttrust.connectors.email import EmailConnector
from agenttrust.connectors.github import GitHubConnector
from agenttrust.connectors.mock import MockConnector
from agenttrust.connectors.slack import SlackConnector


def _install_defaults() -> None:
    for c in (MockConnector(), GitHubConnector(), SlackConnector(), EmailConnector()):
        register(c)


_install_defaults()

__all__ = [
    "BaseConnector",
    "ConnectorConfig",
    "ConnectorRequest",
    "ConnectorResponse",
    "EmailConnector",
    "GitHubConnector",
    "MockConnector",
    "SlackConnector",
    "get_connector",
    "list_connector_descriptors",
    "real_connectors_enabled",
    "register",
    "sanitize_for_audit",
]
