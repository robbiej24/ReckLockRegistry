"""Outbound connectors — enforcement layer before external systems (Phase 3D)."""

from __future__ import annotations

from recklock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRequest,
    ConnectorResponse,
    real_connectors_enabled,
    sanitize_for_audit,
)
from recklock.connectors.registry import get_connector, list_connector_descriptors, register
from recklock.connectors.email import EmailConnector
from recklock.connectors.github import GitHubConnector
from recklock.connectors.mock import MockConnector
from recklock.connectors.slack import SlackConnector


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
