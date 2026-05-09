"""Connector registry — discovery & lookup."""

from __future__ import annotations

from typing import Any

from agenttrust.connectors.base import BaseConnector


_REGISTRY: dict[str, BaseConnector] = {}


def register(connector: BaseConnector) -> None:
    _REGISTRY[connector.connector_id] = connector


def get_connector(connector_id: str) -> BaseConnector | None:
    return _REGISTRY.get(connector_id)


def list_connector_descriptors() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for c in sorted(_REGISTRY.values(), key=lambda x: x.connector_id):
        rows.append(
            {
                "connector_id": c.connector_id,
                "name": c.name,
                "supported_capabilities": list(c.supported_capabilities),
                "required_permission_scopes": list(c.required_permission_scopes),
            }
        )
    return rows


def all_registered_ids() -> frozenset[str]:
    return frozenset(_REGISTRY.keys())
