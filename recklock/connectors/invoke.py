"""Shared connector invocation for API & CLI (Phase 3D)."""

from __future__ import annotations

from recklock.connectors.base import ConnectorRequest, ConnectorResponse
from recklock.connectors.registry import get_connector
from recklock.connectors.schemas import ConnectorInvokeBody


class ConnectorHttpError(Exception):
    """Maps to HTTP status codes when raised from the REST layer."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def run_connector(body: ConnectorInvokeBody, *, dry_run: bool) -> ConnectorResponse:
    conn = get_connector(body.connector_id)
    if conn is None:
        raise ConnectorHttpError(404, f"Unknown connector_id {body.connector_id!r}")

    req_scopes = set(conn.required_permission_scopes)
    if "*" not in req_scopes and body.permission_scope not in req_scopes:
        raise ConnectorHttpError(
            400,
            (
                f"permission_scope {body.permission_scope!r} not permitted "
                f"(requires one of {sorted(req_scopes)})"
            ),
        )

    if body.action not in conn.supported_capabilities:
        raise ConnectorHttpError(
            400,
            f"Unsupported action {body.action!r} for connector {body.connector_id}",
        )

    cfg = dict(body.config)
    cfg["_validated_action"] = body.action
    try:
        conn.validate_config(cfg)
    except ValueError as exc:
        raise ConnectorHttpError(400, str(exc)) from exc

    cr_req = ConnectorRequest(
        connector_id=body.connector_id,
        action=body.action,
        agent_id=body.agent_id,
        capability=body.capability,
        permission_scope=body.permission_scope,
        config=dict(body.config),
        dry_run=dry_run,
        request_id=None,
    )
    try:
        return conn.dry_run(cr_req) if dry_run else conn.execute(cr_req)
    except ValueError as exc:
        raise ConnectorHttpError(400, str(exc)) from exc
