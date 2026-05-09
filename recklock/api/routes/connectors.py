"""Connector discovery & direct invocation API (Phase 3D)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_CONNECTORS_DRY_RUN, PERM_CONNECTORS_EXECUTE, PERM_CONNECTORS_READ
from recklock.connectors.base import ConnectorResponse
from recklock.connectors.invoke import ConnectorHttpError, run_connector
from recklock.connectors.registry import list_connector_descriptors
from recklock.connectors.schemas import ConnectorInvokeBody

router = APIRouter()


@router.get("/", dependencies=[Depends(require_permission(PERM_CONNECTORS_READ))])
def list_connectors() -> list[dict]:
    return list_connector_descriptors()


@router.post("/dry-run", dependencies=[Depends(require_permission(PERM_CONNECTORS_DRY_RUN))])
def dry_run(body: ConnectorInvokeBody) -> ConnectorResponse:
    try:
        return run_connector(body, dry_run=True)
    except ConnectorHttpError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.post("/execute", dependencies=[Depends(require_permission(PERM_CONNECTORS_EXECUTE))])
def execute(body: ConnectorInvokeBody) -> ConnectorResponse:
    try:
        return run_connector(body, dry_run=False)
    except ConnectorHttpError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
