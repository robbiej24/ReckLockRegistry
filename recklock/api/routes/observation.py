"""Phase 4A observation endpoints — passive telemetry & discovery exports (no enforcement)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from recklock.api.deps import get_paths, get_settings
from recklock.api.settings import ApiSettings, ResolvedPaths
from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_OBSERVATION_APPEND, PERM_OBSERVATION_READ
from recklock.discovery.evidence import build_evidence_report
from recklock.discovery.telemetry import (
    record_agent_error,
    record_agent_external_call,
    record_agent_observation,
)

router = APIRouter()


class ObservationBody(BaseModel):
    agent_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    capability: str | None = None
    permission_scope: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    metadata: dict[str, Any] | None = None


class ErrorBody(BaseModel):
    agent_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    error_type: str = Field(..., min_length=1)
    error_message: str = Field(..., min_length=1)
    metadata: dict[str, Any] | None = None


class ExternalCallBody(BaseModel):
    agent_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    endpoint: str | None = None
    capability: str | None = None
    metadata: dict[str, Any] | None = None


def _events_file(paths: ResolvedPaths) -> Path:
    return paths.evidence_dir / "observation_events.jsonl"


def _discovered_export(paths: ResolvedPaths) -> Path:
    return paths.evidence_dir / "discovered_agents.json"


@router.post(
    "/telemetry/observation",
    dependencies=[Depends(require_permission(PERM_OBSERVATION_APPEND))],
)
def post_observation(
    body: ObservationBody,
    settings: Annotated[ApiSettings, Depends(get_settings)],
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
) -> dict[str, Any]:
    """Append one passive observation row (never blocks callers of instrumented code)."""
    if not settings.observation_mode:
        return {"accepted": False, "reason": "observation_mode_disabled"}
    record_agent_observation(
        body.agent_id,
        body.action,
        capability=body.capability,
        permission_scope=body.permission_scope,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        metadata=body.metadata,
        force=True,
        events_path=_events_file(paths),
    )
    return {"accepted": True}


@router.post(
    "/telemetry/error",
    dependencies=[Depends(require_permission(PERM_OBSERVATION_APPEND))],
)
def post_error(
    body: ErrorBody,
    settings: Annotated[ApiSettings, Depends(get_settings)],
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
) -> dict[str, Any]:
    if not settings.observation_mode:
        return {"accepted": False, "reason": "observation_mode_disabled"}
    record_agent_error(
        body.agent_id,
        body.action,
        body.error_type,
        body.error_message,
        metadata=body.metadata,
        force=True,
        events_path=_events_file(paths),
    )
    return {"accepted": True}


@router.post(
    "/telemetry/external-call",
    dependencies=[Depends(require_permission(PERM_OBSERVATION_APPEND))],
)
def post_external_call(
    body: ExternalCallBody,
    settings: Annotated[ApiSettings, Depends(get_settings)],
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
) -> dict[str, Any]:
    if not settings.observation_mode:
        return {"accepted": False, "reason": "observation_mode_disabled"}
    record_agent_external_call(
        body.agent_id,
        body.provider,
        endpoint=body.endpoint,
        capability=body.capability,
        metadata=body.metadata,
        force=True,
        events_path=_events_file(paths),
    )
    return {"accepted": True}


@router.get(
    "/evidence/report",
    dependencies=[Depends(require_permission(PERM_OBSERVATION_READ))],
)
def get_evidence_report(
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
    days: int = 7,
) -> dict[str, Any]:
    report = build_evidence_report(days=days, events_path=_events_file(paths))
    return report.as_dict()


@router.get(
    "/discovery/candidates",
    dependencies=[Depends(require_permission(PERM_OBSERVATION_READ))],
)
def get_discovery_candidates(
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
) -> dict[str, Any]:
    path = _discovered_export(paths)
    if not path.is_file():
        return {"candidates": [], "note": "Run ``recklock-registry discover-agents`` to populate evidence/discovered_agents.json."}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"cannot read discovery export: {exc}") from exc
    if isinstance(doc, dict):
        return doc
    return {"candidates": doc}
