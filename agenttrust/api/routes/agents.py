"""Registry agent listing."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from agenttrust.api.deps import get_paths
from agenttrust.api.settings import ResolvedPaths
from agenttrust.auth.dependencies import require_permission
from agenttrust.auth.service import PERM_AGENTS_READ
from agenttrust.gateway import load_registry_index

router = APIRouter()


@router.get("/", dependencies=[Depends(require_permission(PERM_AGENTS_READ))])
def list_agents(paths: Annotated[ResolvedPaths, Depends(get_paths)]) -> list[dict]:
    try:
        idx = load_registry_index(paths.index_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail="registry index not found") from e
    return [a.model_dump(mode="json") for a in idx.agents]


@router.get("/{agent_id}", dependencies=[Depends(require_permission(PERM_AGENTS_READ))])
def get_agent(
    agent_id: str,
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
) -> dict:
    try:
        idx = load_registry_index(paths.index_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail="registry index not found") from e
    for a in idx.agents:
        if a.agent_id == agent_id:
            return a.model_dump(mode="json")
    raise HTTPException(status_code=404, detail=f"Unknown agent_id {agent_id!r}")
