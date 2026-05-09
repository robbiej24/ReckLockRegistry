"""Gateway execution API."""

from __future__ import annotations

from pydantic import BaseModel, Field

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from recklock.api.deps import get_db, get_paths
from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_EXECUTION_REQUEST
from recklock.api.settings import ResolvedPaths
from recklock.db.repositories import append_audit_event as persist_audit_event
from recklock.db.repositories import store_execution_request, store_execution_response
from recklock.gateway import ExecutionRequest, ExecutionResponse, execute_request, load_registry_index
from recklock.policy import Policy

router = APIRouter()


class ExecutionBody(BaseModel):
    request: ExecutionRequest
    policies: list[Policy] = Field(default_factory=list)


class ExecutionApiResponse(BaseModel):
    """Gateway outcome plus sealed audit hashes (same information as CLI JSON)."""

    response: ExecutionResponse
    appended_audit_event_hashes: list[str]


@router.post("/request", dependencies=[Depends(require_permission(PERM_EXECUTION_REQUEST))])
def run_execution(
    body: ExecutionBody,
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
    db: Annotated[Session, Depends(get_db)],
) -> ExecutionApiResponse:
    store_execution_request(db, body.request)
    index = load_registry_index(paths.index_path)
    outcome = execute_request(
        body.request,
        body.policies,
        index,
        registry_root=paths.registry_root,
        approval_log_path=paths.approval_log_path,
        db_session=db,
    )
    hashes: list[str] = []
    sealed = persist_audit_event(db, outcome.audit_event)
    hashes.append(sealed.event_hash or "")
    for approval_ev in outcome.approval_audit_events:
        sealed_ap = persist_audit_event(db, approval_ev)
        hashes.append(sealed_ap.event_hash or "")
    store_execution_response(
        db,
        request_id=body.request.request_id,
        response=outcome.response,
        audit_event_ids=hashes,
    )
    return ExecutionApiResponse(response=outcome.response, appended_audit_event_hashes=hashes)
