"""Audit log API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from recklock.api.deps import get_db
from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_AUDIT_APPEND, PERM_AUDIT_READ
from recklock.audit import AuditEvent
from recklock.db.repositories import append_audit_event as persist_audit_event
from recklock.db.repositories import list_audit_events

router = APIRouter()


@router.get("/events", dependencies=[Depends(require_permission(PERM_AUDIT_READ))])
def list_events(db: Annotated[Session, Depends(get_db)]) -> list[dict]:
    events = list_audit_events(db)
    return [e.model_dump(mode="json") for e in events]


@router.post("/events", dependencies=[Depends(require_permission(PERM_AUDIT_APPEND))])
def append_audit_event_route(
    event: AuditEvent,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    sealed = persist_audit_event(db, event)
    return {"event_id": sealed.event_id, "event_hash": sealed.event_hash or ""}
