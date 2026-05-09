"""Approval workflow API."""

from __future__ import annotations

from pydantic import BaseModel, Field

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from recklock.api.deps import get_db
from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_APPROVALS_APPROVE, PERM_APPROVALS_DENY, PERM_APPROVALS_READ
from recklock.approvals import ApprovalRequest
from recklock.db.repositories import approve_request_db, deny_request_db, list_approvals as list_approvals_db

router = APIRouter()


class ApproverActionBody(BaseModel):
    """Human identity recorded on the approval row (matches CLI ``--approver``)."""

    approver: str = Field(..., min_length=1)


@router.get("/", dependencies=[Depends(require_permission(PERM_APPROVALS_READ))])
def list_approvals(db: Annotated[Session, Depends(get_db)]) -> list[dict]:
    rows = list_approvals_db(db)
    return [r.model_dump(mode="json") for r in rows]


@router.post("/{approval_id}/approve", dependencies=[Depends(require_permission(PERM_APPROVALS_APPROVE))])
def approve(
    approval_id: str,
    body: ApproverActionBody,
    db: Annotated[Session, Depends(get_db)],
) -> ApprovalRequest:
    try:
        rec, _events = approve_request_db(db, approval_id, body.approver)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return rec


@router.post("/{approval_id}/deny", dependencies=[Depends(require_permission(PERM_APPROVALS_DENY))])
def deny(
    approval_id: str,
    body: ApproverActionBody,
    db: Annotated[Session, Depends(get_db)],
) -> ApprovalRequest:
    try:
        rec, _audit = deny_request_db(db, approval_id, body.approver)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return rec
