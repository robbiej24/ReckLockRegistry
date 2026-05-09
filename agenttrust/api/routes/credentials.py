"""Temporary credential broker API (Phase 3E)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from agenttrust.api.deps import get_db, get_paths
from agenttrust.api.settings import ResolvedPaths
from agenttrust.auth.dependencies import require_permission
from agenttrust.auth.models import AuthenticatedPrincipal
from agenttrust.auth.service import (
    PERM_CREDENTIALS_READ,
    PERM_CREDENTIALS_REQUEST,
    PERM_CREDENTIALS_REVOKE,
    PERM_CREDENTIALS_VERIFY,
)
from agenttrust.credentials.broker import issue_credential, revoke_credential, to_response, verify_credential
from agenttrust.credentials import storage as cred_storage
from agenttrust.credentials.models import CredentialIssueResult, CredentialRequest, CredentialResponse
from agenttrust.credentials.models import CredentialVerificationResult
from agenttrust.gateway import load_registry_index
from agenttrust.policy import Policy

router = APIRouter()


class CredentialIssueBody(BaseModel):
    """Policies are evaluated server-side with the persisted registry index."""

    credential: CredentialRequest
    policies: list[Policy] = Field(default_factory=list)


class VerifyBody(BaseModel):
    token: str = Field(..., min_length=1)


class RevokeBody(BaseModel):
    actor: str | None = Field(
        default=None,
        min_length=1,
        description="Optional human identity; defaults to the caller API key name/id.",
    )


def _issued_by(principal: AuthenticatedPrincipal) -> str:
    return principal.name.strip() if principal.name.strip() else principal.key_id


@router.post("/request", response_model=CredentialIssueResult)
def request_credential(
    body: CredentialIssueBody,
    paths: Annotated[ResolvedPaths, Depends(get_paths)],
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[AuthenticatedPrincipal, Depends(require_permission(PERM_CREDENTIALS_REQUEST))],
) -> CredentialIssueResult:
    try:
        index = load_registry_index(paths.index_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail="registry index not found") from e
    return issue_credential(
        db,
        body.credential,
        body.policies,
        registry_root=paths.registry_root,
        registry_index=index,
        issued_by=_issued_by(principal),
    )


@router.post("/verify", response_model=CredentialVerificationResult)
def verify_token(
    body: VerifyBody,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedPrincipal, Depends(require_permission(PERM_CREDENTIALS_VERIFY))],
) -> CredentialVerificationResult:
    return verify_credential(db, body.token)


@router.get("/", response_model=list[CredentialResponse])
def list_credentials(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedPrincipal, Depends(require_permission(PERM_CREDENTIALS_READ))],
) -> list[CredentialResponse]:
    rows = cred_storage.list_credentials(db)
    return [to_response(r) for r in rows]


@router.post("/{credential_id}/revoke", status_code=204)
def revoke(
    credential_id: str,
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[AuthenticatedPrincipal, Depends(require_permission(PERM_CREDENTIALS_REVOKE))],
    body: RevokeBody = RevokeBody(),
) -> None:
    actor = body.actor or _issued_by(principal)
    try:
        revoke_credential(db, credential_id, actor_id=actor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
