"""Pydantic models for the temporary credential broker."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

CredentialStatus = Literal["active", "revoked", "expired"]
IssueOutcome = Literal["issued", "denied", "pending_approval"]


class CredentialRequest(BaseModel):
    """Input describing what temporary credential an agent needs."""

    agent_id: str = Field(..., min_length=1)
    requested_scopes: list[str] = Field(..., min_length=1)
    resource: str = Field(..., min_length=1)
    environment: str = Field(default="default", min_length=1)
    duration_seconds: int | None = Field(default=None, ge=1)
    reason: str | None = None
    request_id: str | None = Field(default=None, min_length=1)

    @field_validator("requested_scopes")
    @classmethod
    def scopes_nonempty_strings(cls, v: list[str]) -> list[str]:
        out = [s.strip() for s in v if str(s).strip()]
        if not out:
            raise ValueError("requested_scopes must contain at least one non-empty scope")
        return out


class TemporaryCredential(BaseModel):
    """Persisted credential metadata (never includes a raw token)."""

    credential_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    issued_at: datetime
    expires_at: datetime
    scopes: list[str]
    resource: str
    environment: str
    issued_by: str = Field(..., min_length=1)
    status: CredentialStatus
    token_hash: str = Field(..., min_length=1)
    metadata: dict[str, Any] | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def ts_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class CredentialResponse(BaseModel):
    """API response for issuance or listing (token only at issuance)."""

    credential_id: str
    token: str | None = None
    expires_at: datetime
    scopes: list[str]
    resource: str
    status: CredentialStatus


class CredentialVerificationResult(BaseModel):
    """Outcome of verifying a bearer token against stored hash & lifecycle."""

    valid: bool
    credential_id: str | None = None
    agent_id: str | None = None
    expires_at: datetime | None = None
    scopes: list[str] | None = None
    resource: str | None = None
    environment: str | None = None
    status: CredentialStatus | None = None
    reason: str | None = None


class CredentialIssueResult(BaseModel):
    """Structured result from :func:`issue_credential`."""

    outcome: IssueOutcome
    reason: str
    credential_id: str | None = None
    token: str | None = None
    expires_at: datetime | None = None
    scopes: list[str] | None = None
    resource: str | None = None
    status: CredentialStatus | None = None
    approval_id: str | None = None


def load_credential_request_yaml(path: Path) -> CredentialRequest:
    """Load a :class:`CredentialRequest` from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("credential request YAML must be a mapping at the top level")
    return CredentialRequest.model_validate(raw)
