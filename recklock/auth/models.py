"""Auth domain models for API keys & roles."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AuthRole = Literal["admin", "auditor", "approver", "operator", "developer", "read_only"]

ROLE_VALUES: tuple[str, ...] = (
    "admin",
    "auditor",
    "approver",
    "operator",
    "developer",
    "read_only",
)


class APIKeyRecord(BaseModel):
    """Persisted API key metadata (never includes raw secret material)."""

    key_id: str
    key_hash: str
    name: str
    role: AuthRole
    created_at: datetime
    expires_at: datetime | None = None
    disabled: bool = False


class AuthenticatedPrincipal(BaseModel):
    """Caller identity resolved from a validated API key."""

    key_id: str
    role: AuthRole
    name: str = Field(default="", description="Human label from api_keys.name")
