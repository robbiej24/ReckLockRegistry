"""API key authentication & role-based access control (Phase 3C)."""

from __future__ import annotations

from agenttrust.auth.dependencies import require_permission
from agenttrust.auth.models import APIKeyRecord, AuthRole, AuthenticatedPrincipal
from agenttrust.auth.service import (
    create_api_key,
    hash_api_key,
    permissions_for_role,
    principal_has_permission,
)

__all__ = [
    "APIKeyRecord",
    "AuthRole",
    "AuthenticatedPrincipal",
    "create_api_key",
    "hash_api_key",
    "permissions_for_role",
    "principal_has_permission",
    "require_permission",
]
