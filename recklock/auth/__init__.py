"""API key authentication & role-based access control (Phase 3C)."""

from __future__ import annotations

from recklock.auth.dependencies import require_permission
from recklock.auth.models import APIKeyRecord, AuthRole, AuthenticatedPrincipal
from recklock.auth.service import (
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
