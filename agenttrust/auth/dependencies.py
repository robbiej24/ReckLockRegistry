"""FastAPI dependencies for Bearer API key auth & RBAC."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from agenttrust.api.deps import get_db
from agenttrust.auth.models import AuthenticatedPrincipal
from agenttrust.auth.service import authenticate_api_key, principal_has_permission


def get_authenticated_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthenticatedPrincipal:
    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header (expected Bearer token).",
        )
    token = auth.removeprefix("Bearer ").strip()
    principal = authenticate_api_key(db, token)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or disabled API key.",
        )
    return principal


def require_permission(permission: str):
    """Return a FastAPI dependency that requires the given permission for the caller's role."""

    def _dep(principal: Annotated[AuthenticatedPrincipal, Depends(get_authenticated_principal)]) -> AuthenticatedPrincipal:
        if not principal_has_permission(principal, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission {permission!r} for role {principal.role!r}.",
            )
        return principal

    return _dep
