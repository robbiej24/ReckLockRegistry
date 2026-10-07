"""Authentication for HTML routes (Bearer header or signed-in cookie)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from recklock.api.deps import get_db
from recklock.auth.models import AuthenticatedPrincipal
from recklock.auth.service import authenticate_api_key, principal_from_key_id, principal_has_permission
from recklock.web.ui_sessions import resolve_ui_session

UI_BEARER_COOKIE = "recklock_ui_bearer"


def _extract_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        tok = auth.removeprefix("Bearer ").strip()
        if tok:
            return tok
    ck = request.cookies.get(UI_BEARER_COOKIE)
    if ck and ck.strip():
        return ck.strip()
    return None


def get_ui_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthenticatedPrincipal:
    token = _extract_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Use Authorization: Bearer or sign in at /ui/sign-in.",
        )
    key_id = resolve_ui_session(token)
    if key_id is not None:
        principal = principal_from_key_id(db, key_id)
    else:
        principal = authenticate_api_key(db, token)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or disabled API key.",
        )
    return principal


def require_ui_permissions(*permissions: str):
    """Require the principal to hold at least one of *permissions*."""

    def _dep(principal: Annotated[AuthenticatedPrincipal, Depends(get_ui_principal)]) -> AuthenticatedPrincipal:
        if any(principal_has_permission(principal, p) for p in permissions):
            return principal
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for this page.",
        )

    return _dep
