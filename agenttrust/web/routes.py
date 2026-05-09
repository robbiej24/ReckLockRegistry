"""Server-rendered operational dashboard routes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from agenttrust.api.deps import get_db
from agenttrust.auth.models import AuthenticatedPrincipal
from agenttrust.auth.service import (
    PERM_AGENTS_READ,
    PERM_APPROVALS_APPROVE,
    PERM_APPROVALS_DENY,
    PERM_APPROVALS_READ,
    PERM_AUDIT_READ,
    PERM_CREDENTIALS_READ,
    PERM_EXECUTION_REQUEST,
    PERM_POLICIES_EVALUATE,
    PERM_TRUST_READ,
    authenticate_api_key,
    principal_has_permission,
)
from agenttrust.credentials.models import TemporaryCredential
from agenttrust.credentials.storage import list_credentials as list_credentials_db
from agenttrust.db.repositories import (
    approve_request_db,
    count_audit_events,
    deny_request_db,
    list_agents,
    list_approvals,
    list_audit_events_recent,
    list_execution_pairs_recent,
    list_policies,
    list_trust_profiles,
)
from agenttrust.web.deps import UI_BEARER_COOKIE, get_ui_principal, require_ui_permissions

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(prefix="/ui", tags=["ui"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mask_token_hash(digest: str) -> str:
    if not digest:
        return "—"
    if len(digest) <= 16:
        return "hash on file"
    return f"{digest[:12]}…"


def _credential_status_row(cred: Any, *, now: datetime) -> str:
    if not isinstance(cred, TemporaryCredential):
        return str(getattr(cred, "status", ""))
    if cred.status == "revoked":
        return "revoked"
    if cred.status != "active":
        return cred.status
    if cred.expires_at < now:
        return "expired"
    return "active"


def _nav_context(principal: AuthenticatedPrincipal, nav_active: str) -> dict[str, Any]:
    return {
        "principal": principal,
        "nav_active": nav_active,
        "can_agents": principal_has_permission(principal, PERM_AGENTS_READ),
        "can_audit": principal_has_permission(principal, PERM_AUDIT_READ),
        "can_approvals": principal_has_permission(principal, PERM_APPROVALS_READ),
        "can_trust": principal_has_permission(principal, PERM_TRUST_READ),
        "can_credentials": principal_has_permission(principal, PERM_CREDENTIALS_READ),
        "can_executions": principal_has_permission(principal, PERM_EXECUTION_REQUEST)
        or principal_has_permission(principal, PERM_AUDIT_READ)
        or principal_has_permission(principal, PERM_AGENTS_READ),
        "can_approve_action": principal_has_permission(principal, PERM_APPROVALS_APPROVE),
        "can_deny_action": principal_has_permission(principal, PERM_APPROVALS_DENY),
    }


@router.get("/sign-in")
def sign_in_page(request: Request) -> Any:
    return templates.TemplateResponse(request, "sign_in.html", {"title": "Sign in", "error": None})


@router.post("/sign-in")
def sign_in_submit(
    request: Request,
    db: Session = Depends(get_db),
    token: str = Form(""),
) -> Any:
    raw = token.strip()
    if not raw:
        return templates.TemplateResponse(
            request,
            "sign_in.html",
            {"title": "Sign in", "error": "API key is required."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    principal = authenticate_api_key(db, raw)
    if principal is None:
        return templates.TemplateResponse(
            request,
            "sign_in.html",
            {"title": "Sign in", "error": "Invalid, expired, or disabled API key."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    resp = RedirectResponse(url="/ui/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        UI_BEARER_COOKIE,
        value=raw,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,
        secure=False,
    )
    return resp


@router.post("/sign-out")
def sign_out() -> RedirectResponse:
    resp = RedirectResponse(url="/ui/sign-in", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(UI_BEARER_COOKIE)
    return resp


@router.get("/")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(get_ui_principal),
) -> Any:
    now = _utc_now()
    ctx: dict[str, Any] = {
        "title": "Dashboard",
        **_nav_context(principal, "dashboard"),
        "counts": {},
        "policy_count": None,
        "high_risk_agent_ids": [],
    }
    if principal_has_permission(principal, PERM_AGENTS_READ):
        ctx["counts"]["agents"] = len(list_agents(db))
    if principal_has_permission(principal, PERM_TRUST_READ):
        profs = list_trust_profiles(db)
        risky = [p.agent_id for p in profs if p.score_band in ("high_risk", "critical_risk")]
        ctx["high_risk_agent_ids"] = sorted(risky)
        ctx["counts"]["high_risk_agents"] = len(risky)
    if principal_has_permission(principal, PERM_AUDIT_READ):
        ctx["counts"]["audit_events"] = count_audit_events(db)
    if principal_has_permission(principal, PERM_APPROVALS_READ):
        ctx["counts"]["pending_approvals"] = sum(1 for a in list_approvals(db) if a.status == "pending")
    if principal_has_permission(principal, PERM_CREDENTIALS_READ):
        creds = list_credentials_db(db)
        active = 0
        for c in creds:
            if _credential_status_row(c, now=now) == "active":
                active += 1
        ctx["counts"]["active_credentials"] = active
    if principal_has_permission(principal, PERM_POLICIES_EVALUATE):
        ctx["policy_count"] = len(list_policies(db))
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@router.get("/agents")
def ui_agents(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_AGENTS_READ)),
) -> Any:
    rows = list_agents(db)
    return templates.TemplateResponse(
        request,
        "agents.html",
        {
            "title": "Agents",
            **_nav_context(principal, "agents"),
            "agents": rows,
        },
    )


@router.get("/audit")
def ui_audit(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_AUDIT_READ)),
) -> Any:
    events = list_audit_events_recent(db, limit=100)
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "title": "Audit events",
            **_nav_context(principal, "audit"),
            "events": events,
        },
    )


@router.get("/approvals")
def ui_approvals(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_APPROVALS_READ)),
    done: str | None = None,
    err: str | None = None,
) -> Any:
    pending = [a for a in list_approvals(db) if a.status == "pending"]
    return templates.TemplateResponse(
        request,
        "approvals.html",
        {
            "title": "Approvals",
            **_nav_context(principal, "approvals"),
            "pending": pending,
            "flash_done": done == "1",
            "flash_error": err,
        },
    )


@router.post("/approvals/{approval_id}/approve")
def ui_approve(
    approval_id: str,
    db: Session = Depends(get_db),
    _principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_APPROVALS_APPROVE)),
    approver: str = Form(...),
) -> RedirectResponse:
    try:
        approve_request_db(db, approval_id, approver.strip())
    except ValueError as e:
        q = quote(str(e), safe="")
        return RedirectResponse(
            url=f"/ui/approvals?err={q}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url="/ui/approvals?done=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/approvals/{approval_id}/deny")
def ui_deny(
    approval_id: str,
    db: Session = Depends(get_db),
    _principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_APPROVALS_DENY)),
    approver: str = Form(...),
) -> RedirectResponse:
    try:
        deny_request_db(db, approval_id, approver.strip())
    except ValueError as e:
        q = quote(str(e), safe="")
        return RedirectResponse(
            url=f"/ui/approvals?err={q}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url="/ui/approvals?done=1", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/trust")
def ui_trust(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_TRUST_READ)),
) -> Any:
    profiles = list_trust_profiles(db)
    return templates.TemplateResponse(
        request,
        "trust.html",
        {
            "title": "Trust profiles",
            **_nav_context(principal, "trust"),
            "profiles": profiles,
        },
    )


@router.get("/credentials")
def ui_credentials(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_ui_permissions(PERM_CREDENTIALS_READ)),
) -> Any:
    now = _utc_now()
    creds = list_credentials_db(db)
    rows: list[dict[str, Any]] = []
    for c in creds:
        rows.append(
            {
                "credential_id": c.credential_id,
                "agent_id": c.agent_id,
                "issued_at": c.issued_at,
                "expires_at": c.expires_at,
                "scopes": c.scopes,
                "resource": c.resource,
                "environment": c.environment,
                "issued_by": c.issued_by,
                "display_status": _credential_status_row(c, now=now),
                "token_fingerprint": _mask_token_hash(c.token_hash),
            }
        )
    return templates.TemplateResponse(
        request,
        "credentials.html",
        {
            "title": "Credentials",
            **_nav_context(principal, "credentials"),
            "credentials": rows,
        },
    )


@router.get("/executions")
def ui_executions(
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(
        require_ui_permissions(PERM_AGENTS_READ, PERM_AUDIT_READ, PERM_EXECUTION_REQUEST)
    ),
) -> Any:
    pairs = list_execution_pairs_recent(db, limit=50)
    return templates.TemplateResponse(
        request,
        "executions.html",
        {
            "title": "Executions",
            **_nav_context(principal, "executions"),
            "pairs": pairs,
        },
    )
