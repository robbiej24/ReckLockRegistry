"""API key lifecycle, hashing, and role → permission mapping."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import FrozenSet

from sqlalchemy.orm import Session

from agenttrust.auth.models import APIKeyRecord, AuthenticatedPrincipal, AuthRole, ROLE_VALUES

# Permission strings used by route dependencies.
PERM_AGENTS_READ = "agents.read"
PERM_POLICIES_EVALUATE = "policies.evaluate"
PERM_EXECUTION_REQUEST = "execution.request"
PERM_AUDIT_READ = "audit.read"
PERM_AUDIT_APPEND = "audit.append"
PERM_APPROVALS_READ = "approvals.read"
PERM_APPROVALS_APPROVE = "approvals.approve"
PERM_APPROVALS_DENY = "approvals.deny"
PERM_TRUST_READ = "trust.read"
PERM_TRUST_CALCULATE = "trust.calculate"
PERM_CONNECTORS_READ = "connectors.read"
PERM_CONNECTORS_DRY_RUN = "connectors.dry_run"
PERM_CONNECTORS_EXECUTE = "connectors.execute"
PERM_CREDENTIALS_REQUEST = "credentials.request"
PERM_CREDENTIALS_READ = "credentials.read"
PERM_CREDENTIALS_REVOKE = "credentials.revoke"
PERM_CREDENTIALS_VERIFY = "credentials.verify"
PERM_OBSERVATION_APPEND = "observation.append"
PERM_OBSERVATION_READ = "observation.read"

_ALL_PERMISSIONS: FrozenSet[str] = frozenset(
    {
        PERM_AGENTS_READ,
        PERM_POLICIES_EVALUATE,
        PERM_EXECUTION_REQUEST,
        PERM_AUDIT_READ,
        PERM_AUDIT_APPEND,
        PERM_APPROVALS_READ,
        PERM_APPROVALS_APPROVE,
        PERM_APPROVALS_DENY,
        PERM_TRUST_READ,
        PERM_TRUST_CALCULATE,
        PERM_CONNECTORS_READ,
        PERM_CONNECTORS_DRY_RUN,
        PERM_CONNECTORS_EXECUTE,
        PERM_CREDENTIALS_REQUEST,
        PERM_CREDENTIALS_READ,
        PERM_CREDENTIALS_REVOKE,
        PERM_CREDENTIALS_VERIFY,
        PERM_OBSERVATION_APPEND,
        PERM_OBSERVATION_READ,
    }
)


def permissions_for_role(role: AuthRole) -> FrozenSet[str]:
    if role == "admin":
        return _ALL_PERMISSIONS
    if role == "auditor":
        return frozenset(
            {
                PERM_AGENTS_READ,
                PERM_AUDIT_READ,
                PERM_TRUST_READ,
                PERM_CONNECTORS_READ,
                PERM_CREDENTIALS_READ,
                PERM_OBSERVATION_READ,
            }
        )
    if role == "approver":
        return frozenset(
            {
                PERM_APPROVALS_READ,
                PERM_APPROVALS_APPROVE,
                PERM_APPROVALS_DENY,
            }
        )
    if role == "operator":
        return frozenset(
            {
                PERM_EXECUTION_REQUEST,
                PERM_POLICIES_EVALUATE,
                PERM_AGENTS_READ,
                PERM_AUDIT_APPEND,
                PERM_TRUST_CALCULATE,
                PERM_CONNECTORS_READ,
                PERM_CONNECTORS_DRY_RUN,
                PERM_CONNECTORS_EXECUTE,
                PERM_CREDENTIALS_REQUEST,
                PERM_CREDENTIALS_READ,
                PERM_CREDENTIALS_REVOKE,
                PERM_CREDENTIALS_VERIFY,
                PERM_OBSERVATION_APPEND,
                PERM_OBSERVATION_READ,
            }
        )
    if role == "developer":
        return frozenset(
            {
                PERM_AGENTS_READ,
                PERM_POLICIES_EVALUATE,
                PERM_CONNECTORS_READ,
                PERM_CONNECTORS_DRY_RUN,
                PERM_CREDENTIALS_READ,
                PERM_CREDENTIALS_VERIFY,
                PERM_OBSERVATION_APPEND,
                PERM_OBSERVATION_READ,
            }
        )
    if role == "read_only":
        return frozenset({PERM_AGENTS_READ, PERM_OBSERVATION_READ})
    raise ValueError(f"Unknown role {role!r}")


def principal_has_permission(principal: AuthenticatedPrincipal, permission: str) -> bool:
    perms = permissions_for_role(principal.role)
    return permission in perms


def hash_api_key(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    ts = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_raw_api_key() -> tuple[str, str]:
    """Return (key_id, raw_bearer_token) — token embeds key_id for readability."""
    key_id = "k_" + secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    raw = f"atk_{key_id}_{secret}"
    return key_id, raw


def validate_role(role: str) -> AuthRole:
    if role not in ROLE_VALUES:
        raise ValueError(f"Invalid role {role!r}; expected one of {', '.join(ROLE_VALUES)}.")
    return role  # type: ignore[return-value]


def create_api_key(
    session: Session,
    *,
    name: str,
    role: str,
    expires_at: datetime | None = None,
) -> tuple[str, APIKeyRecord]:
    """Persist a new API key; returns (raw_token_once, stored_record)."""
    from agenttrust.db.repositories import insert_api_key_row

    r = validate_role(role)
    key_id, raw = generate_raw_api_key()
    digest = hash_api_key(raw)
    now = _utc_now()
    insert_api_key_row(
        session,
        key_id=key_id,
        key_hash=digest,
        name=name,
        role=r,
        created_at_iso=_iso(now),
        expires_at_iso=_iso(expires_at) if expires_at is not None else None,
        disabled=False,
    )
    record = APIKeyRecord(
        key_id=key_id,
        key_hash=digest,
        name=name,
        role=r,
        created_at=now,
        expires_at=expires_at,
        disabled=False,
    )
    return raw, record


def authenticate_api_key(session: Session, raw_token: str) -> AuthenticatedPrincipal | None:
    """Resolve bearer token to a principal, or None if invalid / disabled / expired."""
    from agenttrust.db.repositories import fetch_api_key_by_hash

    raw = raw_token.strip()
    if not raw:
        return None
    digest = hash_api_key(raw)
    row = fetch_api_key_by_hash(session, digest)
    if row is None:
        return None
    if row.disabled:
        return None
    if row.expires_at is not None and row.expires_at < _utc_now():
        return None
    return AuthenticatedPrincipal(key_id=row.key_id, role=row.role, name=row.name)
