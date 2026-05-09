"""Temporary credential issuance with policy, approval, and audit hooks (Phase 3E)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from recklock.approvals import (
    derive_approval_requirements_from_rules,
    deterministic_approval_id,
    is_request_fully_approved,
)
from recklock.audit import AuditEvent
from recklock.credentials.models import (
    CredentialIssueResult,
    CredentialRequest,
    CredentialVerificationResult,
    CredentialResponse,
    TemporaryCredential,
)
from recklock.credentials import storage as cred_storage
from recklock.db.repositories import append_audit_event, create_approval_request_db, load_approvals_map
from recklock.db.repositories import maybe_expire_stale_db
from recklock.manifest import AgentManifest, load_manifest
from recklock.policy import ActionRequest, Policy, collect_matching_rules, evaluate_action
from recklock.registry import IndexAgentEntry, RegistryIndex

CRED_CAPABILITY = "credential.issue"
DEFAULT_TTL_SECONDS = 300
MAX_DURATION_SECONDS = 3600
BROKER_PHASE = "3E"


def scope_key(scopes: list[str]) -> str:
    """Deterministic permission_scope string for policy & approval matching."""
    return ",".join(sorted(scopes))


def hash_token(raw: str) -> str:
    """SHA-256 hex digest of the raw bearer token (matches API key hashing style)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utc(ts: datetime | None) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _effective_request_id(req: CredentialRequest) -> str:
    if req.request_id:
        return req.request_id
    body = json.dumps(
        {
            "agent_id": req.agent_id,
            "environment": req.environment,
            "resource": req.resource,
            "scopes": sorted(req.requested_scopes),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "cr_" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:20]


def _deterministic_event_id(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"evt_{digest[:24]}"


def _clamp_ttl(seconds: int | None) -> int:
    raw = int(seconds) if seconds is not None else DEFAULT_TTL_SECONDS
    return max(1, min(raw, MAX_DURATION_SECONDS))


def _audit_requested(
    *,
    req: CredentialRequest,
    request_id: str,
    evaluated_at: datetime,
    issued_by: str,
) -> AuditEvent:
    # Each issuance attempt must yield a unique audit row id (same logical request_id may retry).
    nonce = secrets.token_hex(8)
    payload_for_id = {
        "agent_id": req.agent_id,
        "request_id": request_id,
        "resource": req.resource,
        "scopes": sorted(req.requested_scopes),
        "subtype": "requested",
        "nonce": nonce,
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=req.agent_id,
        actor_type="system",
        actor_id=issued_by,
        event_type="credential.requested",
        action=CRED_CAPABILITY,
        resource_type="credential_request",
        resource_id=request_id,
        permission_scope=scope_key(req.requested_scopes),
        decision="allowed",
        policy_ids=None,
        metadata={
            "broker_phase": BROKER_PHASE,
            "environment": req.environment,
            "reason": req.reason,
            "attempt_nonce": nonce,
        },
    )


def _audit_denied(
    *,
    req: CredentialRequest,
    request_id: str,
    evaluated_at: datetime,
    issued_by: str,
    reason: str,
    matched_policy_ids: list[str] | None,
) -> AuditEvent:
    payload_for_id = {
        "agent_id": req.agent_id,
        "decision": "denied",
        "reason": reason,
        "request_id": request_id,
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=req.agent_id,
        actor_type="system",
        actor_id=issued_by,
        event_type="credential.denied",
        action=CRED_CAPABILITY,
        resource_type="credential_request",
        resource_id=request_id,
        permission_scope=scope_key(req.requested_scopes),
        decision="denied",
        policy_ids=sorted(matched_policy_ids) if matched_policy_ids else None,
        metadata={"broker_phase": BROKER_PHASE, "detail": reason},
    )


def _audit_issued(
    *,
    req: CredentialRequest,
    credential_id: str,
    evaluated_at: datetime,
    issued_by: str,
    matched_policy_ids: list[str] | None,
) -> AuditEvent:
    payload_for_id = {
        "agent_id": req.agent_id,
        "credential_id": credential_id,
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=req.agent_id,
        actor_type="system",
        actor_id=issued_by,
        event_type="credential.issued",
        action=CRED_CAPABILITY,
        resource_type="temporary_credential",
        resource_id=credential_id,
        permission_scope=scope_key(req.requested_scopes),
        decision="allowed",
        policy_ids=sorted(matched_policy_ids) if matched_policy_ids else None,
        metadata={"broker_phase": BROKER_PHASE, "resource": req.resource},
    )


def _audit_revoked(
    *,
    credential_id: str,
    agent_id: str,
    evaluated_at: datetime,
    actor_id: str,
    permission_scope: str | None,
) -> AuditEvent:
    payload_for_id = {
        "agent_id": agent_id,
        "credential_id": credential_id,
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "subtype": "revoked",
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=agent_id,
        actor_type="human",
        actor_id=actor_id,
        event_type="credential.revoked",
        action=CRED_CAPABILITY,
        resource_type="temporary_credential",
        resource_id=credential_id,
        permission_scope=permission_scope,
        decision="denied",
        policy_ids=None,
        metadata={"broker_phase": BROKER_PHASE},
    )


def _audit_expired(
    *,
    credential_id: str,
    agent_id: str,
    evaluated_at: datetime,
    permission_scope: str | None,
) -> AuditEvent:
    payload_for_id = {
        "agent_id": agent_id,
        "credential_id": credential_id,
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "subtype": "expired",
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=agent_id,
        actor_type="system",
        actor_id="recklock",
        event_type="credential.expired",
        action=CRED_CAPABILITY,
        resource_type="temporary_credential",
        resource_id=credential_id,
        permission_scope=permission_scope,
        decision="denied",
        policy_ids=None,
        metadata={"broker_phase": BROKER_PHASE},
    )


def _resolve_registry(
    req: CredentialRequest,
    registry_root: Path,
    registry_index: RegistryIndex,
) -> tuple[IndexAgentEntry, AgentManifest] | tuple[CredentialIssueResult, list[AuditEvent]]:
    """Return (entry, manifest) or (failure result, audits to persist)."""
    by_id = {a.agent_id: a for a in registry_index.agents}
    entry = by_id.get(req.agent_id)
    if entry is None:
        reason = f"Unknown agent_id {req.agent_id!r}; not present in registry index."
        res = CredentialIssueResult(outcome="denied", reason=reason)
        return res, []

    manifest_path = (registry_root / Path(entry.manifest_path)).resolve()
    if not manifest_path.is_file():
        reason = f"Manifest missing at {manifest_path} (index manifest_path={entry.manifest_path!r})."
        return CredentialIssueResult(outcome="denied", reason=reason), []

    try:
        manifest = load_manifest(manifest_path)
    except (ValidationError, ValueError, OSError) as exc:
        reason = f"Manifest invalid or unreadable at {manifest_path}: {exc}"
        return CredentialIssueResult(outcome="denied", reason=reason), []

    if manifest.agent_id != req.agent_id:
        reason = (
            f"Manifest agent_id mismatch: manifest has {manifest.agent_id!r}, request has {req.agent_id!r}."
        )
        return CredentialIssueResult(outcome="denied", reason=reason), []

    if CRED_CAPABILITY not in manifest.capabilities:
        reason = (
            f"Capability {CRED_CAPABILITY!r} is not declared in the agent manifest "
            f"(declared: {sorted(manifest.capabilities)})."
        )
        return CredentialIssueResult(outcome="denied", reason=reason), []

    for s in req.requested_scopes:
        if s not in manifest.permission_scopes:
            reason = (
                f"Permission scope {s!r} is not declared in the agent manifest "
                f"(declared: {sorted(manifest.permission_scopes)})."
            )
            return CredentialIssueResult(outcome="denied", reason=reason), []

    return (entry, manifest)


def issue_credential(
    session: Session,
    req: CredentialRequest,
    policies: list[Policy],
    *,
    registry_root: Path,
    registry_index: RegistryIndex,
    issued_by: str,
    evaluated_at: datetime | None = None,
) -> CredentialIssueResult:
    """Evaluate policy & approvals, then mint a one-time raw token (hash persisted only)."""
    ts = _utc(evaluated_at)
    expire_credentials(session, now=ts)

    request_id = _effective_request_id(req)
    append_audit_event(
        session,
        _audit_requested(req=req, request_id=request_id, evaluated_at=ts, issued_by=issued_by),
    )

    resolved = _resolve_registry(req, registry_root, registry_index)
    if isinstance(resolved[0], CredentialIssueResult):
        fail, _ = resolved
        append_audit_event(
            session,
            _audit_denied(
                req=req,
                request_id=request_id,
                evaluated_at=ts,
                issued_by=issued_by,
                reason=fail.reason,
                matched_policy_ids=None,
            ),
        )
        return fail

    _entry, manifest = resolved

    action = ActionRequest(
        agent_id=req.agent_id,
        capability=CRED_CAPABILITY,
        permission_scope=scope_key(req.requested_scopes),
        risk_level=manifest.risk_level,
        requires_human_approval=manifest.requires_human_approval,
        environment=req.environment,
        metadata={
            "credential_resource": req.resource,
            "credential_reason": req.reason,
        },
    )
    policy_decision = evaluate_action(action, policies, evaluated_at=ts)

    if policy_decision.decision == "deny":
        append_audit_event(
            session,
            _audit_denied(
                req=req,
                request_id=request_id,
                evaluated_at=ts,
                issued_by=issued_by,
                reason=policy_decision.reason,
                matched_policy_ids=policy_decision.matched_policy_ids,
            ),
        )
        return CredentialIssueResult(
            outcome="denied",
            reason=policy_decision.reason,
            approval_id=None,
        )

    if policy_decision.decision == "require_approval":
        matches = collect_matching_rules(action, policies)
        appr_rules = [r for _, r in matches if r.effect == "require_approval"]
        req_names, min_distinct = derive_approval_requirements_from_rules(appr_rules)
        approval_id = deterministic_approval_id(
            request_id=request_id,
            agent_id=req.agent_id,
            capability=CRED_CAPABILITY,
            permission_scope=scope_key(req.requested_scopes),
        )

        approval_audits: list[AuditEvent] = []
        rows = load_approvals_map(session)
        existing = rows.get(approval_id)
        if existing is not None:
            existing, exp_audit = maybe_expire_stale_db(session, existing, now=ts)
            if exp_audit is not None:
                approval_audits.append(exp_audit)

        matched_ids = (
            sorted(policy_decision.matched_policy_ids) if policy_decision.matched_policy_ids else None
        )

        if existing is not None and existing.status == "approved" and is_request_fully_approved(existing, now=ts):
            for ev in approval_audits:
                append_audit_event(session, ev)
            return _mint_credential(
                session,
                req=req,
                request_id=request_id,
                issued_by=issued_by,
                ts=ts,
                matched_policy_ids=matched_ids,
            )

        if existing is not None and existing.status == "expired":
            reason = f"Approval {existing.approval_id} expired; credential blocked."
            append_audit_event(
                session,
                _audit_denied(
                    req=req,
                    request_id=request_id,
                    evaluated_at=ts,
                    issued_by=issued_by,
                    reason=reason,
                    matched_policy_ids=matched_ids,
                ),
            )
            for ev in approval_audits:
                append_audit_event(session, ev)
            return CredentialIssueResult(outcome="denied", reason=reason, approval_id=approval_id)

        if existing is not None and existing.status == "denied":
            reason = f"Approval {existing.approval_id} was denied."
            append_audit_event(
                session,
                _audit_denied(
                    req=req,
                    request_id=request_id,
                    evaluated_at=ts,
                    issued_by=issued_by,
                    reason=reason,
                    matched_policy_ids=matched_ids,
                ),
            )
            for ev in approval_audits:
                append_audit_event(session, ev)
            return CredentialIssueResult(outcome="denied", reason=reason, approval_id=approval_id)

        if existing is not None and existing.status == "pending":
            reason = f"Awaiting human approval ({existing.approval_id})."
            for ev in approval_audits:
                append_audit_event(session, ev)
            return CredentialIssueResult(
                outcome="pending_approval",
                reason=reason,
                approval_id=approval_id,
            )

        _rec, created_audit = create_approval_request_db(
            session,
            approval_id=approval_id,
            request_id=request_id,
            agent_id=req.agent_id,
            requested_action={
                "capability": CRED_CAPABILITY,
                "permission_scope": scope_key(req.requested_scopes),
                "environment": req.environment,
                "resource": req.resource,
            },
            required_approvers=req_names,
            min_distinct_approvers=min_distinct,
            expires_at=None,
            metadata={
                "matched_rule_ids": policy_decision.matched_rule_ids,
                "policy_decision": policy_decision.decision,
                "policy_reason": policy_decision.reason,
            },
            created_at=ts,
        )
        append_audit_event(session, created_audit)
        for ev in approval_audits:
            append_audit_event(session, ev)
        return CredentialIssueResult(
            outcome="pending_approval",
            reason=policy_decision.reason,
            approval_id=approval_id,
        )

    # allow
    return _mint_credential(
        session,
        req=req,
        request_id=request_id,
        issued_by=issued_by,
        ts=ts,
        matched_policy_ids=sorted(policy_decision.matched_policy_ids)
        if policy_decision.matched_policy_ids
        else None,
    )


def _mint_credential(
    session: Session,
    *,
    req: CredentialRequest,
    request_id: str,
    issued_by: str,
    ts: datetime,
    matched_policy_ids: list[str] | None,
) -> CredentialIssueResult:
    ttl = _clamp_ttl(req.duration_seconds)
    expires = ts + timedelta(seconds=ttl)
    raw = secrets.token_urlsafe(48)
    digest = hash_token(raw)
    cid = "cred_" + secrets.token_hex(12)
    record = TemporaryCredential(
        credential_id=cid,
        agent_id=req.agent_id,
        issued_at=ts,
        expires_at=expires,
        scopes=list(req.requested_scopes),
        resource=req.resource,
        environment=req.environment,
        issued_by=issued_by,
        status="active",
        token_hash=digest,
        metadata={"request_id": request_id, "ttl_seconds": ttl},
    )
    cred_storage.insert_credential(session, record, created_at=ts)
    append_audit_event(
        session,
        _audit_issued(
            req=req,
            credential_id=cid,
            evaluated_at=ts,
            issued_by=issued_by,
            matched_policy_ids=matched_policy_ids,
        ),
    )
    return CredentialIssueResult(
        outcome="issued",
        reason="Credential issued.",
        credential_id=cid,
        token=raw,
        expires_at=expires,
        scopes=list(req.requested_scopes),
        resource=req.resource,
        status="active",
    )


def verify_credential(session: Session, raw_token: str, *, now: datetime | None = None) -> CredentialVerificationResult:
    """Validate raw token against stored hash and lifecycle (constant-time compare)."""
    ts = _utc(now)
    expire_credentials(session, now=ts)
    if not raw_token or not raw_token.strip():
        return CredentialVerificationResult(valid=False, reason="empty token")
    digest = hash_token(raw_token.strip())
    existing = cred_storage.get_by_token_hash(session, digest)
    if existing is None:
        return CredentialVerificationResult(valid=False, reason="unknown or invalid token")
    if existing.expires_at < ts:
        return CredentialVerificationResult(
            valid=False,
            credential_id=existing.credential_id,
            reason="expired",
            status="expired",
        )
    if existing.status == "revoked":
        return CredentialVerificationResult(
            valid=False,
            credential_id=existing.credential_id,
            reason="revoked",
            status="revoked",
        )
    if existing.status == "expired":
        return CredentialVerificationResult(
            valid=False,
            credential_id=existing.credential_id,
            reason="expired",
            status="expired",
        )
    if existing.status != "active":
        return CredentialVerificationResult(valid=False, credential_id=existing.credential_id, reason="inactive")

    # Constant-time compare guard (hash already matched row; mitigates timing on raw string)
    if not hmac.compare_digest(existing.token_hash, digest):
        return CredentialVerificationResult(valid=False, reason="unknown or invalid token")

    return CredentialVerificationResult(
        valid=True,
        credential_id=existing.credential_id,
        agent_id=existing.agent_id,
        expires_at=existing.expires_at,
        scopes=existing.scopes,
        resource=existing.resource,
        environment=existing.environment,
        status="active",
    )


def revoke_credential(
    session: Session,
    credential_id: str,
    *,
    actor_id: str,
    evaluated_at: datetime | None = None,
) -> None:
    """Mark a credential revoked and append audit (idempotent if already terminal)."""
    ts = _utc(evaluated_at)
    rec = cred_storage.get_by_id(session, credential_id)
    if rec is None:
        raise ValueError(f"Unknown credential_id {credential_id!r}.")
    if rec.status != "active":
        raise ValueError(f"Credential {credential_id!r} is not active (status={rec.status!r}).")
    cred_storage.update_status(
        session,
        credential_id,
        "revoked",
        metadata={"revoked_at": ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")},
    )
    append_audit_event(
        session,
        _audit_revoked(
            credential_id=credential_id,
            agent_id=rec.agent_id,
            evaluated_at=ts,
            actor_id=actor_id,
            permission_scope=scope_key(rec.scopes),
        ),
    )


def expire_credentials(session: Session, *, now: datetime | None = None) -> int:
    """Mark overdue active credentials as expired; emit ``credential.expired`` audits."""
    ts = _utc(now)
    ids = cred_storage.iter_active_expired_ids(session, now=ts)
    for cid in ids:
        rec = cred_storage.get_by_id(session, cid)
        if rec is None:
            continue
        cred_storage.update_status(
            session,
            cid,
            "expired",
            metadata={"expired_at": ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")},
        )
        append_audit_event(
            session,
            _audit_expired(
                credential_id=cid,
                agent_id=rec.agent_id,
                evaluated_at=ts,
                permission_scope=scope_key(rec.scopes),
            ),
        )
    return len(ids)


def to_response(record: TemporaryCredential, *, include_token: str | None = None) -> CredentialResponse:
    """Map stored row to API shape (token only immediately after issuance)."""
    return CredentialResponse(
        credential_id=record.credential_id,
        token=include_token,
        expires_at=record.expires_at,
        scopes=record.scopes,
        resource=record.resource,
        status=record.status,
    )
