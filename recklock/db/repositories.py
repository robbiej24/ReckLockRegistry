"""Repository-style persistence helpers (SQLAlchemy Core, synchronous)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from recklock.auth.models import APIKeyRecord
from recklock.approvals import ApprovalRequest, build_approval_audit_event, is_request_fully_approved
from recklock.audit import AuditEvent, seal_event
from recklock.gateway import ExecutionRequest, ExecutionResponse
from recklock.policy import Policy
from recklock.registry import IndexAgentEntry
from recklock.trust import IncidentRecord, TrustProfile, incidents_for_agent, update_trust_profile
from recklock.db import models as m


def _utc_now(now: datetime | None = None) -> datetime:
    ts = now if now is not None else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _utc_now_iso(dt: datetime | None = None) -> str:
    ts = _utc_now(dt)
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dump_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_json(text_val: str | None, default: Any) -> Any:
    if text_val is None or text_val == "":
        return default
    return json.loads(text_val)


def _audit_row_to_event(row: Any) -> AuditEvent:
    raw = {
        "event_id": row.event_id,
        "timestamp": row.timestamp,
        "agent_id": row.agent_id,
        "actor_type": row.actor_type,
        "actor_id": row.actor_id,
        "event_type": row.event_type,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "permission_scope": row.permission_scope,
        "decision": row.decision,
        "policy_ids": _load_json(row.policy_ids, None),
        "metadata": _load_json(row.metadata, None),
        "previous_event_hash": row.previous_event_hash,
        "event_hash": row.event_hash,
    }
    return AuditEvent.model_validate(raw)


# --- Agents ---


def upsert_agent(session: Session, entry: IndexAgentEntry, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now)
    payload = _dump_json(entry.model_dump(mode="json"))
    conn = session.connection()
    cur = conn.execute(select(m.agents.c.agent_id).where(m.agents.c.agent_id == entry.agent_id)).first()
    if cur is None:
        conn.execute(
            m.agents.insert().values(
                agent_id=entry.agent_id,
                record_json=payload,
                created_at=ts,
                updated_at=ts,
            )
        )
    else:
        conn.execute(
            m.agents.update()
            .where(m.agents.c.agent_id == entry.agent_id)
            .values(record_json=payload, updated_at=ts)
        )


def list_agents(session: Session) -> list[IndexAgentEntry]:
    conn = session.connection()
    rows = conn.execute(select(m.agents.c.record_json).order_by(m.agents.c.agent_id)).fetchall()
    return [IndexAgentEntry.model_validate_json(r.record_json) for r in rows]


def get_agent(session: Session, agent_id: str) -> IndexAgentEntry | None:
    conn = session.connection()
    row = conn.execute(
        select(m.agents.c.record_json).where(m.agents.c.agent_id == agent_id)
    ).first()
    if row is None:
        return None
    return IndexAgentEntry.model_validate_json(row.record_json)


# --- Policies ---


def upsert_policy(session: Session, policy: Policy, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now)
    payload = _dump_json(policy.model_dump(mode="json"))
    conn = session.connection()
    cur = conn.execute(
        select(m.policies.c.policy_id).where(m.policies.c.policy_id == policy.policy_id)
    ).first()
    enabled = 1 if policy.enabled else 0
    if cur is None:
        conn.execute(
            m.policies.insert().values(
                policy_id=policy.policy_id,
                policy_json=payload,
                enabled=enabled,
                created_at=ts,
                updated_at=ts,
            )
        )
    else:
        conn.execute(
            m.policies.update()
            .where(m.policies.c.policy_id == policy.policy_id)
            .values(policy_json=payload, enabled=enabled, updated_at=ts)
        )


def list_policies(session: Session) -> list[Policy]:
    conn = session.connection()
    rows = conn.execute(select(m.policies.c.policy_json).order_by(m.policies.c.policy_id)).fetchall()
    return [Policy.model_validate_json(r.policy_json) for r in rows]


# --- Audit ---


def count_audit_events(session: Session) -> int:
    conn = session.connection()
    n = conn.execute(select(func.count()).select_from(m.audit_events)).scalar_one()
    return int(n)


def list_audit_events(session: Session) -> list[AuditEvent]:
    conn = session.connection()
    rows = conn.execute(
        select(m.audit_events).order_by(m.audit_events.c.created_at, m.audit_events.c.event_id)
    ).fetchall()
    return [_audit_row_to_event(r) for r in rows]


def append_audit_event(
    session: Session,
    event: AuditEvent,
    *,
    force_chain: bool = True,
) -> AuditEvent:
    conn = session.connection()
    rows = conn.execute(
        select(m.audit_events).order_by(m.audit_events.c.created_at, m.audit_events.c.event_id)
    ).fetchall()
    existing = [_audit_row_to_event(r) for r in rows]
    prev_hash = existing[-1].event_hash if existing else None
    if force_chain:
        incoming = event.model_copy(update={"previous_event_hash": None, "event_hash": None})
    else:
        incoming = event
    sealed = seal_event(incoming, previous_event_hash=prev_hash)
    created_at = _utc_now_iso(sealed.timestamp)
    conn.execute(
        m.audit_events.insert().values(
            event_id=sealed.event_id,
            timestamp=_utc_now_iso(sealed.timestamp),
            agent_id=sealed.agent_id,
            actor_type=sealed.actor_type,
            actor_id=sealed.actor_id,
            event_type=sealed.event_type,
            action=sealed.action,
            resource_type=sealed.resource_type,
            resource_id=sealed.resource_id,
            permission_scope=sealed.permission_scope,
            decision=sealed.decision,
            policy_ids=_dump_json(sealed.policy_ids) if sealed.policy_ids is not None else None,
            metadata=_dump_json(sealed.metadata) if sealed.metadata is not None else None,
            previous_event_hash=sealed.previous_event_hash,
            event_hash=sealed.event_hash,
            created_at=created_at,
        )
    )
    return sealed


# --- Approvals ---


def _row_to_approval(row: Any) -> ApprovalRequest:
    raw = {
        "approval_id": row.approval_id,
        "request_id": row.request_id,
        "agent_id": row.agent_id,
        "created_at": row.created_at,
        "status": row.status,
        "requested_action": _load_json(row.requested_action, {}),
        "required_approvers": _load_json(row.required_approvers, []),
        "min_distinct_approvers": row.min_distinct_approvers,
        "approved_by": _load_json(row.approved_by, []),
        "expires_at": row.expires_at,
        "metadata": _load_json(row.metadata, None),
    }
    return ApprovalRequest.model_validate(raw)


def load_approvals_map(session: Session) -> dict[str, ApprovalRequest]:
    conn = session.connection()
    rows = conn.execute(select(m.approvals)).fetchall()
    return {r.approval_id: _row_to_approval(r) for r in rows}


def upsert_approval(session: Session, record: ApprovalRequest, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now)
    conn = session.connection()
    conn.execute(delete(m.approvals).where(m.approvals.c.approval_id == record.approval_id))
    conn.execute(
        m.approvals.insert().values(
            approval_id=record.approval_id,
            request_id=record.request_id,
            agent_id=record.agent_id,
            created_at=_utc_now_iso(record.created_at),
            status=record.status,
            requested_action=_dump_json(record.requested_action),
            required_approvers=_dump_json(record.required_approvers),
            min_distinct_approvers=record.min_distinct_approvers,
            approved_by=_dump_json(record.approved_by),
            expires_at=_utc_now_iso(record.expires_at) if record.expires_at else None,
            metadata=_dump_json(record.metadata) if record.metadata is not None else None,
            updated_at=ts,
        )
    )


def create_approval_request_db(
    session: Session,
    *,
    approval_id: str,
    request_id: str,
    agent_id: str,
    requested_action: dict[str, Any],
    required_approvers: list[str],
    min_distinct_approvers: int,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> tuple[ApprovalRequest, AuditEvent]:
    ts = _utc_now(created_at)
    rec = ApprovalRequest(
        approval_id=approval_id,
        request_id=request_id,
        agent_id=agent_id,
        created_at=ts,
        status="pending",
        requested_action=dict(requested_action),
        required_approvers=list(required_approvers),
        min_distinct_approvers=min_distinct_approvers,
        approved_by=[],
        expires_at=expires_at,
        metadata=dict(metadata) if metadata else None,
    )
    upsert_approval(session, rec)
    audit = build_approval_audit_event(
        approval=rec,
        event_subtype="created",
        actor_type="system",
        actor_id="recklock",
        evaluated_at=ts,
        extra_metadata={"phase": "2D"},
    )
    return rec, audit


def expire_request_db(
    session: Session,
    approval_id: str,
    *,
    now: datetime | None = None,
    actor_id: str = "recklock",
) -> tuple[ApprovalRequest, AuditEvent]:
    ts = _utc_now(now)
    rows = load_approvals_map(session)
    cur = rows.get(approval_id)
    if cur is None:
        raise ValueError(f"Unknown approval_id {approval_id!r}.")
    if cur.status != "pending":
        raise ValueError(f"Approval {approval_id!r} is not pending (status={cur.status!r}).")
    if cur.expires_at is None:
        raise ValueError(f"Approval {approval_id!r} has no expires_at; refuse implicit expiry.")
    if cur.expires_at > ts:
        raise ValueError(f"Approval {approval_id!r} is not yet expired.")

    final_rec = cur.model_copy(update={"status": "expired"})
    upsert_approval(session, final_rec)
    audit = build_approval_audit_event(
        approval=final_rec,
        event_subtype="resolved",
        actor_type="system",
        actor_id=actor_id,
        evaluated_at=ts,
        extra_metadata={"outcome": "expired"},
    )
    return final_rec, audit


def maybe_expire_stale_db(
    session: Session,
    approval: ApprovalRequest,
    *,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, AuditEvent | None]:
    ts = _utc_now(now)
    if approval.status != "pending":
        return approval, None
    if approval.expires_at is None or approval.expires_at >= ts:
        return approval, None
    final_rec, audit = expire_request_db(session, approval.approval_id, now=ts)
    return final_rec, audit


def approve_request_db(
    session: Session,
    approval_id: str,
    approver_id: str,
    *,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, list[AuditEvent]]:
    ts = _utc_now(now)
    rows = load_approvals_map(session)
    cur = rows.get(approval_id)
    if cur is None:
        raise ValueError(f"Unknown approval_id {approval_id!r}.")
    if cur.status != "pending":
        raise ValueError(f"Approval {approval_id!r} is not pending (status={cur.status!r}).")
    if cur.expires_at is not None and cur.expires_at < ts:
        raise ValueError(f"Approval {approval_id!r} expired before this sign-off.")

    if approver_id in cur.approved_by:
        raise ValueError(f"Approver {approver_id!r} already recorded for this approval.")

    if cur.required_approvers and approver_id not in cur.required_approvers:
        raise ValueError(
            f"Approver {approver_id!r} is not in the required approver set "
            f"{sorted(cur.required_approvers)}."
        )

    updated_by = list(cur.approved_by)
    updated_by.append(approver_id)
    next_rec = cur.model_copy(update={"approved_by": updated_by})

    events: list[AuditEvent] = []
    events.append(
        build_approval_audit_event(
            approval=next_rec,
            event_subtype="signoff",
            actor_type="human",
            actor_id=approver_id,
            evaluated_at=ts,
            extra_metadata={"partial": not is_request_fully_approved(next_rec, now=ts)},
        )
    )

    if is_request_fully_approved(next_rec, now=ts):
        final_rec = next_rec.model_copy(update={"status": "approved"})
        upsert_approval(session, final_rec)
        events.append(
            build_approval_audit_event(
                approval=final_rec,
                event_subtype="resolved",
                actor_type="human",
                actor_id=approver_id,
                evaluated_at=ts,
                extra_metadata={"outcome": "approved"},
            )
        )
        return final_rec, events

    upsert_approval(session, next_rec)
    return next_rec, events


def deny_request_db(
    session: Session,
    approval_id: str,
    denier_id: str,
    *,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, AuditEvent]:
    ts = _utc_now(now)
    rows = load_approvals_map(session)
    cur = rows.get(approval_id)
    if cur is None:
        raise ValueError(f"Unknown approval_id {approval_id!r}.")
    if cur.status != "pending":
        raise ValueError(f"Approval {approval_id!r} is not pending (status={cur.status!r}).")

    final_rec = cur.model_copy(
        update={"status": "denied", "metadata": {**(cur.metadata or {}), "denied_by": denier_id}}
    )
    upsert_approval(session, final_rec)
    audit = build_approval_audit_event(
        approval=final_rec,
        event_subtype="resolved",
        actor_type="human",
        actor_id=denier_id,
        evaluated_at=ts,
        extra_metadata={"outcome": "denied"},
    )
    return final_rec, audit


def list_approvals(session: Session) -> list[ApprovalRequest]:
    return sorted(load_approvals_map(session).values(), key=lambda r: r.approval_id)


# --- Trust & incidents ---


def load_trust_profiles_map(session: Session) -> dict[str, TrustProfile]:
    conn = session.connection()
    rows = conn.execute(select(m.trust_profiles)).fetchall()
    out: dict[str, TrustProfile] = {}
    for r in rows:
        prof = TrustProfile.model_validate_json(r.profile_json)
        out[prof.agent_id] = prof
    return out


def upsert_trust_profile(session: Session, profile: TrustProfile, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now or profile.last_updated)
    conn = session.connection()
    payload = _dump_json(profile.model_dump(mode="json"))
    conn.execute(delete(m.trust_profiles).where(m.trust_profiles.c.agent_id == profile.agent_id))
    conn.execute(
        m.trust_profiles.insert().values(agent_id=profile.agent_id, profile_json=payload, updated_at=ts)
    )


def list_trust_profiles(session: Session) -> list[TrustProfile]:
    return sorted(load_trust_profiles_map(session).values(), key=lambda r: r.agent_id)


def list_incidents(session: Session) -> list[IncidentRecord]:
    conn = session.connection()
    rows = conn.execute(select(m.incidents).order_by(m.incidents.c.timestamp, m.incidents.c.incident_id)).fetchall()
    out: list[IncidentRecord] = []
    for r in rows:
        raw = {
            "incident_id": r.incident_id,
            "agent_id": r.agent_id,
            "timestamp": r.timestamp,
            "incident_type": r.incident_type,
            "severity": r.severity,
            "description": r.description,
            "related_event_ids": _load_json(r.related_event_ids, None),
        }
        out.append(IncidentRecord.model_validate(raw))
    return out


def append_incident_db(session: Session, record: IncidentRecord, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now)
    conn = session.connection()
    conn.execute(
        m.incidents.insert().values(
            incident_id=record.incident_id,
            agent_id=record.agent_id,
            timestamp=_utc_now_iso(record.timestamp),
            incident_type=record.incident_type,
            severity=record.severity,
            description=record.description,
            related_event_ids=_dump_json(record.related_event_ids)
            if record.related_event_ids is not None
            else None,
            created_at=ts,
        )
    )


def recalculate_all_profiles_db(session: Session, *, now: datetime | None = None) -> dict[str, TrustProfile]:
    incidents = list_incidents(session)
    profiles = load_trust_profiles_map(session)
    by_agent: dict[str, TrustProfile] = {}
    for aid, prof in profiles.items():
        agent_inc = incidents_for_agent(incidents, aid)
        by_agent[aid] = update_trust_profile(prof, incidents=agent_inc, now=now)
    for aid, prof in by_agent.items():
        upsert_trust_profile(session, prof, now=now)
    return by_agent


# --- Execution ---


def store_execution_request(session: Session, request: ExecutionRequest, *, now: datetime | None = None) -> None:
    ts = _utc_now_iso(now)
    conn = session.connection()
    conn.execute(
        m.execution_requests.insert().values(
            request_id=request.request_id,
            agent_id=request.agent_id,
            request_json=_dump_json(request.model_dump(mode="json")),
            created_at=ts,
        )
    )


def store_execution_response(
    session: Session,
    *,
    request_id: str,
    response: ExecutionResponse,
    audit_event_ids: list[str],
    now: datetime | None = None,
) -> None:
    ts = _utc_now_iso(now)
    conn = session.connection()
    conn.execute(
        m.execution_responses.insert().values(
            request_id=request_id,
            response_json=_dump_json(response.model_dump(mode="json")),
            evaluated_at=_utc_now_iso(response.evaluated_at),
            audit_event_ids=_dump_json(audit_event_ids),
            created_at=ts,
        )
    )


def insert_api_key_row(
    session: Session,
    *,
    key_id: str,
    key_hash: str,
    name: str,
    role: str,
    created_at_iso: str,
    expires_at_iso: str | None,
    disabled: bool,
) -> None:
    conn = session.connection()
    conn.execute(
        m.api_keys.insert().values(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            role=role,
            created_at=created_at_iso,
            expires_at=expires_at_iso,
            disabled=1 if disabled else 0,
        )
    )


def fetch_api_key_by_hash(session: Session, key_hash: str) -> APIKeyRecord | None:
    conn = session.connection()
    row = conn.execute(select(m.api_keys).where(m.api_keys.c.key_hash == key_hash)).first()
    if row is None:
        return None
    expires = row.expires_at
    created = row.created_at
    exp_dt = _parse_api_key_dt(expires) if expires else None
    cr_dt = _parse_api_key_dt(created)
    return APIKeyRecord(
        key_id=row.key_id,
        key_hash=row.key_hash,
        name=row.name,
        role=row.role,  # type: ignore[arg-type]
        created_at=cr_dt,
        expires_at=exp_dt,
        disabled=bool(row.disabled),
    )


def _parse_api_key_dt(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def list_execution_pairs(session: Session) -> list[tuple[ExecutionRequest, ExecutionResponse]]:
    conn = session.connection()
    stmt = (
        select(m.execution_requests.c.request_json, m.execution_responses.c.response_json)
        .select_from(
            m.execution_requests.join(
                m.execution_responses,
                m.execution_requests.c.request_id == m.execution_responses.c.request_id,
            )
        )
        .order_by(m.execution_requests.c.created_at)
    )
    rows = conn.execute(stmt).fetchall()
    out: list[tuple[ExecutionRequest, ExecutionResponse]] = []
    for req_json, resp_json in rows:
        req = ExecutionRequest.model_validate_json(req_json)
        resp = ExecutionResponse.model_validate_json(resp_json)
        out.append((req, resp))
    return out


def list_audit_events_recent(session: Session, *, limit: int = 100) -> list[AuditEvent]:
    conn = session.connection()
    rows = conn.execute(
        select(m.audit_events).order_by(m.audit_events.c.created_at.desc()).limit(limit)
    ).fetchall()
    return [_audit_row_to_event(r) for r in rows]


def list_execution_pairs_recent(session: Session, *, limit: int = 50) -> list[tuple[ExecutionRequest, ExecutionResponse]]:
    conn = session.connection()
    stmt = (
        select(m.execution_requests.c.request_json, m.execution_responses.c.response_json)
        .select_from(
            m.execution_requests.join(
                m.execution_responses,
                m.execution_requests.c.request_id == m.execution_responses.c.request_id,
            )
        )
        .order_by(m.execution_requests.c.created_at.desc())
        .limit(limit)
    )
    rows = conn.execute(stmt).fetchall()
    out: list[tuple[ExecutionRequest, ExecutionResponse]] = []
    for req_json, resp_json in rows:
        req = ExecutionRequest.model_validate_json(req_json)
        resp = ExecutionResponse.model_validate_json(resp_json)
        out.append((req, resp))
    return out
