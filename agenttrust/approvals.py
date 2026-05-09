"""Human approval workflows for sensitive agent actions (Phase 2D)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from agenttrust.audit import AuditEvent
from agenttrust.constants import DEFAULT_APPROVAL_LOG_PATH as _DEFAULT_APPROVAL_LOG_STR
from agenttrust.policy import Rule

ApprovalStatus = Literal["pending", "approved", "denied", "expired"]

DEFAULT_APPROVAL_LOG_PATH = Path(_DEFAULT_APPROVAL_LOG_STR)


class ApprovalCreationDocument(BaseModel):
    """YAML input for :func:`create_approval_request` via the CLI (`agenttrust create-approval`)."""

    request_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    requested_action: dict[str, Any]
    required_approvers: list[str] = Field(default_factory=list)
    min_distinct_approvers: int = Field(default=1, ge=1)
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("expires_at")
    @classmethod
    def expires_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class ApprovalRequest(BaseModel):
    """Structured approval gate for a proposed execution."""

    approval_id: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    created_at: datetime
    status: ApprovalStatus
    requested_action: dict[str, Any]
    required_approvers: list[str] = Field(default_factory=list)
    min_distinct_approvers: int = Field(default=1, ge=1)
    approved_by: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("created_at", "expires_at")
    @classmethod
    def timestamps_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


def load_approval_creation_yaml(path: Path) -> ApprovalCreationDocument:
    """Load CLI approval creation input from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("approval creation YAML must be a mapping at the top level")
    return ApprovalCreationDocument.model_validate(raw)


def load_approval_request_yaml(path: Path) -> ApprovalRequest:
    """Load an :class:`ApprovalRequest` from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("approval request YAML must be a mapping at the top level")
    return ApprovalRequest.model_validate(raw)


def _utc_now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.now(timezone.utc)


def deterministic_approval_id(
    *,
    request_id: str,
    agent_id: str,
    capability: str,
    permission_scope: str,
) -> str:
    """Stable id so repeated gateway evaluations attach to the same approval record."""
    body = json.dumps(
        {
            "agent_id": agent_id,
            "capability": capability,
            "permission_scope": permission_scope,
            "request_id": request_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"apr_{digest[:24]}"


def derive_approval_requirements_from_rules(require_approval_rules: list[Rule]) -> tuple[list[str], int]:
    """Derive ``(required_approvers, min_distinct_approvers)`` from matched ``require_approval`` rules.

    Named approver ids across rules are merged in stable order; when any named approver is present,
    every listed identity must approve. Otherwise ``min_distinct_approvers`` is the maximum of
    per-rule ``min_distinct_approvers`` (minimum 1).
    """
    named: list[str] = []
    max_min = 1
    for rule in require_approval_rules:
        if rule.effect != "require_approval":
            continue
        cond = rule.conditions
        if cond is None:
            continue
        if cond.required_approver_ids:
            for rid in cond.required_approver_ids:
                if rid not in named:
                    named.append(rid)
        if cond.min_distinct_approvers is not None:
            max_min = max(max_min, cond.min_distinct_approvers)
    if named:
        return named, max(len(set(named)), 1)
    return [], max_min


def load_approvals(log_path: Path | None = None) -> dict[str, ApprovalRequest]:
    """Load approval records from JSONL; last line wins per ``approval_id``."""
    path = log_path or DEFAULT_APPROVAL_LOG_PATH
    if not path.is_file():
        return {}
    latest: dict[str, ApprovalRequest] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError(f"{path}:{line_no}: each line must be a JSON object")
        rec = ApprovalRequest.model_validate(raw)
        latest[rec.approval_id] = rec
    return latest


def append_approval_record(record: ApprovalRequest, log_path: Path | None = None) -> None:
    """Append one snapshot line for *record* (full replace via last-write wins on load)."""
    path = log_path or DEFAULT_APPROVAL_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = record.model_dump(mode="json")
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _deterministic_event_id(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"evt_{digest[:24]}"


def build_approval_audit_event(
    *,
    approval: ApprovalRequest,
    event_subtype: Literal["created", "signoff", "resolved"],
    actor_type: Literal["human", "agent", "system"],
    actor_id: str,
    evaluated_at: datetime,
    extra_metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Construct a deterministic audit template for approval lifecycle events."""
    meta: dict[str, Any] = dict(approval.metadata or {})
    meta.setdefault("gateway_phase", "2D")
    meta["approval_id"] = approval.approval_id
    meta["approval_status"] = approval.status
    meta["approval_subtype"] = event_subtype
    if extra_metadata:
        meta.update(extra_metadata)

    payload_for_id = {
        "approval_id": approval.approval_id,
        "approval_status": approval.status,
        "actor_id": actor_id,
        "decision": approval.status if approval.status in ("approved", "denied", "expired") else "pending",
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "request_id": approval.request_id,
        "subtype": event_subtype,
    }
    event_id = _deterministic_event_id(payload_for_id)

    audit_decision: Literal["allowed", "denied", "pending_approval"]
    if approval.status == "approved":
        audit_decision = "allowed"
    elif approval.status in ("denied", "expired"):
        audit_decision = "denied"
    else:
        audit_decision = "pending_approval"

    action_name = str(approval.requested_action.get("capability", "unknown"))

    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=approval.agent_id,
        actor_type=actor_type,
        actor_id=actor_id,
        event_type=f"approval.{event_subtype}",
        action=action_name,
        resource_type="approval_request",
        resource_id=approval.approval_id,
        permission_scope=str(approval.requested_action.get("permission_scope"))
        if approval.requested_action.get("permission_scope") is not None
        else None,
        decision=audit_decision,
        policy_ids=None,
        metadata=meta or None,
    )


def create_approval_request(
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
    log_path: Path | None = None,
) -> tuple[ApprovalRequest, AuditEvent]:
    """Persist a new pending approval and return the record plus an ``approval.created`` audit template."""
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
    append_approval_record(rec, log_path=log_path)
    audit = build_approval_audit_event(
        approval=rec,
        event_subtype="created",
        actor_type="system",
        actor_id="agenttrust",
        evaluated_at=ts,
        extra_metadata={"phase": "2D"},
    )
    return rec, audit


def is_request_fully_approved(
    approval: ApprovalRequest,
    *,
    now: datetime | None = None,
) -> bool:
    """Return True when policies are satisfied and the record is not expired."""
    ts = _utc_now(now)
    if approval.expires_at is not None and approval.expires_at < ts:
        return False
    if approval.status == "approved":
        return True
    if approval.status != "pending":
        return False
    if approval.required_approvers:
        got = set(approval.approved_by)
        return all(r in got for r in approval.required_approvers)
    distinct = len(set(approval.approved_by))
    return distinct >= approval.min_distinct_approvers


def approve_request(
    approval_id: str,
    approver_id: str,
    *,
    log_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, list[AuditEvent]]:
    """Record one human approval; duplicate approvers are rejected. Returns updated row & audit templates."""
    ts = _utc_now(now)
    rows = load_approvals(log_path)
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
        append_approval_record(final_rec, log_path=log_path)
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

    append_approval_record(next_rec, log_path=log_path)
    return next_rec, events


def deny_request(
    approval_id: str,
    denier_id: str,
    *,
    log_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, AuditEvent]:
    """Finalize an approval as denied (terminal)."""
    ts = _utc_now(now)
    rows = load_approvals(log_path)
    cur = rows.get(approval_id)
    if cur is None:
        raise ValueError(f"Unknown approval_id {approval_id!r}.")
    if cur.status != "pending":
        raise ValueError(f"Approval {approval_id!r} is not pending (status={cur.status!r}).")

    final_rec = cur.model_copy(update={"status": "denied", "metadata": {**(cur.metadata or {}), "denied_by": denier_id}})
    append_approval_record(final_rec, log_path=log_path)
    audit = build_approval_audit_event(
        approval=final_rec,
        event_subtype="resolved",
        actor_type="human",
        actor_id=denier_id,
        evaluated_at=ts,
        extra_metadata={"outcome": "denied"},
    )
    return final_rec, audit


def expire_request(
    approval_id: str,
    *,
    log_path: Path | None = None,
    now: datetime | None = None,
    actor_id: str = "agenttrust",
) -> tuple[ApprovalRequest, AuditEvent]:
    """Mark an approval expired (terminal)."""
    ts = _utc_now(now)
    rows = load_approvals(log_path)
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
    append_approval_record(final_rec, log_path=log_path)
    audit = build_approval_audit_event(
        approval=final_rec,
        event_subtype="resolved",
        actor_type="system",
        actor_id=actor_id,
        evaluated_at=ts,
        extra_metadata={"outcome": "expired"},
    )
    return final_rec, audit


def maybe_expire_stale_request(
    approval: ApprovalRequest,
    *,
    log_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, AuditEvent | None]:
    """If *approval* is pending and past *expires_at*, mark expired and return audit template."""
    ts = _utc_now(now)
    if approval.status != "pending":
        return approval, None
    if approval.expires_at is None or approval.expires_at >= ts:
        return approval, None
    final_rec, audit = expire_request(approval.approval_id, log_path=log_path, now=ts)
    return final_rec, audit
