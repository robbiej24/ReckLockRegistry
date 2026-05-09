"""Local runtime execution gateway — intercept actions before execution (Phase 2C)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Sequence

from sqlalchemy.orm import Session

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from agenttrust.approvals import (
    DEFAULT_APPROVAL_LOG_PATH,
    create_approval_request,
    deterministic_approval_id,
    derive_approval_requirements_from_rules,
    is_request_fully_approved,
    load_approvals,
    maybe_expire_stale_request,
)
from agenttrust.audit import AuditEvent
from agenttrust.connectors.base import ConnectorRequest as ConnectorInvocationRequest
from agenttrust.connectors.base import ConnectorResponse as ConnectorCallResult
from agenttrust.connectors.base import sanitize_for_audit
from agenttrust.connectors.registry import get_connector
from agenttrust.manifest import load_manifest
from agenttrust.policy import ActionRequest, Policy, PolicyDecision, collect_matching_rules, evaluate_action
from agenttrust.registry import IndexAgentEntry, RegistryIndex

ExecutionDecision = Literal["allowed", "denied", "pending_approval"]


class ExecutionRequest(BaseModel):
    """Agent-submitted action to evaluate through the gateway."""

    request_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    capability: str = Field(..., min_length=1)
    permission_scope: str = Field(..., min_length=1)
    environment: str | None = None
    amount: float | None = None
    metadata: dict[str, Any] | None = None
    connector_id: str | None = None
    connector_action: str | None = None
    connector_config: dict[str, Any] | None = None
    dry_run: bool = True

    @field_validator("amount")
    @classmethod
    def amount_finite(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if v != v or v in (float("inf"), float("-inf")):  # noqa: PLR0124
            raise ValueError("amount must be a finite number")
        return v


class ExecutionResponse(BaseModel):
    """Gateway outcome for one execution request."""

    request_id: str
    decision: ExecutionDecision
    reason: str
    audit_event_id: str
    evaluated_at: datetime
    approval_id: str | None = None
    connector: ConnectorCallResult | None = None


class GatewayExecutionResult(BaseModel):
    """Structured result from :func:`execute_request` (response plus audit record)."""

    response: ExecutionResponse
    audit_event: AuditEvent
    approval_audit_events: list[AuditEvent] = Field(default_factory=list)


def load_execution_request_yaml(path: Path) -> ExecutionRequest:
    """Load an :class:`ExecutionRequest` from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("execution request YAML must be a mapping at the top level")
    return ExecutionRequest.model_validate(raw)


def load_registry_index(path: Path) -> RegistryIndex:
    """Load :class:`RegistryIndex` from ``registry/index.json`` (or a test path)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return RegistryIndex.model_validate(raw)


def _normalize_agents(
    registered_agents: Sequence[IndexAgentEntry] | RegistryIndex,
) -> list[IndexAgentEntry]:
    if isinstance(registered_agents, RegistryIndex):
        return list(registered_agents.agents)
    return list(registered_agents)


def _deterministic_event_id(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"evt_{digest[:24]}"


def _mapping_gateway_decision(policy_decision: PolicyDecision) -> ExecutionDecision:
    if policy_decision.decision == "deny":
        return "denied"
    if policy_decision.decision == "require_approval":
        return "pending_approval"
    return "allowed"


def _fixed_timestamp(evaluated_at: datetime | None) -> datetime:
    return evaluated_at if evaluated_at is not None else datetime.now(timezone.utc)


def _parse_approval_expires(metadata: dict[str, Any] | None) -> datetime | None:
    if not metadata:
        return None
    raw = metadata.get("approval_expires_at")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return None


def _merge_connector_result(
    request: ExecutionRequest,
    result: GatewayExecutionResult,
    connector_resp: ConnectorCallResult,
) -> GatewayExecutionResult:
    meta = dict(result.audit_event.metadata or {})
    meta["gateway_phase"] = "3D"
    meta["connector_result"] = {
        "connector_id": connector_resp.connector_id,
        "action": connector_resp.action,
        "dry_run": connector_resp.dry_run,
        "success": connector_resp.success,
        "message": connector_resp.message,
        "external_reference": connector_resp.external_reference,
        "metadata": sanitize_for_audit(connector_resp.metadata or {}),
    }
    new_audit = result.audit_event.model_copy(update={"metadata": meta})
    new_resp = result.response.model_copy(update={"connector": connector_resp})
    return GatewayExecutionResult(
        response=new_resp,
        audit_event=new_audit,
        approval_audit_events=list(result.approval_audit_events),
    )


def _apply_connector_phase(
    request: ExecutionRequest,
    result: GatewayExecutionResult,
) -> GatewayExecutionResult:
    if result.response.decision != "allowed":
        return result
    if not request.connector_id:
        return result
    if not request.connector_action:
        cr = ConnectorCallResult(
            connector_id=request.connector_id,
            action="",
            dry_run=request.dry_run,
            success=False,
            message="connector_action is required when connector_id is set",
        )
        return _merge_connector_result(request, result, cr)

    conn = get_connector(request.connector_id)
    if conn is None:
        cr = ConnectorCallResult(
            connector_id=request.connector_id,
            action=request.connector_action or "",
            dry_run=request.dry_run,
            success=False,
            message=f"Unknown connector_id {request.connector_id!r}",
        )
        return _merge_connector_result(request, result, cr)

    req_scopes = set(conn.required_permission_scopes)
    if "*" not in req_scopes and request.permission_scope not in req_scopes:
        cr = ConnectorCallResult(
            connector_id=conn.connector_id,
            action=request.connector_action,
            dry_run=request.dry_run,
            success=False,
            message=(
                f"permission_scope {request.permission_scope!r} not allowed for connector "
                f"(requires one of {sorted(req_scopes)})"
            ),
        )
        return _merge_connector_result(request, result, cr)

    if request.connector_action not in conn.supported_capabilities:
        cr = ConnectorCallResult(
            connector_id=conn.connector_id,
            action=request.connector_action,
            dry_run=request.dry_run,
            success=False,
            message=f"Unsupported capability {request.connector_action!r} for connector {conn.connector_id}",
        )
        return _merge_connector_result(request, result, cr)

    cfg = dict(request.connector_config or {})
    cfg["_validated_action"] = request.connector_action
    try:
        conn.validate_config(cfg)
    except ValueError as exc:
        cr = ConnectorCallResult(
            connector_id=conn.connector_id,
            action=request.connector_action,
            dry_run=request.dry_run,
            success=False,
            message=str(exc),
        )
        return _merge_connector_result(request, result, cr)

    cr_req = ConnectorInvocationRequest(
        connector_id=request.connector_id,
        action=request.connector_action,
        agent_id=request.agent_id,
        capability=request.capability,
        permission_scope=request.permission_scope,
        config=dict(request.connector_config or {}),
        dry_run=request.dry_run,
        request_id=request.request_id,
    )
    try:
        cr_out = conn.dry_run(cr_req) if request.dry_run else conn.execute(cr_req)
    except Exception as exc:  # noqa: BLE001 — surface connector failures safely
        cr_out = ConnectorCallResult(
            connector_id=conn.connector_id,
            action=request.connector_action,
            dry_run=request.dry_run,
            success=False,
            message=f"Connector error: {exc}",
        )
    return _merge_connector_result(request, result, cr_out)


def _build_audit_event(
    *,
    request: ExecutionRequest,
    gateway_decision: ExecutionDecision,
    reason: str,
    evaluated_at: datetime,
    matched_policy_ids: list[str] | None,
    permission_scope: str | None,
    metadata_extra: dict[str, Any] | None = None,
    gateway_phase: str = "2C",
) -> AuditEvent:
    meta: dict[str, Any] = dict(request.metadata or {})
    meta.setdefault("gateway_phase", gateway_phase)
    if metadata_extra:
        meta.update(metadata_extra)
    payload_for_id = {
        "request_id": request.request_id,
        "agent_id": request.agent_id,
        "capability": request.capability,
        "decision": gateway_decision,
        "evaluated_at": evaluated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "reason": reason,
    }
    event_id = _deterministic_event_id(payload_for_id)
    return AuditEvent(
        event_id=event_id,
        timestamp=evaluated_at,
        agent_id=request.agent_id,
        actor_type="agent",
        actor_id=request.agent_id,
        event_type="gateway.execution",
        action=request.capability,
        resource_type="execution_request",
        resource_id=request.request_id,
        permission_scope=permission_scope,
        decision=gateway_decision,
        policy_ids=matched_policy_ids,
        metadata=meta or None,
    )


def execute_request(
    request: ExecutionRequest,
    policies: list[Policy],
    registered_agents: Sequence[IndexAgentEntry] | RegistryIndex,
    *,
    registry_root: Path,
    evaluated_at: datetime | None = None,
    approval_log_path: Path | None = None,
    db_session: Session | None = None,
) -> GatewayExecutionResult:
    """Evaluate *request* for a registered agent, apply *policies*, emit an audit template.

    Steps:

    1. Resolve the agent against *registered_agents* (from ``registry/index.json``).
    2. Require an on-disk manifest at ``registry_root / manifest_path``.
    3. Ensure the declared capability and permission scope exist on the manifest.
    4. Build an :class:`ActionRequest` using manifest risk fields.
    5. Run :func:`agenttrust.policy.evaluate_action`.
    6. Map policy outcome to gateway ``allowed`` / ``denied`` / ``pending_approval``.
    7. Build a deterministic audit event id and return response plus :class:`AuditEvent`.

    Append the returned ``audit_event`` with :func:`agenttrust.audit.append_event` to persist.

    Pass *evaluated_at* in tests for deterministic timestamps.

    When policy requires human approval, approval rows are written under
    *approval_log_path* (default ``approval_logs/approvals.jsonl``) unless *db_session*
    is provided, in which case approvals are stored in the database. Completed approvals
    satisfy subsequent executions with the same deterministic approval id.
    """
    ts = _fixed_timestamp(evaluated_at)
    agents = _normalize_agents(registered_agents)
    by_id: dict[str, IndexAgentEntry] = {a.agent_id: a for a in agents}

    entry = by_id.get(request.agent_id)
    if entry is None:
        reason = f"Unknown agent_id {request.agent_id!r}; not present in registry index."
        decision: ExecutionDecision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "unknown_agent"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    manifest_path = (registry_root / Path(entry.manifest_path)).resolve()
    if not manifest_path.is_file():
        reason = f"Manifest missing at {manifest_path} (index manifest_path={entry.manifest_path!r})."
        decision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "manifest_missing"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    try:
        manifest = load_manifest(manifest_path)
    except (ValidationError, ValueError, OSError) as exc:
        reason = f"Manifest invalid or unreadable at {manifest_path}: {exc}"
        decision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "manifest_invalid"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    if manifest.agent_id != request.agent_id:
        reason = (
            f"Manifest agent_id mismatch: manifest has {manifest.agent_id!r}, "
            f"request has {request.agent_id!r}."
        )
        decision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "agent_id_mismatch"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    if request.capability not in manifest.capabilities:
        reason = (
            f"Capability {request.capability!r} is not declared in the agent manifest "
            f"(declared: {sorted(manifest.capabilities)})."
        )
        decision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "capability_not_in_manifest"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    if request.permission_scope not in manifest.permission_scopes:
        reason = (
            f"Permission scope {request.permission_scope!r} is not declared in the agent manifest "
            f"(declared: {sorted(manifest.permission_scopes)})."
        )
        decision = "denied"
        audit = _build_audit_event(
            request=request,
            gateway_decision=decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=None,
            permission_scope=request.permission_scope,
            metadata_extra={"registry_check": "scope_not_in_manifest"},
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=ts,
            ),
            audit_event=audit,
        )

    action = ActionRequest(
        agent_id=request.agent_id,
        capability=request.capability,
        permission_scope=request.permission_scope,
        risk_level=manifest.risk_level,
        requires_human_approval=manifest.requires_human_approval,
        environment=request.environment,
        amount=request.amount,
        metadata=request.metadata,
    )
    policy_decision = evaluate_action(action, policies, evaluated_at=ts)

    if policy_decision.decision == "require_approval":
        ap_log = approval_log_path if approval_log_path is not None else DEFAULT_APPROVAL_LOG_PATH
        matches = collect_matching_rules(action, policies)
        appr_rules = [r for _, r in matches if r.effect == "require_approval"]
        req_names, min_distinct = derive_approval_requirements_from_rules(appr_rules)
        approval_id = deterministic_approval_id(
            request_id=request.request_id,
            agent_id=request.agent_id,
            capability=request.capability,
            permission_scope=request.permission_scope,
        )

        approval_audits: list[AuditEvent] = []
        if db_session is not None:
            from agenttrust.db import repositories as repos

            rows = repos.load_approvals_map(db_session)
        else:
            rows = load_approvals(ap_log)
        existing = rows.get(approval_id)
        if existing is not None:
            if db_session is not None:
                from agenttrust.db import repositories as repos

                existing, exp_audit = repos.maybe_expire_stale_db(db_session, existing, now=ts)
            else:
                existing, exp_audit = maybe_expire_stale_request(existing, log_path=ap_log, now=ts)
            if exp_audit is not None:
                approval_audits.append(exp_audit)

        common_meta = {
            "matched_rule_ids": policy_decision.matched_rule_ids,
            "policy_decision": policy_decision.decision,
            "approval_id": approval_id,
        }

        if existing is not None and existing.status == "approved" and is_request_fully_approved(existing, now=ts):
            gateway_decision = "allowed"
            reason = f"Human approval satisfied ({existing.approval_id})."
            audit = _build_audit_event(
                request=request,
                gateway_decision=gateway_decision,
                reason=reason,
                evaluated_at=ts,
                matched_policy_ids=sorted(policy_decision.matched_policy_ids)
                if policy_decision.matched_policy_ids
                else None,
                permission_scope=request.permission_scope,
                metadata_extra={**common_meta, "approval_status": "approved"},
                gateway_phase="2D",
            )
            approved_result = GatewayExecutionResult(
                response=ExecutionResponse(
                    request_id=request.request_id,
                    decision=gateway_decision,
                    reason=reason,
                    audit_event_id=audit.event_id,
                    evaluated_at=policy_decision.evaluated_at,
                    approval_id=existing.approval_id,
                ),
                audit_event=audit,
                approval_audit_events=approval_audits,
            )
            return _apply_connector_phase(request, approved_result)

        if existing is not None and existing.status == "expired":
            gateway_decision = "denied"
            reason = f"Approval {existing.approval_id} expired; execution blocked."
            audit = _build_audit_event(
                request=request,
                gateway_decision=gateway_decision,
                reason=reason,
                evaluated_at=ts,
                matched_policy_ids=sorted(policy_decision.matched_policy_ids)
                if policy_decision.matched_policy_ids
                else None,
                permission_scope=request.permission_scope,
                metadata_extra={**common_meta, "approval_status": "expired"},
                gateway_phase="2D",
            )
            return GatewayExecutionResult(
                response=ExecutionResponse(
                    request_id=request.request_id,
                    decision=gateway_decision,
                    reason=reason,
                    audit_event_id=audit.event_id,
                    evaluated_at=policy_decision.evaluated_at,
                    approval_id=existing.approval_id,
                ),
                audit_event=audit,
                approval_audit_events=approval_audits,
            )

        if existing is not None and existing.status == "denied":
            gateway_decision = "denied"
            reason = f"Approval {existing.approval_id} was denied."
            audit = _build_audit_event(
                request=request,
                gateway_decision=gateway_decision,
                reason=reason,
                evaluated_at=ts,
                matched_policy_ids=sorted(policy_decision.matched_policy_ids)
                if policy_decision.matched_policy_ids
                else None,
                permission_scope=request.permission_scope,
                metadata_extra={**common_meta, "approval_status": "denied"},
                gateway_phase="2D",
            )
            return GatewayExecutionResult(
                response=ExecutionResponse(
                    request_id=request.request_id,
                    decision=gateway_decision,
                    reason=reason,
                    audit_event_id=audit.event_id,
                    evaluated_at=policy_decision.evaluated_at,
                    approval_id=existing.approval_id,
                ),
                audit_event=audit,
                approval_audit_events=approval_audits,
            )

        if existing is not None and existing.status == "pending":
            gateway_decision = "pending_approval"
            reason = f"Awaiting human approval ({existing.approval_id})."
            audit = _build_audit_event(
                request=request,
                gateway_decision=gateway_decision,
                reason=reason,
                evaluated_at=ts,
                matched_policy_ids=sorted(policy_decision.matched_policy_ids)
                if policy_decision.matched_policy_ids
                else None,
                permission_scope=request.permission_scope,
                metadata_extra={**common_meta, "approval_status": "pending"},
                gateway_phase="2D",
            )
            return GatewayExecutionResult(
                response=ExecutionResponse(
                    request_id=request.request_id,
                    decision=gateway_decision,
                    reason=reason,
                    audit_event_id=audit.event_id,
                    evaluated_at=policy_decision.evaluated_at,
                    approval_id=existing.approval_id,
                ),
                audit_event=audit,
                approval_audit_events=approval_audits,
            )

        expires_at = _parse_approval_expires(request.metadata)
        if db_session is not None:
            from agenttrust.db import repositories as repos

            rec, created_audit = repos.create_approval_request_db(
                db_session,
                approval_id=approval_id,
                request_id=request.request_id,
                agent_id=request.agent_id,
                requested_action={
                    "capability": request.capability,
                    "permission_scope": request.permission_scope,
                    "amount": request.amount,
                    "environment": request.environment,
                },
                required_approvers=req_names,
                min_distinct_approvers=min_distinct,
                expires_at=expires_at,
                metadata={
                    "matched_rule_ids": policy_decision.matched_rule_ids,
                    "policy_decision": policy_decision.decision,
                    "policy_reason": policy_decision.reason,
                },
                created_at=ts,
            )
        else:
            rec, created_audit = create_approval_request(
                approval_id=approval_id,
                request_id=request.request_id,
                agent_id=request.agent_id,
                requested_action={
                    "capability": request.capability,
                    "permission_scope": request.permission_scope,
                    "amount": request.amount,
                    "environment": request.environment,
                },
                required_approvers=req_names,
                min_distinct_approvers=min_distinct,
                expires_at=expires_at,
                metadata={
                    "matched_rule_ids": policy_decision.matched_rule_ids,
                    "policy_decision": policy_decision.decision,
                    "policy_reason": policy_decision.reason,
                },
                created_at=ts,
                log_path=ap_log,
            )
        approval_audits.append(created_audit)
        gateway_decision = "pending_approval"
        reason = policy_decision.reason
        audit = _build_audit_event(
            request=request,
            gateway_decision=gateway_decision,
            reason=reason,
            evaluated_at=ts,
            matched_policy_ids=sorted(policy_decision.matched_policy_ids)
            if policy_decision.matched_policy_ids
            else None,
            permission_scope=request.permission_scope,
            metadata_extra={**common_meta, "approval_status": "pending"},
            gateway_phase="2D",
        )
        return GatewayExecutionResult(
            response=ExecutionResponse(
                request_id=request.request_id,
                decision=gateway_decision,
                reason=reason,
                audit_event_id=audit.event_id,
                evaluated_at=policy_decision.evaluated_at,
                approval_id=rec.approval_id,
            ),
            audit_event=audit,
            approval_audit_events=approval_audits,
        )

    gateway_decision = _mapping_gateway_decision(policy_decision)
    audit = _build_audit_event(
        request=request,
        gateway_decision=gateway_decision,
        reason=policy_decision.reason,
        evaluated_at=ts,
        matched_policy_ids=sorted(policy_decision.matched_policy_ids)
        if policy_decision.matched_policy_ids
        else None,
        permission_scope=request.permission_scope,
        metadata_extra={
            "matched_rule_ids": policy_decision.matched_rule_ids,
            "policy_decision": policy_decision.decision,
        },
    )

    normal_result = GatewayExecutionResult(
        response=ExecutionResponse(
            request_id=request.request_id,
            decision=gateway_decision,
            reason=policy_decision.reason,
            audit_event_id=audit.event_id,
            evaluated_at=policy_decision.evaluated_at,
            approval_id=None,
        ),
        audit_event=audit,
    )
    return _apply_connector_phase(request, normal_result)
