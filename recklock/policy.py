"""Deterministic policy evaluation for agent actions (Phase 2A)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

Effect = Literal["allow", "deny", "require_approval"]
Decision = Literal["allow", "deny", "require_approval"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class RuleConditions(BaseModel):
    """Optional predicates; omitted fields do not constrain the match."""

    capability: str | None = None
    permission_scope: str | None = None
    risk_level: RiskLevel | None = None
    requires_human_approval: bool | None = None
    environment: str | None = None
    amount_gt: float | None = None
    amount_lt: float | None = None
    production_deploy: bool | None = None
    min_distinct_approvers: int | None = Field(default=None, ge=1)
    required_approver_ids: list[str] | None = None

    @field_validator("amount_gt", "amount_lt")
    @classmethod
    def amounts_must_be_finite(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if v != v or v in (float("inf"), float("-inf")):  # noqa: PLR0124 — NaN check
            raise ValueError("amount bounds must be finite numbers")
        return v


class ActionRequest(BaseModel):
    """An action an agent proposes to take."""

    agent_id: str = Field(..., min_length=1)
    capability: str = Field(..., min_length=1)
    permission_scope: str = Field(..., min_length=1)
    risk_level: RiskLevel
    requires_human_approval: bool | None = None
    environment: str | None = None
    amount: float | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("amount")
    @classmethod
    def amount_finite(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if v != v or v in (float("inf"), float("-inf")):  # noqa: PLR0124
            raise ValueError("amount must be a finite number")
        return v


class Rule(BaseModel):
    """A single rule with an effect and optional conditions."""

    rule_id: str = Field(..., min_length=1)
    effect: Effect
    conditions: RuleConditions | None = None

    def matches(self, request: ActionRequest) -> bool:
        if self.conditions is None:
            return True
        c = self.conditions
        if c.capability is not None and request.capability != c.capability:
            return False
        if c.permission_scope is not None and request.permission_scope != c.permission_scope:
            return False
        if c.risk_level is not None and request.risk_level != c.risk_level:
            return False
        if c.requires_human_approval is not None:
            if request.requires_human_approval is None:
                return False
            if request.requires_human_approval != c.requires_human_approval:
                return False
        if c.environment is not None:
            if request.environment is None or request.environment != c.environment:
                return False
        if c.amount_gt is not None:
            if request.amount is None or request.amount <= c.amount_gt:
                return False
        if c.amount_lt is not None:
            if request.amount is None or request.amount >= c.amount_lt:
                return False
        if c.production_deploy is not None:
            meta = request.metadata or {}
            flag = meta.get("production_deploy")
            if flag is not True:
                return False
        return True


class Policy(BaseModel):
    """A versioned policy document containing ordered rules."""

    policy_id: str = Field(..., min_length=1)
    description: str = Field(default="", description="Human-readable summary")
    enabled: bool = True
    rules: list[Rule] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    """Outcome of evaluating an action against policies."""

    decision: Decision
    matched_policy_ids: list[str]
    matched_rule_ids: list[str]
    reason: str
    evaluated_at: datetime


def collect_matching_rules(request: ActionRequest, policies: list[Policy]) -> list[tuple[str, Rule]]:
    """Return every enabled rule that matches *request* (policy order, then rule order)."""
    active = [p for p in policies if p.enabled]
    active.sort(key=lambda p: p.policy_id)
    out: list[tuple[str, Rule]] = []
    for policy in active:
        for rule in policy.rules:
            if rule.matches(request):
                out.append((policy.policy_id, rule))
    return out


def evaluate_action(
    request: ActionRequest,
    policies: list[Policy],
    *,
    evaluated_at: datetime | None = None,
) -> PolicyDecision:
    """Evaluate *request* against *policies* in deterministic order.

    Precedence among matched rules: **deny** > **require_approval** > **allow**.
    If no rule matches, the decision is **allow**.
    Disabled policies are skipped. Policies are processed in ascending ``policy_id``
    order; rules run in list order within each policy.

    Pass *evaluated_at* for tests; otherwise the current UTC time is used.
    """
    ts = evaluated_at if evaluated_at is not None else datetime.now(timezone.utc)
    matches_detail = collect_matching_rules(request, policies)
    matches: list[tuple[str, str, Effect]] = [
        (policy_id, rule.rule_id, rule.effect) for policy_id, rule in matches_detail
    ]

    matched_policy_ids: list[str] = []
    seen_pid: set[str] = set()
    for pid, _, _ in matches:
        if pid not in seen_pid:
            matched_policy_ids.append(pid)
            seen_pid.add(pid)

    matched_rule_ids = [r for _, r, _ in matches]
    effects = [e for _, _, e in matches]

    if "deny" in effects:
        deny_rules = [r for (_, r, e) in matches if e == "deny"]
        return PolicyDecision(
            decision="deny",
            matched_policy_ids=matched_policy_ids,
            matched_rule_ids=matched_rule_ids,
            reason=_reason_deny(deny_rules),
            evaluated_at=ts,
        )
    if "require_approval" in effects:
        appr_rules = [r for (_, r, e) in matches if e == "require_approval"]
        return PolicyDecision(
            decision="require_approval",
            matched_policy_ids=matched_policy_ids,
            matched_rule_ids=matched_rule_ids,
            reason=_reason_require_approval(appr_rules),
            evaluated_at=ts,
        )
    if "allow" in effects:
        allow_rules = [r for (_, r, e) in matches if e == "allow"]
        return PolicyDecision(
            decision="allow",
            matched_policy_ids=matched_policy_ids,
            matched_rule_ids=matched_rule_ids,
            reason=_reason_allow_explicit(allow_rules),
            evaluated_at=ts,
        )

    return PolicyDecision(
        decision="allow",
        matched_policy_ids=[],
        matched_rule_ids=[],
        reason="No rules matched; default allow.",
        evaluated_at=ts,
    )


def _reason_deny(rule_ids: list[str]) -> str:
    ids = ", ".join(rule_ids)
    return f"Denied by matched rule(s): {ids}."


def _reason_require_approval(rule_ids: list[str]) -> str:
    ids = ", ".join(rule_ids)
    return f"Human approval required by matched rule(s): {ids}."


def _reason_allow_explicit(rule_ids: list[str]) -> str:
    ids = ", ".join(rule_ids)
    return f"Allowed by matched rule(s): {ids}."


def load_action_request_yaml(path: Path) -> ActionRequest:
    """Load an :class:`ActionRequest` from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("request YAML must be a mapping at the top level")
    return ActionRequest.model_validate(raw)


def load_policies_yaml(path: Path) -> list[Policy]:
    """Load a list of :class:`Policy` objects from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return []
    if isinstance(raw, list):
        return [Policy.model_validate(p) for p in raw]
    if isinstance(raw, dict) and "policies" in raw:
        inner = raw["policies"]
        if not isinstance(inner, list):
            raise ValueError("'policies' must be a list")
        return [Policy.model_validate(p) for p in inner]
    if isinstance(raw, dict):
        return [Policy.model_validate(raw)]
    raise ValueError("policies YAML must be a list, a mapping with 'policies', or a single policy mapping")
