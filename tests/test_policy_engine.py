"""Tests for the deterministic policy engine (Phase 2A)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from recklock.cli import app
from recklock.policy import (
    ActionRequest,
    Policy,
    Rule,
    RuleConditions,
    evaluate_action,
)

FIXED_TS = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)


def _req(**kwargs: object) -> ActionRequest:
    base = dict(
        agent_id="agt_test_a1b2c3d4",
        capability="misc.op",
        permission_scope="general",
        risk_level="low",
    )
    base.update(kwargs)
    return ActionRequest.model_validate(base)


def test_deny_overrides_allow() -> None:
    policies = [
        Policy(
            policy_id="mixed",
            enabled=True,
            rules=[
                Rule(rule_id="allow_all", effect="allow"),
                Rule(rule_id="deny_specific", effect="deny", conditions=RuleConditions(capability="pay.send")),
            ],
        ),
    ]
    r = _req(capability="pay.send")
    d = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    assert d.decision == "deny"
    assert "deny_specific" in d.matched_rule_ids
    assert "allow_all" in d.matched_rule_ids


def test_require_approval_overrides_allow() -> None:
    policies = [
        Policy(
            policy_id="pay",
            enabled=True,
            rules=[
                Rule(rule_id="allow_low", effect="allow", conditions=RuleConditions(risk_level="low")),
                Rule(
                    rule_id="approve_large",
                    effect="require_approval",
                    conditions=RuleConditions(capability="pay.invoice", amount_gt=100.0),
                ),
            ],
        ),
    ]
    r = _req(capability="pay.invoice", risk_level="low", amount=500.0)
    d = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    assert d.decision == "require_approval"
    assert d.matched_rule_ids == ["allow_low", "approve_large"]


def test_unmatched_defaults_allow() -> None:
    policies = [
        Policy(
            policy_id="narrow",
            enabled=True,
            rules=[
                Rule(
                    rule_id="only_research",
                    effect="allow",
                    conditions=RuleConditions(capability="research.query"),
                ),
            ],
        ),
    ]
    r = _req(capability="other.op")
    d = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    assert d.decision == "allow"
    assert d.matched_policy_ids == []
    assert d.matched_rule_ids == []
    assert "default allow" in d.reason.lower()


def test_amount_threshold_require_approval() -> None:
    policies = [
        Policy(
            policy_id="payments",
            enabled=True,
            rules=[
                Rule(
                    rule_id="large_payment",
                    effect="require_approval",
                    conditions=RuleConditions(capability="payment.transfer", amount_gt=1000.0),
                ),
            ],
        ),
    ]
    over = _req(capability="payment.transfer", amount=1500.0)
    assert evaluate_action(over, policies, evaluated_at=FIXED_TS).decision == "require_approval"

    under = _req(capability="payment.transfer", amount=500.0)
    du = evaluate_action(under, policies, evaluated_at=FIXED_TS)
    assert du.decision == "allow"
    assert du.matched_rule_ids == []


def test_environment_matching_deny_deploy() -> None:
    policies = [
        Policy(
            policy_id="prod_safety",
            enabled=True,
            rules=[
                Rule(
                    rule_id="no_prod_deploy",
                    effect="deny",
                    conditions=RuleConditions(
                        capability="production.deploy",
                        environment="production",
                    ),
                ),
            ],
        ),
    ]
    bad = _req(
        capability="production.deploy",
        permission_scope="infra",
        risk_level="high",
        environment="production",
    )
    assert evaluate_action(bad, policies, evaluated_at=FIXED_TS).decision == "deny"

    ok = bad.model_copy(update={"environment": "staging"})
    assert evaluate_action(ok, policies, evaluated_at=FIXED_TS).decision == "allow"


def test_disabled_policies_ignored() -> None:
    policies = [
        Policy(
            policy_id="off",
            enabled=False,
            rules=[Rule(rule_id="would_deny", effect="deny")],
        ),
        Policy(
            policy_id="on",
            enabled=True,
            rules=[Rule(rule_id="allow_default", effect="allow")],
        ),
    ]
    r = _req()
    d = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    assert d.decision == "allow"
    assert d.matched_policy_ids == ["on"]


def test_deterministic_order_and_output() -> None:
    """Policies run in ascending policy_id order; matched_rule_ids follow that order."""
    policies = [
        Policy(
            policy_id="zebra",
            enabled=True,
            rules=[Rule(rule_id="z_rule", effect="allow", conditions=RuleConditions(risk_level="low"))],
        ),
        Policy(
            policy_id="alpha",
            enabled=True,
            rules=[Rule(rule_id="a_rule", effect="allow", conditions=RuleConditions(risk_level="low"))],
        ),
    ]
    r = _req(risk_level="low")
    d1 = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    d2 = evaluate_action(r, policies, evaluated_at=FIXED_TS)
    assert d1.model_dump() == d2.model_dump()
    assert d1.matched_policy_ids == ["alpha", "zebra"]
    assert d1.matched_rule_ids == ["a_rule", "z_rule"]


def test_critical_without_human_approval_denied() -> None:
    policies = [
        Policy(
            policy_id="safety",
            enabled=True,
            rules=[
                Rule(
                    rule_id="critical_needs_human",
                    effect="deny",
                    conditions=RuleConditions(
                        risk_level="critical",
                        requires_human_approval=False,
                    ),
                ),
            ],
        ),
    ]
    bad = _req(risk_level="critical", requires_human_approval=False)
    assert evaluate_action(bad, policies, evaluated_at=FIXED_TS).decision == "deny"

    good = _req(risk_level="critical", requires_human_approval=True)
    assert evaluate_action(good, policies, evaluated_at=FIXED_TS).decision == "allow"


def test_evaluate_policy_cli(tmp_path: Path) -> None:
    req = tmp_path / "request.yaml"
    req.write_text(
        """
agent_id: agt_cli_test_x1
capability: research.query
permission_scope: lab
risk_level: low
""",
        encoding="utf-8",
    )
    pol = tmp_path / "policies.yaml"
    pol.write_text(
        """
policies:
  - policy_id: research
    enabled: true
    rules:
      - rule_id: low_risk_ok
        effect: allow
        conditions:
          risk_level: low
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(app, ["evaluate-policy", str(req), str(pol)])
    assert result.exit_code == 0, result.output
    assert '"decision": "allow"' in result.stdout
    assert "low_risk_ok" in result.stdout
