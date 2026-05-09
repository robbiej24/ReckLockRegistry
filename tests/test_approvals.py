"""Tests for human approval workflows (Phase 2D)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typer.testing import CliRunner

from agenttrust.approvals import (
    approve_request,
    create_approval_request,
    deny_request,
    deterministic_approval_id,
    derive_approval_requirements_from_rules,
    is_request_fully_approved,
    load_approvals,
    maybe_expire_stale_request,
)
from agenttrust.audit import append_event, load_events
from agenttrust.cli import app
from agenttrust.gateway import ExecutionRequest, execute_request, load_registry_index
from agenttrust.policy import Policy, Rule, RuleConditions
from agenttrust.registry import IndexAgentEntry, RegistryIndex

FIXED_TS = datetime(2026, 5, 8, 18, 0, 0, tzinfo=timezone.utc)

MANIFEST_YAML = """
agent_id: agt_appr_a1b2c3d4
name: Approval Test Agent
version: "0.1.0"
developer:
  name: Test Org
description: Minimal manifest for approval tests.
agent_type: assistant
model_providers:
  - openai
capabilities:
  - pay.transfer
permission_scopes:
  - payments.send
risk_level: low
requires_human_approval: false
metadata:
  created_at: "2026-01-01T00:00:00Z"
  updated_at: "2026-05-08T00:00:00Z"
  registry_version: "0.1.0"
"""


def _write_registry(tmp: Path) -> tuple[Path, Path]:
    agents = tmp / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "approval-test.yaml"
    mf.write_text(MANIFEST_YAML.strip() + "\n", encoding="utf-8")
    index_path = tmp / "registry" / "index.json"
    index = RegistryIndex(
        registry_version="0.1.0",
        generated_at="2026-05-08T18:00:00Z",
        agent_count=1,
        agents=[
            IndexAgentEntry(
                agent_id="agt_appr_a1b2c3d4",
                name="Approval Test Agent",
                version="0.1.0",
                developer="Test Org",
                agent_type="assistant",
                risk_level="low",
                capabilities=["pay.transfer"],
                permission_scopes=["payments.send"],
                manifest_path="registry/agents/approval-test.yaml",
                signature_verified=False,
            )
        ],
    )
    index_path.write_text(
        json.dumps(index.model_dump(), indent=2) + "\n",
        encoding="utf-8",
    )
    return tmp, index_path


def _exec_pay(amount: float | None = None, **kwargs: object) -> ExecutionRequest:
    base = dict(
        request_id="req_appr_001",
        agent_id="agt_appr_a1b2c3d4",
        capability="pay.transfer",
        permission_scope="payments.send",
        amount=amount,
    )
    base.update(kwargs)
    return ExecutionRequest.model_validate(base)


def test_derive_named_and_dual_requirements() -> None:
    named_rules = [
        Rule(
            rule_id="r1",
            effect="require_approval",
            conditions=RuleConditions(required_approver_ids=["alice", "bob"]),
        )
    ]
    names, nmin = derive_approval_requirements_from_rules(named_rules)
    assert names == ["alice", "bob"]
    assert nmin >= 1

    dual = [
        Rule(
            rule_id="dual",
            effect="require_approval",
            conditions=RuleConditions(amount_gt=0.0, min_distinct_approvers=2),
        )
    ]
    names2, nmin2 = derive_approval_requirements_from_rules(dual)
    assert names2 == []
    assert nmin2 == 2


def test_dual_approval_requires_distinct_humans(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    aid = deterministic_approval_id(
        request_id="r1",
        agent_id="agt",
        capability="pay.transfer",
        permission_scope="payments.send",
    )
    create_approval_request(
        approval_id=aid,
        request_id="r1",
        agent_id="agt",
        requested_action={"capability": "pay.transfer"},
        required_approvers=[],
        min_distinct_approvers=2,
        created_at=FIXED_TS,
        log_path=log,
    )
    approve_request(aid, "u1", log_path=log, now=FIXED_TS)
    mid = load_approvals(log)[aid]
    assert mid.status == "pending"
    approve_request(aid, "u2", log_path=log, now=FIXED_TS)
    final = load_approvals(log)[aid]
    assert final.status == "approved"


def test_duplicate_approval_rejected(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    aid = deterministic_approval_id(
        request_id="r1",
        agent_id="agt",
        capability="x",
        permission_scope="y",
    )
    create_approval_request(
        approval_id=aid,
        request_id="r1",
        agent_id="agt",
        requested_action={"capability": "x"},
        required_approvers=[],
        min_distinct_approvers=2,
        created_at=FIXED_TS,
        log_path=log,
    )
    approve_request(aid, "alice", log_path=log, now=FIXED_TS)
    try:
        approve_request(aid, "alice", log_path=log, now=FIXED_TS)
    except ValueError as e:
        assert "already recorded" in str(e).lower()
    else:
        raise AssertionError("expected duplicate approval error")


def test_deny_is_terminal(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    aid = deterministic_approval_id(
        request_id="r1",
        agent_id="agt",
        capability="x",
        permission_scope="y",
    )
    create_approval_request(
        approval_id=aid,
        request_id="r1",
        agent_id="agt",
        requested_action={"capability": "x"},
        required_approvers=[],
        min_distinct_approvers=1,
        created_at=FIXED_TS,
        log_path=log,
    )
    deny_request(aid, "carol", log_path=log, now=FIXED_TS)
    assert load_approvals(log)[aid].status == "denied"
    try:
        approve_request(aid, "alice", log_path=log, now=FIXED_TS)
    except ValueError as e:
        assert "not pending" in str(e).lower()
    else:
        raise AssertionError("expected terminal denial")


def test_expire_request_terminal(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    aid = deterministic_approval_id(
        request_id="r1",
        agent_id="agt",
        capability="x",
        permission_scope="y",
    )
    exp = FIXED_TS - timedelta(hours=1)
    create_approval_request(
        approval_id=aid,
        request_id="r1",
        agent_id="agt",
        requested_action={"capability": "x"},
        required_approvers=[],
        min_distinct_approvers=1,
        expires_at=exp,
        created_at=FIXED_TS - timedelta(days=1),
        log_path=log,
    )
    rec = load_approvals(log)[aid]
    final, audit = maybe_expire_stale_request(rec, log_path=log, now=FIXED_TS)
    assert final.status == "expired"
    assert audit is not None


def test_gateway_integration_pending_then_allowed(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="pay",
            enabled=True,
            rules=[
                Rule(
                    rule_id="large",
                    effect="require_approval",
                    conditions=RuleConditions(capability="pay.transfer", amount_gt=50.0),
                ),
            ],
        ),
    ]
    ap_log = tmp_path / "approvals.jsonl"
    req = _exec_pay(amount=100.0)
    first = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    assert first.response.decision == "pending_approval"
    aid = first.response.approval_id
    assert aid

    approve_request(aid, "lead", log_path=ap_log, now=FIXED_TS)

    second = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    assert second.response.decision == "allowed"
    assert aid in second.response.reason


def test_gateway_denied_approval_blocks_execution(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="pay",
            enabled=True,
            rules=[
                Rule(
                    rule_id="large",
                    effect="require_approval",
                    conditions=RuleConditions(capability="pay.transfer", amount_gt=10.0),
                ),
            ],
        ),
    ]
    ap_log = tmp_path / "approvals.jsonl"
    req = _exec_pay(amount=99.0)
    first = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    aid = first.response.approval_id
    assert aid
    deny_request(aid, "lead", log_path=ap_log, now=FIXED_TS)
    second = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    assert second.response.decision == "denied"
    assert "denied" in second.response.reason.lower()


def test_audit_events_from_cli_approve(tmp_path: Path) -> None:
    yaml_path = tmp_path / "create.yaml"
    yaml_path.write_text(
        "request_id: r_cli\n"
        "agent_id: agt_appr_a1b2c3d4\n"
        "requested_action:\n"
        "  capability: pay.transfer\n"
        "  permission_scope: payments.send\n"
        "required_approvers:\n"
        "  - sam\n",
        encoding="utf-8",
    )
    ap_log = tmp_path / "ap.jsonl"
    audit_log = tmp_path / "audit.log"
    runner = CliRunner()
    r1 = runner.invoke(
        app,
        ["create-approval", str(yaml_path), "--approvals-log", str(ap_log), "--audit-log", str(audit_log)],
    )
    assert r1.exit_code == 0, r1.output
    aid = json.loads(r1.stdout)["approval_id"]
    r2 = runner.invoke(
        app,
        [
            "approve-request",
            aid,
            "--approver",
            "sam",
            "--approvals-log",
            str(ap_log),
            "--audit-log",
            str(audit_log),
        ],
    )
    assert r2.exit_code == 0, r2.output
    events = load_events(audit_log)
    types = [e.event_type for e in events]
    assert "approval.created" in types
    assert "approval.signoff" in types
    assert "approval.resolved" in types


def test_is_request_fully_approved_named(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    aid = deterministic_approval_id(
        request_id="r1",
        agent_id="agt",
        capability="pay.transfer",
        permission_scope="payments.send",
    )
    create_approval_request(
        approval_id=aid,
        request_id="r1",
        agent_id="agt",
        requested_action={"capability": "pay.transfer"},
        required_approvers=["a", "b"],
        min_distinct_approvers=2,
        created_at=FIXED_TS,
        log_path=log,
    )
    cur = load_approvals(log)[aid]
    assert not is_request_fully_approved(cur, now=FIXED_TS)
    approve_request(aid, "a", log_path=log, now=FIXED_TS)
    mid = load_approvals(log)[aid]
    assert not is_request_fully_approved(mid, now=FIXED_TS)
    approve_request(aid, "b", log_path=log, now=FIXED_TS)
    done = load_approvals(log)[aid]
    assert is_request_fully_approved(done, now=FIXED_TS)


def test_gateway_emits_approval_audit_pipe(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="pay",
            enabled=True,
            rules=[
                Rule(
                    rule_id="large",
                    effect="require_approval",
                    conditions=RuleConditions(capability="pay.transfer", amount_gt=1.0),
                ),
            ],
        ),
    ]
    ap_log = tmp_path / "approvals.jsonl"
    audit_log = tmp_path / "audit.log"
    first = execute_request(
        _exec_pay(amount=50.0),
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    assert first.approval_audit_events
    append_event(first.audit_event, log_path=audit_log)
    for ev in first.approval_audit_events:
        append_event(ev, log_path=audit_log)
    types = [e.event_type for e in load_events(audit_log)]
    assert "gateway.execution" in types
    assert "approval.created" in types
