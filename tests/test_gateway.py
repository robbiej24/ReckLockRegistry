"""Tests for the local execution gateway (Phase 2C)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from recklock.cli import app
from recklock.gateway import ExecutionRequest, execute_request, load_registry_index
from recklock.policy import Policy, Rule, RuleConditions
from recklock.registry import IndexAgentEntry, RegistryIndex

FIXED_TS = datetime(2026, 5, 8, 16, 0, 0, tzinfo=timezone.utc)

MANIFEST_YAML = """
agent_id: agt_gateway-test_a1b2c3d4
name: Gateway Test Agent
version: "0.1.0"
developer:
  name: Test Org
description: Minimal manifest for gateway tests.
agent_type: assistant
model_providers:
  - openai
capabilities:
  - read_public_docs
  - pay.transfer
permission_scopes:
  - workspace.read
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
    mf = agents / "gateway-test.yaml"
    mf.write_text(MANIFEST_YAML.strip() + "\n", encoding="utf-8")
    index_path = tmp / "registry" / "index.json"
    index = RegistryIndex(
        registry_version="0.1.0",
        generated_at="2026-05-08T16:00:00Z",
        agent_count=1,
        agents=[
            IndexAgentEntry(
                agent_id="agt_gateway-test_a1b2c3d4",
                name="Gateway Test Agent",
                version="0.1.0",
                developer="Test Org",
                agent_type="assistant",
                risk_level="low",
                capabilities=["read_public_docs", "pay.transfer"],
                permission_scopes=["workspace.read", "payments.send"],
                manifest_path="registry/agents/gateway-test.yaml",
                signature_verified=False,
            )
        ],
    )
    index_path.write_text(
        json.dumps(index.model_dump(), indent=2) + "\n",
        encoding="utf-8",
    )
    return tmp, index_path


def _exec_req(**kwargs: object) -> ExecutionRequest:
    base = dict(
        request_id="req_gateway_001",
        agent_id="agt_gateway-test_a1b2c3d4",
        capability="read_public_docs",
        permission_scope="workspace.read",
    )
    base.update(kwargs)
    return ExecutionRequest.model_validate(base)


def test_unknown_agent_denied(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies: list[Policy] = []
    req = _exec_req(agent_id="agt_nope_not_registered")
    out = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=tmp_path / "approvals.jsonl",
    )
    assert out.response.decision == "denied"
    assert "Unknown agent_id" in out.response.reason
    assert out.audit_event.decision == "denied"
    assert out.audit_event.event_id == out.response.audit_event_id


def test_allowed_request_succeeds(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="open",
            enabled=True,
            rules=[
                Rule(
                    rule_id="allow_reads",
                    effect="allow",
                    conditions=RuleConditions(capability="read_public_docs"),
                ),
            ],
        ),
    ]
    req = _exec_req()
    out = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=tmp_path / "approvals.jsonl",
    )
    assert out.response.decision == "allowed"
    assert out.audit_event.decision == "allowed"
    assert out.response.audit_event_id == out.audit_event.event_id


def test_denied_request_blocked(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="block",
            enabled=True,
            rules=[
                Rule(
                    rule_id="deny_pay",
                    effect="deny",
                    conditions=RuleConditions(capability="pay.transfer"),
                ),
            ],
        ),
    ]
    req = _exec_req(capability="pay.transfer", permission_scope="payments.send")
    out = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=tmp_path / "approvals.jsonl",
    )
    assert out.response.decision == "denied"
    assert out.audit_event.decision == "denied"
    assert "Denied by matched rule" in out.response.reason


def test_approval_request_pending(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="pay",
            enabled=True,
            rules=[
                Rule(
                    rule_id="approve_large",
                    effect="require_approval",
                    conditions=RuleConditions(capability="pay.transfer", amount_gt=100.0),
                ),
            ],
        ),
    ]
    req = _exec_req(
        capability="pay.transfer",
        permission_scope="payments.send",
        amount=500.0,
    )
    ap_log = tmp_path / "approvals.jsonl"
    out = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap_log,
    )
    assert out.response.decision == "pending_approval"
    assert out.audit_event.decision == "pending_approval"
    assert out.response.approval_id
    assert ap_log.is_file()
    assert out.approval_audit_events


def test_audit_events_generated_and_append_cli(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    req_yaml = tmp_path / "exec.yaml"
    req_yaml.write_text(
        """
request_id: req_audit_cli
agent_id: agt_gateway-test_a1b2c3d4
capability: read_public_docs
permission_scope: workspace.read
""".strip()
        + "\n",
        encoding="utf-8",
    )
    pol_yaml = tmp_path / "policies.yaml"
    pol_yaml.write_text(
        """
policies:
  - policy_id: open
    enabled: true
    rules:
      - rule_id: allow_low
        effect: allow
        conditions:
          risk_level: low
""".strip()
        + "\n",
        encoding="utf-8",
    )
    log = tmp_path / "events.log"
    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "execute-request",
            str(req_yaml),
            str(pol_yaml),
            "--index",
            str(index_path),
            "--root",
            str(root),
            "--log",
            str(log),
            "--approvals-log",
            str(tmp_path / "approvals.jsonl"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert '"decision": "allowed"' in r.stdout
    assert "appended_audit_event_hash" in r.stdout
    assert log.is_file()
    text = log.read_text(encoding="utf-8").strip()
    assert text
    line = json.loads(text.splitlines()[-1])
    assert line["event_type"] == "gateway.execution"
    assert line["decision"] == "allowed"


def test_deterministic_gateway_behavior(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    policies = [
        Policy(
            policy_id="z",
            enabled=True,
            rules=[Rule(rule_id="z_rule", effect="allow", conditions=RuleConditions(risk_level="low"))],
        ),
    ]
    req = _exec_req()
    ap = tmp_path / "approvals.jsonl"
    a = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap,
    )
    b = execute_request(
        req,
        policies,
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=ap,
    )
    assert a.response.model_dump() == b.response.model_dump()
    assert a.audit_event.model_dump() == b.audit_event.model_dump()


def test_capability_not_in_manifest_denied(tmp_path: Path) -> None:
    root, index_path = _write_registry(tmp_path)
    idx = load_registry_index(index_path)
    req = _exec_req(capability="undeclared.capability")
    out = execute_request(
        req,
        [],
        idx,
        registry_root=root,
        evaluated_at=FIXED_TS,
        approval_log_path=tmp_path / "approvals.jsonl",
    )
    assert out.response.decision == "denied"
    assert "not declared in the agent manifest" in out.response.reason
