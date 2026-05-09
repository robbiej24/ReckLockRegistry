"""Tests for Phase 3D connector framework & gateway integration."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from agenttrust.api.app import create_app, reset_cached_settings_for_tests
from agenttrust.api.settings import ApiSettings
from agenttrust.auth.service import create_api_key
from agenttrust.cli import app as cli_app
from agenttrust.connectors.base import real_connectors_enabled
from agenttrust.connectors.registry import get_connector, list_connector_descriptors
from agenttrust.db.session import create_engine_from_settings
from agenttrust.gateway import ExecutionRequest, execute_request, load_registry_index
from agenttrust.policy import Policy, Rule, RuleConditions
from agenttrust.registry import IndexAgentEntry, RegistryIndex

from test_api import _auth, _bootstrap_registry


@pytest.fixture
def conn_settings(tmp_path: Path) -> ApiSettings:
    reset_cached_settings_for_tests()
    return _bootstrap_registry(tmp_path)


@pytest.fixture
def conn_admin_token(conn_settings: ApiSettings) -> str:
    engine = create_engine_from_settings(conn_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="Conn Admin", role="admin")
        session.commit()
    return raw


@pytest.fixture
def conn_client(conn_settings: ApiSettings) -> TestClient:
    with TestClient(create_app(conn_settings)) as client:
        yield client


def test_registry_lists_connectors() -> None:
    rows = list_connector_descriptors()
    ids = {r["connector_id"] for r in rows}
    assert ids >= {"mock", "github", "slack", "email"}
    mock_row = next(r for r in rows if r["connector_id"] == "mock")
    assert "echo" in mock_row["supported_capabilities"]


def test_mock_connector_dry_run() -> None:
    m = get_connector("mock")
    assert m is not None
    from agenttrust.connectors.base import ConnectorRequest

    req = ConnectorRequest(
        connector_id="mock",
        action="echo",
        agent_id="agt_x",
        capability="test",
        permission_scope="*",
        config={"hello": "world"},
        dry_run=True,
    )
    out = m.dry_run(req)
    assert out.success
    assert out.dry_run is True


def test_disabled_real_connector_execution_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTTRUST_ENABLE_REAL_CONNECTORS", raising=False)
    assert real_connectors_enabled() is False
    gh = get_connector("github")
    assert gh is not None
    from agenttrust.connectors.base import ConnectorRequest

    req = ConnectorRequest(
        connector_id="github",
        action="create_issue",
        agent_id="agt_x",
        capability="issue.create",
        permission_scope="workspace.write",
        config={"repository": "org/repo", "title": "t"},
        dry_run=False,
    )
    out = gh.execute(req)
    assert out.success is False
    assert "disabled" in out.message.lower() or "Real GitHub" in out.message


def test_gateway_routes_allowed_connector_request(tmp_path: Path) -> None:
    agents = tmp_path / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "c.yaml"
    mf.write_text(
        dedent(
            """
            agent_id: agt_conn-test_a1b2c3d4
            name: C
            version: "0.1.0"
            developer:
              name: T
            description: x
            agent_type: assistant
            model_providers:
              - openai
            capabilities:
              - ops.echo
            permission_scopes:
              - workspace.ops
            risk_level: low
            requires_human_approval: false
            metadata:
              created_at: "2026-01-01T00:00:00Z"
              updated_at: "2026-05-08T00:00:00Z"
              registry_version: "0.1.0"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    index_path = tmp_path / "registry" / "index.json"
    index_path.write_text(
        json.dumps(
            RegistryIndex(
                registry_version="0.1.0",
                generated_at="2026-05-08T16:00:00Z",
                agent_count=1,
                agents=[
                    IndexAgentEntry(
                        agent_id="agt_conn-test_a1b2c3d4",
                        name="C",
                        version="0.1.0",
                        developer="T",
                        agent_type="assistant",
                        risk_level="low",
                        capabilities=["ops.echo"],
                        permission_scopes=["workspace.ops"],
                        manifest_path="registry/agents/c.yaml",
                        signature_verified=False,
                    )
                ],
            ).model_dump(),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    policies = [
        Policy(
            policy_id="p",
            enabled=True,
            rules=[
                Rule(
                    rule_id="allow_echo",
                    effect="allow",
                    conditions=RuleConditions(capability="ops.echo"),
                ),
            ],
        ),
    ]
    req = ExecutionRequest(
        request_id="req_conn_1",
        agent_id="agt_conn-test_a1b2c3d4",
        capability="ops.echo",
        permission_scope="workspace.ops",
        connector_id="mock",
        connector_action="echo",
        connector_config={"note": "x"},
        dry_run=True,
    )
    out = execute_request(
        req,
        policies,
        load_registry_index(index_path),
        registry_root=tmp_path,
        approval_log_path=tmp_path / "ap.jsonl",
    )
    assert out.response.decision == "allowed"
    assert out.response.connector is not None
    assert out.response.connector.connector_id == "mock"
    assert out.response.connector.success is True
    assert out.audit_event.metadata and out.audit_event.metadata.get("connector_result")


def test_denied_policy_skips_connector(tmp_path: Path) -> None:
    """Denied gateway decision must not invoke connector."""
    agents = tmp_path / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "d.yaml"
    mf.write_text(
        dedent(
            """
            agent_id: agt_denied-test_a1b2c3d4
            name: D
            version: "0.1.0"
            developer:
              name: T
            description: x
            agent_type: assistant
            model_providers:
              - openai
            capabilities:
              - ops.echo
            permission_scopes:
              - workspace.ops
            risk_level: low
            requires_human_approval: false
            metadata:
              created_at: "2026-01-01T00:00:00Z"
              updated_at: "2026-05-08T00:00:00Z"
              registry_version: "0.1.0"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    index_path = tmp_path / "registry" / "index.json"
    index_path.write_text(
        json.dumps(
            RegistryIndex(
                registry_version="0.1.0",
                generated_at="2026-05-08T16:00:00Z",
                agent_count=1,
                agents=[
                    IndexAgentEntry(
                        agent_id="agt_denied-test_a1b2c3d4",
                        name="D",
                        version="0.1.0",
                        developer="T",
                        agent_type="assistant",
                        risk_level="low",
                        capabilities=["ops.echo"],
                        permission_scopes=["workspace.ops"],
                        manifest_path="registry/agents/d.yaml",
                        signature_verified=False,
                    )
                ],
            ).model_dump(),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    policies = [
        Policy(
            policy_id="block",
            enabled=True,
            rules=[
                Rule(
                    rule_id="deny_all",
                    effect="deny",
                    conditions=RuleConditions(capability="ops.echo"),
                ),
            ],
        ),
    ]
    req = ExecutionRequest(
        request_id="req_denied_conn",
        agent_id="agt_denied-test_a1b2c3d4",
        capability="ops.echo",
        permission_scope="workspace.ops",
        connector_id="mock",
        connector_action="echo",
        connector_config={},
        dry_run=True,
    )
    out = execute_request(
        req,
        policies,
        load_registry_index(index_path),
        registry_root=tmp_path,
        approval_log_path=tmp_path / "ap2.jsonl",
    )
    assert out.response.decision == "denied"
    assert out.response.connector is None


def test_no_secrets_in_connector_metadata(tmp_path: Path) -> None:
    agents = tmp_path / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "s.yaml"
    mf.write_text(
        dedent(
            """
            agent_id: agt_secret-test_a1b2c3d4
            name: S
            version: "0.1.0"
            developer:
              name: T
            description: x
            agent_type: assistant
            model_providers:
              - openai
            capabilities:
              - ops.echo
            permission_scopes:
              - workspace.ops
            risk_level: low
            requires_human_approval: false
            metadata:
              created_at: "2026-01-01T00:00:00Z"
              updated_at: "2026-05-08T00:00:00Z"
              registry_version: "0.1.0"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    index_path = tmp_path / "registry" / "index.json"
    index_path.write_text(
        json.dumps(
            RegistryIndex(
                registry_version="0.1.0",
                generated_at="2026-05-08T16:00:00Z",
                agent_count=1,
                agents=[
                    IndexAgentEntry(
                        agent_id="agt_secret-test_a1b2c3d4",
                        name="S",
                        version="0.1.0",
                        developer="T",
                        agent_type="assistant",
                        risk_level="low",
                        capabilities=["ops.echo"],
                        permission_scopes=["workspace.ops"],
                        manifest_path="registry/agents/s.yaml",
                        signature_verified=False,
                    )
                ],
            ).model_dump(),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    policies = [
        Policy(
            policy_id="p",
            enabled=True,
            rules=[
                Rule(rule_id="a", effect="allow", conditions=RuleConditions(capability="ops.echo")),
            ],
        ),
    ]
    req = ExecutionRequest(
        request_id="req_sec",
        agent_id="agt_secret-test_a1b2c3d4",
        capability="ops.echo",
        permission_scope="workspace.ops",
        connector_id="mock",
        connector_action="echo",
        connector_config={"api_token": "supersecret", "nested": {"password": "p"}},
        dry_run=True,
    )
    out = execute_request(
        req,
        policies,
        load_registry_index(index_path),
        registry_root=tmp_path,
        approval_log_path=tmp_path / "ap3.jsonl",
    )
    meta = json.dumps(out.audit_event.metadata, sort_keys=True)
    assert "supersecret" not in meta
    assert "[redacted]" in meta


def test_api_list_connectors(conn_client: TestClient, conn_admin_token: str) -> None:
    r = conn_client.get("/connectors/", headers=_auth(conn_admin_token))
    assert r.status_code == 200
    assert any(row["connector_id"] == "mock" for row in r.json())


def test_cli_list_connectors() -> None:
    runner = CliRunner()
    res = runner.invoke(cli_app, ["list-connectors"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)


def test_cli_connector_dry_run(tmp_path: Path) -> None:
    y = tmp_path / "cr.yaml"
    y.write_text(
        """
connector_id: mock
action: noop
agent_id: agt_x
capability: connector.invoke
permission_scope: "*"
config: {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(cli_app, ["connector-dry-run", str(y)])
    assert res.exit_code == 0
    body = json.loads(res.stdout)
    assert body["success"] is True
