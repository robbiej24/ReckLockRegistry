"""Tests for the Phase 3A FastAPI runtime."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import pytest
import httpx
from fastapi.testclient import TestClient

from agenttrust.api.app import create_app, reset_cached_settings_for_tests
from agenttrust.api.settings import ApiSettings
from agenttrust.approvals import deterministic_approval_id
from agenttrust.auth.service import create_api_key
from agenttrust.db.init_db import init_database
from agenttrust.db.repositories import create_approval_request_db
from agenttrust.db.session import create_engine_from_settings
from sqlalchemy.orm import sessionmaker
from agenttrust.gateway import ExecutionRequest, RegistryIndex
from agenttrust.policy import Policy, Rule, RuleConditions
from agenttrust.registry import IndexAgentEntry

MANIFEST_YAML = """
agent_id: agt_api-test_a1b2c3d4
name: API Test Agent
version: "0.1.0"
developer:
  name: Test Org
description: Minimal manifest for API tests.
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_registry(tmp: Path) -> ApiSettings:
    agents = tmp / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "api-test.yaml"
    mf.write_text(MANIFEST_YAML.strip() + "\n", encoding="utf-8")
    index_path = tmp / "registry" / "index.json"
    index = RegistryIndex(
        registry_version="0.1.0",
        generated_at="2026-05-08T16:00:00Z",
        agent_count=1,
        agents=[
            IndexAgentEntry(
                agent_id="agt_api-test_a1b2c3d4",
                name="API Test Agent",
                version="0.1.0",
                developer="Test Org",
                agent_type="assistant",
                risk_level="low",
                capabilities=["read_public_docs", "pay.transfer"],
                permission_scopes=["workspace.read", "payments.send"],
                manifest_path="registry/agents/api-test.yaml",
                signature_verified=False,
            )
        ],
    )
    index_path.write_text(
        json.dumps(index.model_dump(), indent=2) + "\n",
        encoding="utf-8",
    )
    audit = tmp / "audit_logs" / "events.log"
    approvals = tmp / "approval_logs" / "approvals.jsonl"
    trust_profiles = tmp / "trust_data" / "trust_profiles.jsonl"
    incidents = tmp / "trust_data" / "incidents.jsonl"
    db_path = tmp / "api_test.db"
    db_url = f"sqlite:///{db_path}"
    init_database(db_url)
    return ApiSettings(
        registry_root=tmp,
        audit_log_path=audit.relative_to(tmp),
        approval_log_path=approvals.relative_to(tmp),
        trust_profiles_path=trust_profiles.relative_to(tmp),
        incidents_path=incidents.relative_to(tmp),
        database_url=db_url,
    )


def _write_registry(tmp: Path) -> tuple[ApiSettings, str]:
    settings = _bootstrap_registry(tmp)
    engine = create_engine_from_settings(settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="API Test Admin", role="admin")
        session.commit()
    return settings, raw


@pytest.fixture
def api_bundle(tmp_path: Path) -> tuple[ApiSettings, str]:
    reset_cached_settings_for_tests()
    return _write_registry(tmp_path)


@pytest.fixture
def api_settings(api_bundle: tuple[ApiSettings, str]) -> ApiSettings:
    return api_bundle[0]


@pytest.fixture
def admin_token(api_bundle: tuple[ApiSettings, str]) -> str:
    return api_bundle[1]


@pytest.fixture
def client(api_settings: ApiSettings) -> TestClient:
    app = create_app(api_settings)
    with TestClient(app) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "agenttrust-api"


def test_list_agents(client: TestClient, admin_token: str) -> None:
    r = client.get("/agents/", headers=_auth(admin_token))
    assert r.status_code == 200
    agents = r.json()
    assert len(agents) == 1
    assert agents[0]["agent_id"] == "agt_api-test_a1b2c3d4"


def test_get_agent(client: TestClient, admin_token: str) -> None:
    r = client.get("/agents/agt_api-test_a1b2c3d4", headers=_auth(admin_token))
    assert r.status_code == 200
    assert r.json()["name"] == "API Test Agent"


def test_evaluate_policy(client: TestClient, admin_token: str) -> None:
    payload = {
        "request": {
            "agent_id": "agt_api-test_a1b2c3d4",
            "capability": "read_public_docs",
            "permission_scope": "workspace.read",
            "risk_level": "low",
        },
        "policies": [
            {
                "policy_id": "p1",
                "enabled": True,
                "rules": [
                    {
                        "rule_id": "r1",
                        "effect": "allow",
                        "conditions": {"capability": "read_public_docs"},
                    },
                ],
            },
        ],
    }
    r = client.post("/policies/evaluate", json=payload, headers=_auth(admin_token))
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"


def test_execution_appends_audit_event(
    client: TestClient, api_settings: ApiSettings, admin_token: str
) -> None:
    req = ExecutionRequest(
        request_id="req_api_001",
        agent_id="agt_api-test_a1b2c3d4",
        capability="read_public_docs",
        permission_scope="workspace.read",
    )
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
    r = client.post(
        "/execution/request",
        json={
            "request": req.model_dump(mode="json"),
            "policies": [p.model_dump(mode="json") for p in policies],
        },
        headers=_auth(admin_token),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["response"]["decision"] == "allowed"
    assert body["appended_audit_event_hashes"]

    ev = client.get("/audit/events", headers=_auth(admin_token))
    assert ev.status_code == 200
    events = ev.json()
    assert len(events) >= 1
    assert events[-1]["event_type"] == "gateway.execution"


def test_approval_approve_and_deny(
    client: TestClient,
    api_settings: ApiSettings,
    admin_token: str,
) -> None:
    approval_id = deterministic_approval_id(
        request_id="req_apr",
        agent_id="agt_api-test_a1b2c3d4",
        capability="pay.transfer",
        permission_scope="payments.send",
    )
    engine = create_engine_from_settings(api_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        create_approval_request_db(
            session,
            approval_id=approval_id,
            request_id="req_apr",
            agent_id="agt_api-test_a1b2c3d4",
            requested_action={
                "capability": "pay.transfer",
                "permission_scope": "payments.send",
            },
            required_approvers=[],
            min_distinct_approvers=1,
        )
        session.commit()

    listed = client.get("/approvals/", headers=_auth(admin_token))
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    appr = client.post(
        f"/approvals/{approval_id}/approve",
        json={"approver": "alice"},
        headers=_auth(admin_token),
    )
    assert appr.status_code == 200
    assert appr.json()["status"] == "approved"

    approval_id_2 = deterministic_approval_id(
        request_id="req_apr2",
        agent_id="agt_api-test_a1b2c3d4",
        capability="read_public_docs",
        permission_scope="workspace.read",
    )
    with SessionLocal() as session:
        create_approval_request_db(
            session,
            approval_id=approval_id_2,
            request_id="req_apr2",
            agent_id="agt_api-test_a1b2c3d4",
            requested_action={
                "capability": "read_public_docs",
                "permission_scope": "workspace.read",
            },
            required_approvers=[],
            min_distinct_approvers=1,
        )
        session.commit()

    deny_r = client.post(
        f"/approvals/{approval_id_2}/deny",
        json={"approver": "bob"},
        headers=_auth(admin_token),
    )
    assert deny_r.status_code == 200
    assert deny_r.json()["status"] == "denied"


def test_trust_profiles_and_calculate(client: TestClient, admin_token: str) -> None:
    prof = client.get("/trust/profiles", headers=_auth(admin_token))
    assert prof.status_code == 200
    assert prof.json() == []

    calc = client.post("/trust/calculate", headers=_auth(admin_token))
    assert calc.status_code == 200
    assert calc.json() == {}


def test_health_via_httpx_asgi(api_settings: ApiSettings) -> None:
    app = create_app(api_settings)
    transport = httpx.ASGITransport(app=app)

    async def _run() -> None:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as h:
            r = await h.get("/health")
            assert r.status_code == 200
            assert r.json()["status"] == "ok"

    asyncio.run(_run())
