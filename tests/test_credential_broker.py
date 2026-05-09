"""Tests for the Phase 3E temporary credential broker."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from agenttrust.api.app import create_app, reset_cached_settings_for_tests
from agenttrust.api.settings import ApiSettings
from agenttrust.approvals import deterministic_approval_id
from agenttrust.auth.service import create_api_key
from agenttrust.credentials.broker import issue_credential, revoke_credential, verify_credential
from agenttrust.credentials.models import CredentialRequest
from agenttrust.db.init_db import init_database
from agenttrust.db import models as m
from agenttrust.db.repositories import approve_request_db, list_audit_events
from agenttrust.db.session import create_engine_from_settings
from agenttrust.gateway import RegistryIndex
from agenttrust.policy import Policy, Rule, RuleConditions
from agenttrust.registry import IndexAgentEntry

from test_api import _auth

MANIFEST_CRED = """
agent_id: agt_cred-test_a1b2c3d4
name: Cred Test Agent
version: "0.1.0"
developer:
  name: Test Org
description: Credential broker tests.
agent_type: assistant
model_providers:
  - openai
capabilities:
  - credential.issue
permission_scopes:
  - workspace.read
risk_level: low
requires_human_approval: false
metadata:
  created_at: "2026-01-01T00:00:00Z"
  updated_at: "2026-05-08T00:00:00Z"
  registry_version: "0.1.0"
"""


def _bootstrap_cred(tmp: Path) -> ApiSettings:
    agents = tmp / "registry" / "agents"
    agents.mkdir(parents=True)
    mf = agents / "cred-test.yaml"
    mf.write_text(MANIFEST_CRED.strip() + "\n", encoding="utf-8")
    index_path = tmp / "registry" / "index.json"
    index = RegistryIndex(
        registry_version="0.1.0",
        generated_at="2026-05-08T16:00:00Z",
        agent_count=1,
        agents=[
            IndexAgentEntry(
                agent_id="agt_cred-test_a1b2c3d4",
                name="Cred Test Agent",
                version="0.1.0",
                developer="Test Org",
                agent_type="assistant",
                risk_level="low",
                capabilities=["credential.issue"],
                permission_scopes=["workspace.read"],
                manifest_path="registry/agents/cred-test.yaml",
                signature_verified=False,
            )
        ],
    )
    index_path.write_text(json.dumps(index.model_dump(), indent=2) + "\n", encoding="utf-8")
    audit = tmp / "audit_logs" / "events.log"
    approvals = tmp / "approval_logs" / "approvals.jsonl"
    trust_profiles = tmp / "trust_data" / "trust_profiles.jsonl"
    incidents = tmp / "trust_data" / "incidents.jsonl"
    db_path = tmp / "cred_test.db"
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


def _allow_policy() -> Policy:
    return Policy(
        policy_id="cred_allow",
        enabled=True,
        rules=[
            Rule(
                rule_id="allow_cred",
                effect="allow",
                conditions=RuleConditions(capability="credential.issue", permission_scope="workspace.read"),
            ),
        ],
    )


def _deny_policy() -> Policy:
    return Policy(
        policy_id="cred_deny",
        enabled=True,
        rules=[
            Rule(rule_id="deny_all", effect="deny", conditions=None),
        ],
    )


def _require_approval_policy() -> Policy:
    return Policy(
        policy_id="cred_appr",
        enabled=True,
        rules=[
            Rule(
                rule_id="need_human",
                effect="require_approval",
                conditions=RuleConditions(capability="credential.issue"),
            ),
        ],
    )


@pytest.fixture
def cred_settings(tmp_path: Path) -> ApiSettings:
    reset_cached_settings_for_tests()
    return _bootstrap_cred(tmp_path)


@pytest.fixture
def cred_client(cred_settings: ApiSettings) -> TestClient:
    with TestClient(create_app(cred_settings)) as client:
        yield client


def _admin_token(settings: ApiSettings) -> str:
    engine = create_engine_from_settings(settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="cred admin", role="admin")
        session.commit()
    return raw


def test_issue_after_allow_policy(cred_settings: ApiSettings, cred_client: TestClient) -> None:
    tok = _admin_token(cred_settings)
    body = {
        "credential": {
            "agent_id": "agt_cred-test_a1b2c3d4",
            "requested_scopes": ["workspace.read"],
            "resource": "svc/db/read-only",
            "environment": "staging",
            "duration_seconds": 600,
            "request_id": "req_cred_001",
        },
        "policies": [_allow_policy().model_dump(mode="json")],
    }
    r = cred_client.post("/credentials/request", json=body, headers=_auth(tok))
    assert r.status_code == 200
    payload = r.json()
    assert payload["outcome"] == "issued"
    assert payload["token"]
    assert payload["credential_id"].startswith("cred_")


def test_denied_policy_blocks(cred_settings: ApiSettings, cred_client: TestClient) -> None:
    tok = _admin_token(cred_settings)
    body = {
        "credential": {
            "agent_id": "agt_cred-test_a1b2c3d4",
            "requested_scopes": ["workspace.read"],
            "resource": "svc/db",
            "environment": "staging",
            "request_id": "req_cred_deny",
        },
        "policies": [_deny_policy().model_dump(mode="json")],
    }
    r = cred_client.post("/credentials/request", json=body, headers=_auth(tok))
    assert r.status_code == 200
    assert r.json()["outcome"] == "denied"
    assert r.json().get("token") is None


def test_token_hash_stored_not_raw_secret(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_allow_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="store/hash-test",
        environment="staging",
        request_id="req_hash",
    )
    raw_token = ""
    with SessionLocal() as session:
        index = RegistryIndex.model_validate_json(
            (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
        )
        out = issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
        raw_token = out.token or ""
        assert raw_token
    db_url = cred_settings.database_url
    assert db_url.startswith("sqlite:///")
    db_path = Path(db_url.replace("sqlite:///", "", 1))
    on_disk = db_path.read_bytes()
    assert raw_token.encode("utf-8") not in on_disk


def test_expired_fails_verification(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_allow_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="ttl-short",
        environment="staging",
        duration_seconds=1,
        request_id="req_ttl",
    )
    index = RegistryIndex.model_validate_json(
        (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
    )
    with SessionLocal() as session:
        out = issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
        tok = out.token
    assert tok
    time.sleep(2.1)
    with SessionLocal() as session:
        v = verify_credential(session, tok)
        session.commit()
    assert v.valid is False


def test_revoked_fails_verification(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_allow_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="revoke-me",
        environment="staging",
        request_id="req_revoke",
    )
    index = RegistryIndex.model_validate_json(
        (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
    )
    with SessionLocal() as session:
        out = issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
        cid = out.credential_id
        tok = out.token
    assert cid and tok
    with SessionLocal() as session:
        revoke_credential(session, cid, actor_id="human")
        session.commit()
    with SessionLocal() as session:
        v = verify_credential(session, tok)
        session.commit()
    assert v.valid is False


def test_approval_required_then_issue(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_require_approval_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="needs-ok",
        environment="staging",
        request_id="req_appr_flow",
    )
    index = RegistryIndex.model_validate_json(
        (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
    )
    approval_id = deterministic_approval_id(
        request_id="req_appr_flow",
        agent_id=req.agent_id,
        capability="credential.issue",
        permission_scope="workspace.read",
    )
    with SessionLocal() as session:
        first = issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
    assert first.outcome == "pending_approval"

    with SessionLocal() as session:
        approve_request_db(session, approval_id, "alice")
        session.commit()

    with SessionLocal() as session:
        second = issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
    assert second.outcome == "issued"
    assert second.token


def test_audit_events_generated(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_allow_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="audit",
        environment="staging",
        request_id="req_audit_ev",
    )
    index = RegistryIndex.model_validate_json(
        (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
    )
    with SessionLocal() as session:
        issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
        events = list_audit_events(session)
    types = {e.event_type for e in events}
    assert "credential.requested" in types
    assert "credential.issued" in types


def test_db_row_has_hash_column_only(cred_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(cred_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    policies = [_allow_policy()]
    req = CredentialRequest(
        agent_id="agt_cred-test_a1b2c3d4",
        requested_scopes=["workspace.read"],
        resource="columns",
        environment="staging",
        request_id="req_cols",
    )
    index = RegistryIndex.model_validate_json(
        (cred_settings.registry_root / "registry" / "index.json").read_text(encoding="utf-8")
    )
    with SessionLocal() as session:
        issue_credential(
            session,
            req,
            policies,
            registry_root=cred_settings.registry_root,
            registry_index=index,
            issued_by="test",
        )
        session.commit()
        conn = session.connection()
        row = conn.execute(select(m.temporary_credentials)).first()
    assert row is not None
    assert hasattr(row, "_mapping")
    keys = set(row._mapping.keys())
    assert "token_hash" in keys
    assert "token" not in keys
