"""Tests for Phase 3C API key authentication & RBAC."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import sessionmaker

from recklock.api.app import create_app, reset_cached_settings_for_tests
from recklock.api.settings import ApiSettings
from recklock.auth.service import create_api_key, hash_opaque_token
from recklock.db import models as m
from recklock.db.session import create_engine_from_settings

from test_api import _auth, _bootstrap_registry


@pytest.fixture
def rbac_settings(tmp_path: Path) -> ApiSettings:
    reset_cached_settings_for_tests()
    return _bootstrap_registry(tmp_path)


@pytest.fixture
def rbac_client(rbac_settings: ApiSettings) -> TestClient:
    with TestClient(create_app(rbac_settings)) as client:
        yield client


def _issue(settings: ApiSettings, *, name: str, role: str) -> str:
    engine = create_engine_from_settings(settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name=name, role=role)
        session.commit()
    return raw


def test_missing_key_rejected(rbac_client: TestClient) -> None:
    r = rbac_client.get("/agents/")
    assert r.status_code == 401


def test_invalid_key_rejected(rbac_client: TestClient) -> None:
    r = rbac_client.get("/agents/", headers=_auth("atk_invalid_clearly_wrong_token_xxxxx"))
    assert r.status_code == 401


def test_disabled_key_rejected(rbac_settings: ApiSettings, rbac_client: TestClient) -> None:
    engine = create_engine_from_settings(rbac_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, rec = create_api_key(session, name="disabled", role="read_only")
        session.execute(update(m.api_keys).where(m.api_keys.c.key_id == rec.key_id).values(disabled=1))
        session.commit()
    r = rbac_client.get("/agents/", headers=_auth(raw))
    assert r.status_code == 401


def test_role_permission_accepted(rbac_settings: ApiSettings, rbac_client: TestClient) -> None:
    tok = _issue(rbac_settings, name="ro", role="read_only")
    r = rbac_client.get("/agents/", headers=_auth(tok))
    assert r.status_code == 200


def test_role_permission_denied(rbac_settings: ApiSettings, rbac_client: TestClient) -> None:
    tok = _issue(rbac_settings, name="ro", role="read_only")
    r = rbac_client.post(
        "/policies/evaluate",
        json={
            "request": {
                "agent_id": "agt_api-test_a1b2c3d4",
                "capability": "read_public_docs",
                "permission_scope": "workspace.read",
                "risk_level": "low",
            },
            "policies": [],
        },
        headers=_auth(tok),
    )
    assert r.status_code == 403


def test_admin_can_access_all(rbac_settings: ApiSettings, rbac_client: TestClient) -> None:
    tok = _issue(rbac_settings, name="adm", role="admin")
    h = _auth(tok)
    assert rbac_client.get("/agents/", headers=h).status_code == 200
    assert rbac_client.get("/trust/profiles", headers=h).status_code == 200
    assert rbac_client.post("/trust/calculate", headers=h).status_code == 200
    assert rbac_client.get("/audit/events", headers=h).status_code == 200
    assert rbac_client.get("/connectors/", headers=h).status_code == 200
    policy_payload = {
        "request": {
            "agent_id": "agt_api-test_a1b2c3d4",
            "capability": "read_public_docs",
            "permission_scope": "workspace.read",
            "risk_level": "low",
        },
        "policies": [],
    }
    assert rbac_client.post("/policies/evaluate", json=policy_payload, headers=h).status_code == 200


def test_raw_key_not_stored(rbac_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(rbac_settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="probe", role="read_only")
        session.commit()
    db_url = rbac_settings.database_url
    assert db_url.startswith("sqlite:///")
    db_path = Path(db_url.replace("sqlite:///", "", 1))
    on_disk = db_path.read_bytes()
    assert raw.encode("utf-8") not in on_disk
    digest = hash_opaque_token(raw)
    assert digest.encode("ascii") in on_disk
