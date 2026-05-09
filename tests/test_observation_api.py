"""Observation API routes tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agenttrust.api.app import create_app, reset_cached_settings_for_tests
from agenttrust.api.settings import ApiSettings
from agenttrust.auth.service import create_api_key
from agenttrust.db.init_db import init_database
from agenttrust.db.session import create_engine_from_settings
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def obs_settings(tmp_path: Path) -> ApiSettings:
    reset_cached_settings_for_tests()
    db_path = tmp_path / "obs.db"
    db_url = f"sqlite:///{db_path}"
    init_database(db_url)
    return ApiSettings(
        registry_root=tmp_path,
        database_url=db_url,
        observation_mode=True,
    )


@pytest.fixture
def obs_client(obs_settings: ApiSettings) -> TestClient:
    with TestClient(create_app(obs_settings)) as client:
        yield client


def _tok(settings: ApiSettings, *, role: str) -> str:
    engine = create_engine_from_settings(settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="obs", role=role)
        session.commit()
    return raw


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_telemetry_observation_accepted(obs_settings: ApiSettings, obs_client: TestClient, tmp_path: Path) -> None:
    tok = _tok(obs_settings, role="developer")
    r = obs_client.post(
        "/telemetry/observation",
        headers=_auth(tok),
        json={
            "agent_id": "agt_api_obs_abcd1234",
            "action": "invoke",
            "capability": "llm_inference",
            "permission_scope": "ai.invoke",
        },
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload.get("accepted") is True
    log = tmp_path / "evidence" / "observation_events.jsonl"
    assert log.is_file()


def test_evidence_report_endpoint(obs_settings: ApiSettings, obs_client: TestClient, tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir(parents=True)
    log = ev / "observation_events.jsonl"
    log.write_text(
        json.dumps(
            {
                "event_kind": "observation",
                "ts": "2099-01-01T00:00:00Z",
                "agent_id": "agt_z_abcd1234",
                "action": "tick",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    tok = _tok(obs_settings, role="read_only")
    r = obs_client.get("/evidence/report?days=7", headers=_auth(tok))
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] >= 1


def test_discovery_candidates_empty(obs_settings: ApiSettings, obs_client: TestClient) -> None:
    tok = _tok(obs_settings, role="read_only")
    r = obs_client.get("/discovery/candidates", headers=_auth(tok))
    assert r.status_code == 200
    assert "candidates" in r.json()
