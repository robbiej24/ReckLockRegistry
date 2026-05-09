"""Tests for Phase 3B database persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from recklock.api.app import create_app, reset_cached_settings_for_tests
from recklock.api.settings import ApiSettings
from recklock.approvals import deterministic_approval_id
from recklock.audit import AuditEvent
from recklock.db.init_db import init_database
from recklock.db.repositories import (
    append_audit_event,
    approve_request_db,
    create_approval_request_db,
    load_trust_profiles_map,
    recalculate_all_profiles_db,
    store_execution_request,
    store_execution_response,
    upsert_trust_profile,
)
from recklock.db.session import create_engine_from_settings
from recklock.gateway import ExecutionRequest, ExecutionResponse


def _sample_audit(agent_id: str = "agt_test") -> AuditEvent:
    return AuditEvent(
        event_id="evt_persist_001",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        agent_id=agent_id,
        actor_type="system",
        actor_id="pytest",
        event_type="test.persistence",
        action="noop",
        resource_type="test",
        resource_id="r1",
        permission_scope=None,
        decision="allowed",
        policy_ids=None,
        metadata={"suite": "persistence"},
    )


@pytest.fixture
def db_settings(tmp_path: Path) -> ApiSettings:
    reset_cached_settings_for_tests()
    db_file = tmp_path / "persist.db"
    url = f"sqlite:///{db_file}"
    init_database(url)
    return ApiSettings(registry_root=tmp_path, database_url=url)


def test_init_db_idempotent(db_settings: ApiSettings) -> None:
    init_database(db_settings.database_url)
    init_database(db_settings.database_url)


def test_audit_roundtrip(db_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(db_settings)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        sealed = append_audit_event(session, _sample_audit())
        session.commit()
        assert sealed.event_hash

    with Session() as session:
        from recklock.db.repositories import list_audit_events

        rows = list_audit_events(session)
        assert len(rows) == 1
        assert rows[0].event_id == sealed.event_id


def test_approval_create_update(db_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(db_settings)
    Session = sessionmaker(bind=engine, future=True)
    approval_id = deterministic_approval_id(
        request_id="req_x",
        agent_id="agt_x",
        capability="cap",
        permission_scope="scope",
    )
    with Session() as session:
        create_approval_request_db(
            session,
            approval_id=approval_id,
            request_id="req_x",
            agent_id="agt_x",
            requested_action={"capability": "cap", "permission_scope": "scope"},
            required_approvers=[],
            min_distinct_approvers=1,
        )
        session.commit()

    with Session() as session:
        rec, _ = approve_request_db(session, approval_id, "alice")
        session.commit()
        assert rec.status == "approved"


def test_trust_profile_update(db_settings: ApiSettings) -> None:
    from recklock.trust import TrustProfile

    engine = create_engine_from_settings(db_settings)
    Session = sessionmaker(bind=engine, future=True)
    ts = datetime.now(timezone.utc)
    prof = TrustProfile(
        agent_id="agt_tp",
        current_score=750,
        score_band="trusted",
        last_updated=ts,
    )
    with Session() as session:
        upsert_trust_profile(session, prof)
        session.commit()

    with Session() as session:
        m = load_trust_profiles_map(session)
        assert m["agt_tp"].current_score == 750

    with Session() as session:
        recalc = recalculate_all_profiles_db(session)
        session.commit()
        assert "agt_tp" in recalc


def test_execution_persist(db_settings: ApiSettings) -> None:
    engine = create_engine_from_settings(db_settings)
    Session = sessionmaker(bind=engine, future=True)
    req = ExecutionRequest(
        request_id="req_exec_1",
        agent_id="agt_exec",
        capability="read_public_docs",
        permission_scope="workspace.read",
    )
    resp = ExecutionResponse(
        request_id=req.request_id,
        decision="allowed",
        reason="ok",
        audit_event_id="evt_1",
        evaluated_at=datetime.now(timezone.utc),
    )
    with Session() as session:
        store_execution_request(session, req)
        store_execution_response(
            session,
            request_id=req.request_id,
            response=resp,
            audit_event_ids=["h1", "h2"],
        )
        session.commit()

    with Session() as session:
        from recklock.db.repositories import list_execution_pairs

        pairs = list_execution_pairs(session)
        assert len(pairs) == 1
        assert pairs[0][0].request_id == "req_exec_1"


def test_api_health_with_db(tmp_path: Path) -> None:
    reset_cached_settings_for_tests()
    db_file = tmp_path / "api.db"
    url = f"sqlite:///{db_file}"
    init_database(url)
    settings = ApiSettings(registry_root=tmp_path, database_url=url)
    with TestClient(create_app(settings)) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
