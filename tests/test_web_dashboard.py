"""Phase 3F operational dashboard smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from recklock.api.app import create_app, reset_cached_settings_for_tests
from recklock.auth.service import create_api_key
from recklock.db.session import create_engine_from_settings
from sqlalchemy.orm import sessionmaker

from test_api import _write_registry


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_bundle(tmp_path: Path):
    reset_cached_settings_for_tests()
    settings, raw = _write_registry(tmp_path)
    return settings, raw


@pytest.fixture
def admin_client(admin_bundle):
    settings, _ = admin_bundle
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def admin_token(admin_bundle: tuple) -> str:
    return admin_bundle[1]


def test_ui_dashboard_requires_auth(admin_client: TestClient) -> None:
    r = admin_client.get("/ui/")
    assert r.status_code == 401


def test_ui_dashboard_renders(admin_client: TestClient, admin_token: str) -> None:
    r = admin_client.get("/ui/", headers=_auth(admin_token))
    assert r.status_code == 200
    assert "Dashboard" in r.text


def test_ui_agents_renders(admin_client: TestClient, admin_token: str) -> None:
    r = admin_client.get("/ui/agents", headers=_auth(admin_token))
    assert r.status_code == 200
    assert "Registered agents" in r.text


def test_ui_audit_trust_credentials_executions_render(admin_client: TestClient, admin_token: str) -> None:
    for path, needle in (
        ("/ui/audit", "Audit events"),
        ("/ui/trust", "Trust profiles"),
        ("/ui/credentials", "Credentials"),
        ("/ui/executions", "Executions"),
    ):
        r = admin_client.get(path, headers=_auth(admin_token))
        assert r.status_code == 200
        assert needle in r.text


def test_ui_approvals_renders(admin_client: TestClient, admin_token: str) -> None:
    r = admin_client.get("/ui/approvals", headers=_auth(admin_token))
    assert r.status_code == 200
    assert "Approvals" in r.text


def test_ui_static_css(admin_client: TestClient) -> None:
    r = admin_client.get("/ui/static/app.css")
    assert r.status_code == 200
    assert "body" in r.text


def test_ui_sign_in_page_public(admin_client: TestClient) -> None:
    r = admin_client.get("/ui/sign-in")
    assert r.status_code == 200
    assert "Sign in" in r.text


def test_ui_agents_forbidden_for_approver_only(tmp_path: Path) -> None:
    reset_cached_settings_for_tests()
    settings, _ = _write_registry(tmp_path)
    engine = create_engine_from_settings(settings)
    SessionLocal = sessionmaker(bind=engine, future=True)
    with SessionLocal() as session:
        raw, _ = create_api_key(session, name="Approver Only", role="approver")
        session.commit()
    app = create_app(settings)
    with TestClient(app) as client:
        r = client.get("/ui/agents", headers=_auth(raw))
        assert r.status_code == 403
