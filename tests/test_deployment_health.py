"""Deployment probes & env-backed settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from recklock.api.app import create_app, reset_cached_settings_for_tests
from recklock.api.settings import ApiSettings
from recklock.db.init_db import init_database


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    reset_cached_settings_for_tests()
    yield
    reset_cached_settings_for_tests()


def test_health_and_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "t.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    settings = ApiSettings(registry_root=tmp_path, database_url=db_url)
    init_database(db_url)
    app = create_app(settings)
    with TestClient(app) as client:
        h = client.get("/health")
        assert h.status_code == 200
        assert h.json()["status"] == "ok"
        r = client.get("/ready")
        assert r.status_code == 200
        assert r.json()["status"] == "ready"
        assert r.json()["database"] == "sqlite"


def test_api_settings_reads_bind_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECKLOCK_API_HOST", "10.0.0.2")
    monkeypatch.setenv("RECKLOCK_API_PORT", "9090")
    monkeypatch.setenv("RECKLOCK_ENV", "staging")
    reset_cached_settings_for_tests()
    s = ApiSettings()
    assert s.api_host == "10.0.0.2"
    assert s.api_port == 9090
    assert s.env == "staging"


def test_database_url_prefers_plain_database_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from recklock.db.session import effective_database_url

    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "a.db"))
    monkeypatch.setenv("RECKLOCK_DATABASE_URL", "sqlite:///" + str(tmp_path / "b.db"))
    s = ApiSettings()
    assert effective_database_url(s).endswith("a.db")
