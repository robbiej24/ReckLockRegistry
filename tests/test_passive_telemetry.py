"""Passive telemetry tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agenttrust.discovery.telemetry import (
    observation_mode_enabled,
    record_agent_observation,
    redact_metadata,
    resolve_observation_log_path,
)


def test_no_op_when_observation_mode_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTTRUST_OBSERVATION_MODE", raising=False)
    log = tmp_path / "observation_events.jsonl"
    record_agent_observation(
        "agt_test_abcd1234",
        "ping",
        metadata={"x": 1},
        events_path=log,
    )
    assert not log.exists()


def test_records_when_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTTRUST_OBSERVATION_MODE", "true")
    log = tmp_path / "observation_events.jsonl"
    record_agent_observation(
        "agt_test_abcd1234",
        "ping",
        metadata={"size": 42},
        events_path=log,
    )
    assert log.is_file()
    row = json.loads(log.read_text(encoding="utf-8").strip())
    assert row["event_kind"] == "observation"
    assert row["agent_id"] == "agt_test_abcd1234"


def test_redacts_secret_looking_metadata() -> None:
    meta = {"api_key": "super-secret-token-value-12345678901234567890"}
    out = redact_metadata(meta)
    assert out is not None
    assert out["api_key"] == "[REDACTED]"


def test_resolve_observation_log_path_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTTRUST_EVIDENCE_DIR", str(tmp_path))
    p = resolve_observation_log_path()
    assert p.name == "observation_events.jsonl"
    assert p.parent.resolve() == tmp_path.resolve()


def test_logging_failure_does_not_raise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTTRUST_OBSERVATION_MODE", "true")
    bad_path = tmp_path / "nope" / "missing" / "nested" / "log.jsonl"

    def boom_open(*args: object, **kwargs: object) -> object:
        raise OSError("simulated")

    monkeypatch.setattr(Path, "open", boom_open)
    record_agent_observation(
        "agt_x_abcd1234",
        "act",
        events_path=bad_path,
    )


def test_observation_mode_enabled_truthy() -> None:
    os.environ["AGENTTRUST_OBSERVATION_MODE"] = "1"
    assert observation_mode_enabled() is True
    del os.environ["AGENTTRUST_OBSERVATION_MODE"]
