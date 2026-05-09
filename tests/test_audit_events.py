"""Tests for append-only audit events and hash chains (Phase 2B)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from agenttrust.audit import (
    AuditEvent,
    append_event,
    canonical_dict_for_hash,
    hash_event,
    load_audit_event_yaml,
    load_events,
    seal_event,
    verify_event_chain,
    verify_log_integrity,
)
from agenttrust.cli import app

FIXED_TS = datetime(2026, 5, 8, 14, 30, 0, tzinfo=timezone.utc)


def _base_event(**kwargs: object) -> AuditEvent:
    data = dict(
        event_id="evt_001",
        timestamp=FIXED_TS,
        agent_id="agt_alpha",
        actor_type="agent",
        actor_id="agt_alpha",
        event_type="policy.decision",
        action="pay.transfer",
        resource_type="payment",
        resource_id="pay_42",
        decision="allowed",
    )
    data.update(kwargs)
    return AuditEvent.model_validate(data)


def test_event_hashing_deterministic() -> None:
    a = _base_event()
    b = _base_event()
    assert hash_event(a) == hash_event(b)


def test_canonicalization_deterministic_policy_ids_order() -> None:
    e1 = _base_event(policy_ids=["p_b", "p_a"])
    e2 = _base_event(policy_ids=["p_a", "p_b"])
    assert canonical_dict_for_hash(e1) == canonical_dict_for_hash(e2)
    assert hash_event(e1) == hash_event(e2)


def test_chain_verification_succeeds(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    first = append_event(_base_event(event_id="evt_1"), log_path=log)
    second = append_event(_base_event(event_id="evt_2"), log_path=log)
    events = load_events(log)
    assert len(events) == 2
    ok, msg = verify_event_chain(events)
    assert ok, msg
    assert first.previous_event_hash is None
    assert second.previous_event_hash == first.event_hash


def test_tampering_breaks_verification(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    append_event(_base_event(event_id="evt_1"), log_path=log)
    append_event(_base_event(event_id="evt_2"), log_path=log)
    text = log.read_text(encoding="utf-8")
    lines = text.strip().split("\n")
    obj = json.loads(lines[0])
    obj["decision"] = "denied"
    lines[0] = json.dumps(obj, sort_keys=True)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = verify_log_integrity(log)
    assert not ok
    assert "Hash mismatch" in msg or "mismatch" in msg.lower()


def test_chain_break_if_previous_wrong() -> None:
    a = _base_event(event_id="e1")
    b = _base_event(event_id="e2")
    s1 = seal_event(a, previous_event_hash=None)
    s2 = seal_event(b, previous_event_hash="not_the_prior_hash")
    ok, msg = verify_event_chain([s1, s2])
    assert not ok
    assert "Chain break" in msg


def test_append_only_logging(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    append_event(_base_event(event_id="a"), log_path=log)
    append_event(_base_event(event_id="b"), log_path=log)
    raw = log.read_text(encoding="utf-8").strip().split("\n")
    assert len(raw) == 2
    assert load_events(log)[1].previous_event_hash == load_events(log)[0].event_hash


def test_load_events_missing_file(tmp_path: Path) -> None:
    assert load_events(tmp_path / "nope.log") == []


def test_verify_empty_log_ok(tmp_path: Path) -> None:
    ok, msg = verify_log_integrity(tmp_path / "missing.log")
    assert ok
    assert "No events" in msg


def test_load_audit_event_yaml_roundtrip(tmp_path: Path) -> None:
    yaml_path = tmp_path / "ev.yaml"
    yaml_path.write_text(
        """
event_id: yaml_evt
timestamp: 2026-05-08T14:30:00Z
agent_id: agt_x
actor_type: human
actor_id: user_7
event_type: login
action: session.start
resource_type: account
resource_id: acc_1
decision: allowed
permission_scope: read
policy_ids: [pol_z, pol_a]
metadata:
  ip: "203.0.113.10"
""".strip(),
        encoding="utf-8",
    )
    ev = load_audit_event_yaml(yaml_path)
    assert ev.event_id == "yaml_evt"
    assert ev.policy_ids == ["pol_a", "pol_z"]


def test_cli_append_and_verify(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    ev_yaml = tmp_path / "one.yaml"
    ev_yaml.write_text(
        """
event_id: cli_evt
timestamp: 2026-05-08T14:30:00Z
agent_id: agt_cli
actor_type: system
actor_id: scheduler
event_type: job.run
action: batch.execute
resource_type: job
resource_id: job_99
decision: pending_approval
""".strip(),
        encoding="utf-8",
    )
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["append-audit-event", str(ev_yaml), "--log", str(log)],
    )
    assert r.exit_code == 0, r.output
    r2 = runner.invoke(app, ["verify-audit-log", "--log", str(log)])
    assert r2.exit_code == 0, r2.output


def test_cli_verify_missing_log_ok(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(app, ["verify-audit-log", "--log", str(tmp_path / "none.log")])
    assert r.exit_code == 0
