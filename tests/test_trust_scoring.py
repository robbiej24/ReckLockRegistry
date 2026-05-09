"""Tests for Phase 2E deterministic trust scoring."""

from __future__ import annotations

from datetime import datetime, timezone

from agenttrust.trust import (
    IncidentRecord,
    TrustProfile,
    calculate_trust_score,
    classify_score_band,
    default_trust_profile,
    incidents_for_agent,
    load_incidents,
    load_trust_profiles,
    recalculate_all_profiles,
    record_incident,
    update_trust_profile,
)
from agenttrust.trust import IncidentYamlDocument


def test_calculate_trust_score_deterministic() -> None:
    a = calculate_trust_score(
        successful_actions=10,
        denied_actions=2,
        approval_required_actions=8,
        policy_violations=1,
        failed_verifications=0,
        tamper_events=0,
        incidents=(),
    )
    b = calculate_trust_score(
        successful_actions=10,
        denied_actions=2,
        approval_required_actions=8,
        policy_violations=1,
        failed_verifications=0,
        tamper_events=0,
        incidents=(),
    )
    assert a == b


def test_incident_severity_impact() -> None:
    ts = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    low = IncidentRecord(
        incident_id="inc_low",
        agent_id="agent-a",
        timestamp=ts,
        incident_type="test",
        severity="low",
        description="low severity",
    )
    critical = IncidentRecord(
        incident_id="inc_crit",
        agent_id="agent-a",
        timestamp=ts,
        incident_type="test",
        severity="critical",
        description="critical severity",
    )
    base = calculate_trust_score(incidents=())
    with_low = calculate_trust_score(incidents=[low])
    with_crit = calculate_trust_score(incidents=[critical])
    assert with_low < base
    assert with_crit < with_low


def test_classify_score_band_boundaries() -> None:
    assert classify_score_band(750) == "trusted"
    assert classify_score_band(800) == "trusted"
    assert classify_score_band(749) == "elevated_risk"
    assert classify_score_band(600) == "elevated_risk"
    assert classify_score_band(599) == "high_risk"
    assert classify_score_band(400) == "high_risk"
    assert classify_score_band(399) == "critical_risk"
    assert classify_score_band(0) == "critical_risk"


def test_update_trust_profile_incident_sync() -> None:
    ts = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    prof = TrustProfile(
        agent_id="x",
        current_score=750,
        score_band="trusted",
        successful_actions=5,
        denied_actions=0,
        approval_required_actions=0,
        policy_violations=0,
        failed_verifications=0,
        tamper_events=0,
        incident_count=0,
        last_updated=ts,
    )
    inc = IncidentRecord(
        incident_id="inc_1",
        agent_id="x",
        timestamp=ts,
        incident_type="policy",
        severity="medium",
        description="medium incident",
    )
    updated = update_trust_profile(prof, incidents=[inc])
    assert updated.incident_count == 1
    assert updated.current_score != prof.current_score
    assert updated.score_band == classify_score_band(updated.current_score)


def test_tamper_penalty_heavier_than_single_violation() -> None:
    viol_only = calculate_trust_score(policy_violations=1, tamper_events=0)
    tamper_only = calculate_trust_score(policy_violations=0, tamper_events=1)
    baseline = calculate_trust_score()
    assert baseline - tamper_only > baseline - viol_only


def test_repeated_policy_violations_escalate_penalty() -> None:
    one = calculate_trust_score(policy_violations=1)
    three = calculate_trust_score(policy_violations=3)
    assert one > three
    delta_1_to_2 = calculate_trust_score(policy_violations=1) - calculate_trust_score(
        policy_violations=2
    )
    delta_2_to_3 = calculate_trust_score(policy_violations=2) - calculate_trust_score(
        policy_violations=3
    )
    assert delta_2_to_3 >= delta_1_to_2


def test_default_trust_profile_baseline(tmp_path) -> None:
    p = default_trust_profile("new-agent")
    assert p.current_score == calculate_trust_score()
    assert p.score_band == "trusted"


def test_record_incident_end_to_end(tmp_path) -> None:
    ip = tmp_path / "incidents.jsonl"
    pp = tmp_path / "profiles.jsonl"
    doc = IncidentYamlDocument(
        agent_id="agent-z",
        timestamp=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
        incident_type="integrity",
        severity="high",
        description="suspicious manifest mutation",
    )
    rec, profile = record_incident(doc, incidents_path=ip, profiles_path=pp)
    assert rec.agent_id == "agent-z"
    loaded_inc = load_incidents(ip)
    assert len(loaded_inc) == 1
    profiles = load_trust_profiles(pp)
    assert profiles["agent-z"].agent_id == "agent-z"
    assert profiles["agent-z"].incident_count == 1


def test_recalculate_all_profiles(tmp_path) -> None:
    ip = tmp_path / "incidents.jsonl"
    pp = tmp_path / "profiles.jsonl"
    ts = datetime(2026, 2, 1, tzinfo=timezone.utc)
    base = TrustProfile(
        agent_id="a1",
        current_score=400,
        score_band="high_risk",
        policy_violations=2,
        incident_count=0,
        last_updated=ts,
    )
    pp.write_text(base.model_dump_json() + "\n", encoding="utf-8")
    inc = IncidentRecord(
        incident_id="i1",
        agent_id="a1",
        timestamp=ts,
        incident_type="t",
        severity="low",
        description="d",
    )
    ip.write_text(inc.model_dump_json() + "\n", encoding="utf-8")

    out = recalculate_all_profiles(profiles_path=pp, incidents_path=ip)
    assert "a1" in out
    assert out["a1"].incident_count == 1


def test_incidents_for_agent_sorted() -> None:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    a = IncidentRecord(
        incident_id="z",
        agent_id="ag",
        timestamp=ts,
        incident_type="t",
        severity="low",
        description="d",
    )
    b = IncidentRecord(
        incident_id="a",
        agent_id="ag",
        timestamp=ts,
        incident_type="t",
        severity="low",
        description="d2",
    )
    ordered = incidents_for_agent([a, b], "ag")
    assert [x.incident_id for x in ordered] == ["a", "z"]
