"""Evidence aggregation tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from recklock.discovery.evidence import (
    build_evidence_report,
    deterministic_recommendations,
    write_evidence_reports,
)


def _write_events(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")


def test_aggregates_events(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    log = tmp_path / "observation_events.jsonl"
    _write_events(
        log,
        [
            {
                "event_kind": "observation",
                "ts": ts,
                "agent_id": "agt_a_abcd1234",
                "action": "run",
                "permission_scope": "database.write",
            },
            {
                "event_kind": "external_call",
                "ts": ts,
                "agent_id": "agt_a_abcd1234",
                "provider": "openai",
            },
            {
                "event_kind": "error",
                "ts": ts,
                "agent_id": "agt_b_ef678901",
                "error_type": "Timeout",
                "error_message": "x",
            },
        ],
    )
    report = build_evidence_report(days=7, events_path=log, now=now)
    assert report.total_events == 3
    assert report.actions_by_agent["agt_a_abcd1234"] == 1
    assert report.external_calls_by_provider["openai"] == 1
    assert report.errors_by_agent["agt_b_ef678901"] == 1


def test_identifies_high_and_critical_buckets(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    log = tmp_path / "observation_events.jsonl"
    _write_events(
        log,
        [
            {
                "event_kind": "observation",
                "ts": ts,
                "agent_id": "agt_deploy_abcd1234",
                "permission_scope": "production.deploy",
            },
            {
                "event_kind": "observation",
                "ts": ts,
                "agent_id": "agt_pay_ef678901",
                "permission_scope": "payments.initiate",
            },
        ],
    )
    report = build_evidence_report(days=7, events_path=log, now=now)
    assert report.critical_risk_actions["agt_deploy_abcd1234"] >= 1
    assert report.critical_risk_actions["agt_pay_ef678901"] >= 1


def test_writes_json_and_markdown(tmp_path: Path) -> None:
    report = build_evidence_report(days=7, events_path=tmp_path / "missing.jsonl")
    jp, mp = write_evidence_reports(report, evidence_dir=tmp_path, date_suffix="2099-01-01")
    assert jp.is_file() and mp.is_file()
    assert "agents_observed" in jp.read_text(encoding="utf-8")
    assert "# ReckLock Registry evidence report" in mp.read_text(encoding="utf-8")


def test_deterministic_governance_recommendations() -> None:
    rows = [
        {
            "event_kind": "observation",
            "agent_id": "agt_x_abcd1234",
            "permission_scope": "production.deploy",
        }
    ]
    recs = deterministic_recommendations(
        rows=rows,
        critical_counts={"agt_x_abcd1234": 1},
        high_counts={},
        ext_by_provider={},
    )
    assert recs
    assert any("deploy" in r.lower() for r in recs)
