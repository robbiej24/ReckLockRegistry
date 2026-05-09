"""Aggregate passive telemetry into weekly-style evidence reports."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from recklock.constants import DEFAULT_EVIDENCE_DIR
from recklock.discovery.telemetry import resolve_observation_log_path


def _parse_ts(ts: str) -> datetime | None:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def load_observation_events(
    *,
    days: int,
    events_path: Path | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    path = resolve_observation_log_path(events_path)
    if not path.is_file():
        return []
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = row.get("ts")
        if not isinstance(ts, str):
            continue
        dt = _parse_ts(ts)
        if dt is None or dt < cutoff:
            continue
        rows.append(row)
    return rows


SCOPE_RISK: dict[str, str] = {
    "production.deploy": "critical",
    "payments.initiate": "critical",
    "finance.read": "critical",
    "database.write": "high",
    "cloud.write": "high",
    "process.exec": "high",
    "email.send": "high",
    "repository.write": "medium",
    "ci.execute": "medium",
}

CAPABILITY_RISK: dict[str, str] = {
    "deploy_code": "critical",
    "initiate_payment": "critical",
    "financial_data_access": "critical",
    "write_database": "high",
    "execute_shell": "high",
    "external_communication": "high",
    "llm_inference": "medium",
}


def _event_risk(row: dict[str, Any]) -> str | None:
    scope = row.get("permission_scope")
    if isinstance(scope, str) and scope in SCOPE_RISK:
        return SCOPE_RISK[scope]
    cap = row.get("capability")
    if isinstance(cap, str) and cap in CAPABILITY_RISK:
        return CAPABILITY_RISK[cap]
    meta = row.get("metadata")
    if isinstance(meta, dict):
        hint = meta.get("risk_guess")
        if hint in {"low", "medium", "high", "critical"}:
            return str(hint)
    return None


@dataclass
class EvidenceReport:
    """Structured weekly evidence summary."""

    period_days: int
    generated_at: str
    total_events: int
    agents_observed: list[str]
    actions_by_agent: dict[str, int] = field(default_factory=dict)
    external_calls_by_provider: Counter[str] = field(default_factory=Counter)
    errors_by_agent: dict[str, int] = field(default_factory=dict)
    high_risk_actions: dict[str, int] = field(default_factory=dict)
    critical_risk_actions: dict[str, int] = field(default_factory=dict)
    unknown_agents: list[str] = field(default_factory=list)
    governance_recommendations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "period_days": self.period_days,
            "generated_at": self.generated_at,
            "total_events": self.total_events,
            "agents_observed": self.agents_observed,
            "actions_by_agent": dict(sorted(self.actions_by_agent.items())),
            "external_calls_by_provider": dict(sorted(self.external_calls_by_provider.items())),
            "errors_by_agent": dict(sorted(self.errors_by_agent.items())),
            "high_risk_actions": dict(sorted(self.high_risk_actions.items())),
            "critical_risk_actions": dict(sorted(self.critical_risk_actions.items())),
            "unknown_agents": sorted(self.unknown_agents),
            "governance_recommendations": list(self.governance_recommendations),
        }


def build_evidence_report(
    *,
    days: int = 7,
    events_path: Path | None = None,
    now: datetime | None = None,
) -> EvidenceReport:
    rows = load_observation_events(days=days, events_path=events_path, now=now)
    generated = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

    actions_by_agent: dict[str, int] = defaultdict(int)
    errors_by_agent: dict[str, int] = defaultdict(int)
    ext_by_provider: Counter[str] = Counter()
    high: dict[str, int] = defaultdict(int)
    critical: dict[str, int] = defaultdict(int)
    agents: set[str] = set()

    for row in rows:
        kind = row.get("event_kind")
        aid = row.get("agent_id")
        if not isinstance(aid, str) or aid == "":
            continue
        agents.add(aid)
        if kind == "observation":
            actions_by_agent[aid] += 1
        elif kind == "error":
            errors_by_agent[aid] += 1
        elif kind == "external_call":
            prov = row.get("provider")
            if isinstance(prov, str) and prov:
                ext_by_provider[prov] += 1

        rk = _event_risk(row)
        if rk == "high":
            high[aid] += 1
        elif rk == "critical":
            critical[aid] += 1

    unknown_agents = sorted(a for a in agents if a.startswith("unknown") or "unknown" in a.lower())

    recs = deterministic_recommendations(
        rows=rows,
        critical_counts=dict(critical),
        high_counts=dict(high),
        ext_by_provider=dict(ext_by_provider),
    )

    return EvidenceReport(
        period_days=days,
        generated_at=generated,
        total_events=len(rows),
        agents_observed=sorted(agents),
        actions_by_agent=dict(actions_by_agent),
        external_calls_by_provider=ext_by_provider,
        errors_by_agent=dict(errors_by_agent),
        high_risk_actions=dict(high),
        critical_risk_actions=dict(critical),
        unknown_agents=unknown_agents,
        governance_recommendations=recs,
    )


def deterministic_recommendations(
    *,
    rows: Iterable[dict[str, Any]],
    critical_counts: dict[str, int],
    high_counts: dict[str, int],
    ext_by_provider: dict[str, int],
) -> list[str]:
    """Rule-based governance suggestions — observation-only; does not enforce policy."""
    recs: list[str] = []

    crit_agents = {a for a, n in critical_counts.items() if n > 0}
    high_agents = {a for a, n in high_counts.items() if n > 0}

    for a in sorted(crit_agents):
        recs.append(f"Prioritize governance review for critical-risk activity observed from agent {a}.")

    # Deploy / payments / DB writes from stream
    for row in rows:
        scope = row.get("permission_scope")
        cap = row.get("capability")
        aid = row.get("agent_id")
        if not isinstance(aid, str):
            continue
        if scope == "production.deploy" or cap == "deploy_code":
            recs.append(f"Govern deploy paths first — observed deploy capability for agent {aid}.")
        if scope in {"payments.initiate", "finance.read"} or cap in {"initiate_payment", "financial_data_access"}:
            recs.append(f"Govern financial flows first — observed finance/payment scope for agent {aid}.")
        if scope == "database.write" or cap == "write_database":
            recs.append(f"Add database write controls — observed database.write for agent {aid}.")

    # Email-like external comms
    for row in rows:
        if row.get("event_kind") != "observation":
            continue
        scope = row.get("permission_scope")
        aid = row.get("agent_id")
        if scope == "email.send" and isinstance(aid, str):
            recs.append(f"Review outbound email governance for agent {aid}.")

    # External calls present
    if ext_by_provider:
        recs.append("Monitor external provider usage — structured connector governance recommended.")

    # Dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)

    if not out and not crit_agents and not high_agents:
        out.append("Continue passive observation — no high/critical signals detected in this window.")

    return out[:50]


def write_evidence_reports(
    report: EvidenceReport,
    *,
    evidence_dir: Path | None = None,
    date_suffix: str | None = None,
) -> tuple[Path, Path]:
    """Write JSON & Markdown siblings under ``evidence/``."""
    base = evidence_dir or (Path.cwd() / DEFAULT_EVIDENCE_DIR)
    base.mkdir(parents=True, exist_ok=True)
    suffix = date_suffix or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    json_path = base / f"evidence_report_{suffix}.json"
    md_path = base / f"evidence_report_{suffix}.md"

    json_path.write_text(json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"# ReckLock Registry evidence report ({suffix})",
        "",
        f"- Period: last {report.period_days} day(s)",
        f"- Generated: {report.generated_at}",
        f"- Total events: {report.total_events}",
        "",
        "## Agents observed",
        "",
    ]
    if report.agents_observed:
        for a in report.agents_observed:
            lines.append(f"- {a}")
    else:
        lines.append("- (none)")
    lines.extend(
        [
            "",
            "## Actions by agent",
            "",
        ]
    )
    for k, v in sorted(report.actions_by_agent.items()):
        lines.append(f"- {k}: {v}")
    lines.extend(["", "## External calls by provider", ""])
    if report.external_calls_by_provider:
        for k, v in sorted(report.external_calls_by_provider.items()):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- (none)")
    lines.extend(["", "## Errors by agent", ""])
    if report.errors_by_agent:
        for k, v in sorted(report.errors_by_agent.items()):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- (none)")
    lines.extend(["", "## Risk buckets", ""])
    lines.append("### High")
    for k, v in sorted(report.high_risk_actions.items()):
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("### Critical")
    for k, v in sorted(report.critical_risk_actions.items()):
        lines.append(f"- {k}: {v}")
    lines.extend(["", "## Unknown agents", ""])
    for u in report.unknown_agents:
        lines.append(f"- {u}")
    if not report.unknown_agents:
        lines.append("- (none)")
    lines.extend(["", "## Governance recommendations", ""])
    for r in report.governance_recommendations:
        lines.append(f"- {r}")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path
