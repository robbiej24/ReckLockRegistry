"""Deterministic trust scoring & incident tracking (Phase 2E)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Sequence

import yaml
from pydantic import BaseModel, Field, field_validator

from agenttrust.constants import DEFAULT_INCIDENTS_PATH as _DEFAULT_INCIDENTS_STR
from agenttrust.constants import DEFAULT_TRUST_PROFILES_PATH as _DEFAULT_PROFILES_STR

DEFAULT_TRUST_PROFILES_PATH = Path(_DEFAULT_PROFILES_STR)
DEFAULT_INCIDENTS_PATH = Path(_DEFAULT_INCIDENTS_STR)

ScoreBand = Literal["trusted", "elevated_risk", "high_risk", "critical_risk"]
IncidentSeverity = Literal["low", "medium", "high", "critical"]

# --- Scoring constants (deterministic, documented in docs/trust-scoring.md) ---
BASE_SCORE = 750
SCORE_MIN = 0
SCORE_MAX = 1000

# Operational signals
SUCCESS_BONUS_PER_ACTION = 2
SUCCESS_BONUS_CAP = 80
DENIED_PENALTY_PER = 4
APPROVAL_FREE_ACTIONS = 5
APPROVAL_EXCESS_PENALTY_PER = 3
POLICY_VIOLATION_FIRST = 12
POLICY_VIOLATION_REPEAT_EXTRA = 5  # each violation after the first adds this on top of base 12
FAILED_VERIFICATION_PENALTY = 10
TAMPER_PENALTY_PER = 55

# Incident severity weights (applied per IncidentRecord)
INCIDENT_WEIGHT: dict[IncidentSeverity, int] = {
    "low": 10,
    "medium": 22,
    "high": 48,
    "critical": 105,
}


class TrustProfile(BaseModel):
    """Aggregate trust metrics for one agent (local JSONL snapshot)."""

    agent_id: str = Field(..., min_length=1)
    current_score: int = Field(..., ge=SCORE_MIN, le=SCORE_MAX)
    score_band: ScoreBand
    successful_actions: int = Field(default=0, ge=0)
    denied_actions: int = Field(default=0, ge=0)
    approval_required_actions: int = Field(default=0, ge=0)
    policy_violations: int = Field(default=0, ge=0)
    failed_verifications: int = Field(default=0, ge=0)
    tamper_events: int = Field(default=0, ge=0)
    incident_count: int = Field(default=0, ge=0)
    last_updated: datetime

    @field_validator("last_updated")
    @classmethod
    def last_updated_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class IncidentRecord(BaseModel):
    """Structured incident for underwriting-style audit trails."""

    incident_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    timestamp: datetime
    incident_type: str = Field(..., min_length=1)
    severity: IncidentSeverity
    description: str = Field(..., min_length=1)
    related_event_ids: list[str] | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("related_event_ids")
    @classmethod
    def related_sorted(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return sorted(v)


def _utc_now(now: datetime | None = None) -> datetime:
    return now if now is not None else datetime.now(timezone.utc)


def _violations_penalty(count: int) -> int:
    """Linear base penalty plus extra for repeated violations after the first."""
    if count <= 0:
        return 0
    base = POLICY_VIOLATION_FIRST * count
    repeat = POLICY_VIOLATION_REPEAT_EXTRA * max(0, count - 1)
    return -(base + repeat)


def _approval_excess_penalty(approval_required_actions: int) -> int:
    excess = max(0, approval_required_actions - APPROVAL_FREE_ACTIONS)
    return -APPROVAL_EXCESS_PENALTY_PER * excess


def _incidents_penalty(incidents: Sequence[IncidentRecord]) -> int:
    total = 0
    for inc in incidents:
        total -= INCIDENT_WEIGHT[inc.severity]
    return total


def calculate_trust_score(
    *,
    successful_actions: int = 0,
    denied_actions: int = 0,
    approval_required_actions: int = 0,
    policy_violations: int = 0,
    failed_verifications: int = 0,
    tamper_events: int = 0,
    incidents: Sequence[IncidentRecord] | None = None,
) -> int:
    """Compute a deterministic integer score from counters and optional incident history.

    Incident impact uses explicit severities only (no ML). ``incident_count`` on profiles
    should match ``len(incidents)`` when incidents are supplied.
    """
    inc = list(incidents or ())
    score = BASE_SCORE

    success_bonus = min(SUCCESS_BONUS_PER_ACTION * successful_actions, SUCCESS_BONUS_CAP)
    score += success_bonus

    score -= DENIED_PENALTY_PER * denied_actions
    score += _approval_excess_penalty(approval_required_actions)
    score += _violations_penalty(policy_violations)
    score -= FAILED_VERIFICATION_PENALTY * failed_verifications
    score -= TAMPER_PENALTY_PER * tamper_events
    score += _incidents_penalty(inc)

    return max(SCORE_MIN, min(SCORE_MAX, score))


def classify_score_band(score: int) -> ScoreBand:
    """Map an integer score to a coarse band (thresholds are fixed & documented)."""
    if score >= 750:
        return "trusted"
    if score >= 600:
        return "elevated_risk"
    if score >= 400:
        return "high_risk"
    return "critical_risk"


def update_trust_profile(
    profile: TrustProfile,
    *,
    incidents: Sequence[IncidentRecord] = (),
    now: datetime | None = None,
) -> TrustProfile:
    """Recompute ``current_score``, ``score_band``, ``incident_count``, and ``last_updated``.

    Pass every :class:`IncidentRecord` for this ``agent_id`` when recalculating; ``incident_count``
    is always ``len(incidents)`` so the snapshot stays consistent with the incident log.
    """
    inc = list(incidents)
    new_score = calculate_trust_score(
        successful_actions=profile.successful_actions,
        denied_actions=profile.denied_actions,
        approval_required_actions=profile.approval_required_actions,
        policy_violations=profile.policy_violations,
        failed_verifications=profile.failed_verifications,
        tamper_events=profile.tamper_events,
        incidents=inc,
    )
    band = classify_score_band(new_score)
    return profile.model_copy(
        update={
            "current_score": new_score,
            "score_band": band,
            "incident_count": len(inc),
            "last_updated": _utc_now(now),
        }
    )


def default_trust_profile(agent_id: str, *, now: datetime | None = None) -> TrustProfile:
    """Pristine profile: baseline score with no incidents."""
    ts = _utc_now(now)
    score = calculate_trust_score(incidents=())
    return TrustProfile(
        agent_id=agent_id,
        current_score=score,
        score_band=classify_score_band(score),
        last_updated=ts,
    )


def load_trust_profiles(path: Path | None = None) -> dict[str, TrustProfile]:
    """Load trust profiles from JSONL; last line wins per ``agent_id``."""
    p = path or DEFAULT_TRUST_PROFILES_PATH
    if not p.is_file():
        return {}
    latest: dict[str, TrustProfile] = {}
    for line_no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{p}:{line_no}: invalid JSON: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError(f"{p}:{line_no}: each line must be a JSON object")
        rec = TrustProfile.model_validate(raw)
        latest[rec.agent_id] = rec
    return latest


def append_trust_profile(record: TrustProfile, path: Path | None = None) -> None:
    """Append one snapshot line (full replace for that agent via last-write wins on load)."""
    out = path or DEFAULT_TRUST_PROFILES_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = record.model_dump(mode="json")
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with out.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_incidents(path: Path | None = None) -> list[IncidentRecord]:
    """Load all incident rows from JSONL (append-only log order preserved)."""
    p = path or DEFAULT_INCIDENTS_PATH
    if not p.is_file():
        return []
    rows: list[IncidentRecord] = []
    for line_no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{p}:{line_no}: invalid JSON: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError(f"{p}:{line_no}: each line must be a JSON object")
        rows.append(IncidentRecord.model_validate(raw))
    return rows


def incidents_for_agent(incidents: Sequence[IncidentRecord], agent_id: str) -> list[IncidentRecord]:
    """Filter incidents for one agent (stable sort by timestamp then id)."""
    matching = [i for i in incidents if i.agent_id == agent_id]
    return sorted(matching, key=lambda i: (i.timestamp, i.incident_id))


def append_incident(record: IncidentRecord, path: Path | None = None) -> None:
    """Append one incident line."""
    out = path or DEFAULT_INCIDENTS_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = record.model_dump(mode="json")
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with out.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def deterministic_incident_id(
    *,
    agent_id: str,
    timestamp: datetime,
    incident_type: str,
    description: str,
) -> str:
    """Stable id when YAML omits ``incident_id``."""
    ts = timestamp.astimezone(timezone.utc) if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
    body = json.dumps(
        {
            "agent_id": agent_id,
            "description": description,
            "incident_type": incident_type,
            "timestamp": ts.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"inc_{digest[:24]}"


class IncidentYamlDocument(BaseModel):
    """YAML input for ``record-incident`` (incident_id optional)."""

    incident_id: str | None = None
    agent_id: str = Field(..., min_length=1)
    timestamp: datetime
    incident_type: str = Field(..., min_length=1)
    severity: IncidentSeverity
    description: str = Field(..., min_length=1)
    related_event_ids: list[str] | None = None

    @field_validator("timestamp")
    @classmethod
    def ts_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


def load_incident_yaml(path: Path) -> IncidentYamlDocument:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("incident YAML must be a mapping at the top level")
    return IncidentYamlDocument.model_validate(raw)


def incident_from_yaml(doc: IncidentYamlDocument) -> IncidentRecord:
    """Build a record, synthesizing ``incident_id`` when missing."""
    iid = doc.incident_id
    if not iid:
        iid = deterministic_incident_id(
            agent_id=doc.agent_id,
            timestamp=doc.timestamp,
            incident_type=doc.incident_type,
            description=doc.description,
        )
    return IncidentRecord(
        incident_id=iid,
        agent_id=doc.agent_id,
        timestamp=doc.timestamp,
        incident_type=doc.incident_type,
        severity=doc.severity,
        description=doc.description,
        related_event_ids=doc.related_event_ids,
    )


def record_incident(
    doc: IncidentYamlDocument,
    *,
    incidents_path: Path | None = None,
    profiles_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[IncidentRecord, TrustProfile]:
    """Persist incident JSONL row and upsert the agent's trust profile snapshot."""
    inc_path = incidents_path or DEFAULT_INCIDENTS_PATH
    prof_path = profiles_path or DEFAULT_TRUST_PROFILES_PATH

    rec = incident_from_yaml(doc)
    append_incident(rec, path=inc_path)

    all_incidents = load_incidents(inc_path)
    agent_incidents = incidents_for_agent(all_incidents, rec.agent_id)

    profiles = load_trust_profiles(prof_path)
    base = profiles.get(rec.agent_id) or default_trust_profile(rec.agent_id, now=now)
    updated = update_trust_profile(base, incidents=agent_incidents, now=now)
    append_trust_profile(updated, path=prof_path)
    return rec, updated


def recalculate_all_profiles(
    *,
    profiles_path: Path | None = None,
    incidents_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, TrustProfile]:
    """Recompute scores from stored counters plus full incident log."""
    pp = profiles_path or DEFAULT_TRUST_PROFILES_PATH
    ip = incidents_path or DEFAULT_INCIDENTS_PATH
    profiles = load_trust_profiles(pp)
    incidents = load_incidents(ip)
    by_agent: dict[str, TrustProfile] = {}
    for aid, prof in profiles.items():
        agent_inc = incidents_for_agent(incidents, aid)
        by_agent[aid] = update_trust_profile(prof, incidents=agent_inc, now=now)
    for aid, prof in by_agent.items():
        append_trust_profile(prof, path=pp)
    return by_agent
