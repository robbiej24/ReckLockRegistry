"""Append-only audit event log with chained hashing (Phase 2B)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

DEFAULT_AUDIT_LOG_PATH = Path("audit_logs/events.log")

ActorType = Literal["human", "agent", "system"]
AuditDecision = Literal["allowed", "denied", "pending_approval"]


class AuditEvent(BaseModel):
    """Single audit record for an AI agent or related actor."""

    event_id: str = Field(..., min_length=1)
    timestamp: datetime
    agent_id: str = Field(..., min_length=1)
    actor_type: ActorType
    actor_id: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    resource_type: str = Field(..., min_length=1)
    resource_id: str = Field(..., min_length=1)
    permission_scope: str | None = None
    decision: AuditDecision
    policy_ids: list[str] | None = None
    metadata: dict[str, Any] | None = None
    previous_event_hash: str | None = None
    event_hash: str | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("policy_ids")
    @classmethod
    def policy_ids_sorted(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return sorted(v)


def _format_timestamp_utc(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if dt.microsecond:
        # Trim to milliseconds for stable width.
        ms = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def canonical_dict_for_hash(event: AuditEvent) -> dict[str, Any]:
    """Return a JSON-serializable dict used for hashing (excludes ``event_hash``)."""
    d = event.model_dump(exclude={"event_hash"}, mode="python")
    d["timestamp"] = _format_timestamp_utc(d["timestamp"])
    return d


def hash_event(event: AuditEvent) -> str:
    """SHA-256 of the canonical JSON payload (``event_hash`` field excluded)."""
    payload = canonical_dict_for_hash(event)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def verify_event_chain(events: list[AuditEvent]) -> tuple[bool, str]:
    """Verify per-event hashes and the previous-hash chain."""
    if not events:
        return True, "No events to verify."

    for i, ev in enumerate(events):
        if ev.event_hash is None:
            return False, f"Event at index {i} ({ev.event_id!r}) is missing event_hash."
        expected = hash_event(ev.model_copy(update={"event_hash": None}))
        if expected != ev.event_hash:
            return (
                False,
                f"Hash mismatch at index {i} ({ev.event_id!r}): "
                f"expected {expected}, stored {ev.event_hash}.",
            )

    for i in range(1, len(events)):
        prev_h = events[i - 1].event_hash
        cur_prev = events[i].previous_event_hash
        if cur_prev != prev_h:
            return (
                False,
                f"Chain break at index {i} ({events[i].event_id!r}): "
                f"previous_event_hash {cur_prev!r} != prior event_hash {prev_h!r}.",
            )

    if events[0].previous_event_hash is not None:
        return (
            False,
            f"First event ({events[0].event_id!r}) must have previous_event_hash=None.",
        )

    return True, f"Verified {len(events)} event(s)."


def _dump_line(event: AuditEvent) -> str:
    payload = event.model_dump(mode="json")
    # Match canonical hashing: single UTC representation in the log file.
    payload["timestamp"] = _format_timestamp_utc(event.timestamp)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_events(log_path: Path | None = None) -> list[AuditEvent]:
    """Load newline-delimited JSON events from *log_path*."""
    path = log_path or DEFAULT_AUDIT_LOG_PATH
    if not path.is_file():
        return []
    out: list[AuditEvent] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError(f"{path}:{line_no}: each line must be a JSON object")
        out.append(AuditEvent.model_validate(raw))
    return out


def verify_log_integrity(log_path: Path | None = None) -> tuple[bool, str]:
    """Load the log and verify the hash chain."""
    events = load_events(log_path)
    return verify_event_chain(events)


def seal_event(event: AuditEvent, *, previous_event_hash: str | None) -> AuditEvent:
    """Attach ``previous_event_hash`` and compute ``event_hash``."""
    base = event.model_copy(update={"previous_event_hash": previous_event_hash, "event_hash": None})
    h = hash_event(base)
    return base.model_copy(update={"event_hash": h})


def append_event(
    event: AuditEvent,
    log_path: Path | None = None,
    *,
    force_chain: bool = True,
) -> AuditEvent:
    """Append one event to the log with chaining & hashing.

    When *force_chain* is True (default), ``previous_event_hash`` and ``event_hash``
    from *event* are ignored; the prior tail hash becomes the new previous link.
    """
    path = log_path or DEFAULT_AUDIT_LOG_PATH
    existing = load_events(path)
    prev_hash = existing[-1].event_hash if existing else None
    if force_chain:
        incoming = event.model_copy(update={"previous_event_hash": None, "event_hash": None})
    else:
        incoming = event
    sealed = seal_event(incoming, previous_event_hash=prev_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(_dump_line(sealed) + "\n")
    return sealed


def load_audit_event_yaml(path: Path) -> AuditEvent:
    """Load an :class:`AuditEvent` from YAML (hashes optional)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("audit event YAML must be a mapping at the top level")
    return AuditEvent.model_validate(raw)
