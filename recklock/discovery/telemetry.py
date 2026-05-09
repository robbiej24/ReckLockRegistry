"""Passive observation telemetry — append-only, non-blocking, secret-safe."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recklock.constants import DEFAULT_EVIDENCE_DIR

_LOG = logging.getLogger(__name__)

OBSERVATION_LOG_FILENAME = "observation_events.jsonl"

_SECRET_KEY_RE = re.compile(
    r"\b(api[_-]?key|secret|token|password|passwd|authorization|bearer|private[_-]?key)\b",
    re.I,
)


def observation_mode_enabled(*, force: bool = False) -> bool:
    if force:
        return True
    raw = os.environ.get("RECKLOCK_OBSERVATION_MODE", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_value(key: str, value: Any) -> Any:
    if _SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, str) and _looks_secret_value(value):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value("item", v) for v in value]
    return value


def _looks_secret_value(s: str) -> bool:
    t = s.strip()
    if len(t) < 20:
        return False
    if t.startswith("atk_") or t.startswith("ghp_") or t.startswith("xoxb-"):
        return True
    if re.fullmatch(r"[A-Za-z0-9/_+\-]+={0,2}", t) and len(t) > 40:
        return True
    return False


def redact_metadata(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    if meta is None:
        return None
    return {str(k): _redact_value(str(k), v) for k, v in meta.items()}


def resolve_observation_log_path(events_path: Path | None = None) -> Path:
    """Default log path under cwd or ``RECKLOCK_EVIDENCE_DIR``."""
    if events_path is not None:
        p = events_path
        return p.resolve() if p.is_absolute() else (Path.cwd() / p).resolve()
    env_dir = os.environ.get("RECKLOCK_EVIDENCE_DIR")
    base = Path(env_dir).resolve() if env_dir else (Path.cwd() / DEFAULT_EVIDENCE_DIR)
    return (base / OBSERVATION_LOG_FILENAME).resolve()


def _append_event(
    event: dict[str, Any],
    *,
    events_path: Path | None = None,
) -> None:
    path = resolve_observation_log_path(events_path)
    line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        _LOG.debug("recklock observation append failed: %s", exc)


def record_agent_observation(
    agent_id: str,
    action: str,
    *,
    capability: str | None = None,
    permission_scope: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    force: bool = False,
    events_path: Path | None = None,
) -> None:
    if not observation_mode_enabled(force=force):
        return
    try:
        event = {
            "event_kind": "observation",
            "ts": _utc_iso(),
            "agent_id": agent_id,
            "action": action,
            "capability": capability,
            "permission_scope": permission_scope,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": redact_metadata(metadata),
        }
        _append_event(event, events_path=events_path)
    except Exception as exc:  # noqa: BLE001 — never block caller
        _LOG.debug("record_agent_observation failed: %s", exc)


def record_agent_error(
    agent_id: str,
    action: str,
    error_type: str,
    error_message: str,
    *,
    metadata: dict[str, Any] | None = None,
    force: bool = False,
    events_path: Path | None = None,
) -> None:
    if not observation_mode_enabled(force=force):
        return
    try:
        safe_msg = error_message if len(error_message) < 2000 else error_message[:2000] + "…"
        event = {
            "event_kind": "error",
            "ts": _utc_iso(),
            "agent_id": agent_id,
            "action": action,
            "error_type": error_type,
            "error_message": safe_msg,
            "metadata": redact_metadata(metadata),
        }
        _append_event(event, events_path=events_path)
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("record_agent_error failed: %s", exc)


def record_agent_external_call(
    agent_id: str,
    provider: str,
    *,
    endpoint: str | None = None,
    capability: str | None = None,
    metadata: dict[str, Any] | None = None,
    force: bool = False,
    events_path: Path | None = None,
) -> None:
    if not observation_mode_enabled(force=force):
        return
    try:
        event = {
            "event_kind": "external_call",
            "ts": _utc_iso(),
            "agent_id": agent_id,
            "provider": provider,
            "endpoint": endpoint,
            "capability": capability,
            "metadata": redact_metadata(metadata),
        }
        _append_event(event, events_path=events_path)
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("record_agent_external_call failed: %s", exc)
