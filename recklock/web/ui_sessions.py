"""In-memory UI sign-in sessions (opaque cookie tokens, not raw API keys)."""

from __future__ import annotations

import secrets
import time
from threading import Lock

_SESSION_TTL_SECONDS = 86400 * 7
_SESSIONS: dict[str, tuple[str, float]] = {}
_LOCK = Lock()


def issue_ui_session(key_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + _SESSION_TTL_SECONDS
    with _LOCK:
        _SESSIONS[token] = (key_id, expires_at)
    return token


def resolve_ui_session(token: str) -> str | None:
    raw = str(token or "").strip()
    if not raw:
        return None
    now = time.time()
    with _LOCK:
        row = _SESSIONS.get(raw)
        if row is None:
            return None
        key_id, expires_at = row
        if expires_at <= now:
            _SESSIONS.pop(raw, None)
            return None
        return key_id


def revoke_ui_session(token: str) -> None:
    raw = str(token or "").strip()
    if not raw:
        return
    with _LOCK:
        _SESSIONS.pop(raw, None)
