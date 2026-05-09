"""Persistence helpers for temporary credentials (hash-only storage)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from recklock.credentials.models import TemporaryCredential
from recklock.db import models as m


def _utc_now(dt: datetime | None = None) -> datetime:
    ts = dt if dt is not None else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return _utc_now(dt).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dump_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_json(text_val: str | None, default: Any) -> Any:
    if text_val is None or text_val == "":
        return default
    return json.loads(text_val)


def insert_credential(session: Session, record: TemporaryCredential, *, created_at: datetime | None = None) -> None:
    conn = session.connection()
    ts = _iso(created_at or record.issued_at)
    conn.execute(
        m.temporary_credentials.insert().values(
            credential_id=record.credential_id,
            agent_id=record.agent_id,
            issued_at=_iso(record.issued_at),
            expires_at=_iso(record.expires_at),
            scopes=_dump_json(record.scopes),
            resource=record.resource,
            environment=record.environment,
            issued_by=record.issued_by,
            status=record.status,
            token_hash=record.token_hash,
            metadata=_dump_json(record.metadata) if record.metadata is not None else None,
            created_at=ts,
        )
    )


def get_by_id(session: Session, credential_id: str) -> TemporaryCredential | None:
    conn = session.connection()
    row = conn.execute(
        select(m.temporary_credentials).where(m.temporary_credentials.c.credential_id == credential_id)
    ).first()
    if row is None:
        return None
    return _row_to_model(row)


def get_by_token_hash(session: Session, token_hash: str) -> TemporaryCredential | None:
    conn = session.connection()
    row = conn.execute(
        select(m.temporary_credentials).where(m.temporary_credentials.c.token_hash == token_hash)
    ).first()
    if row is None:
        return None
    return _row_to_model(row)


def _row_to_model(row: Any) -> TemporaryCredential:
    return TemporaryCredential(
        credential_id=row.credential_id,
        agent_id=row.agent_id,
        issued_at=_parse_iso(row.issued_at),
        expires_at=_parse_iso(row.expires_at),
        scopes=_load_json(row.scopes, []),
        resource=row.resource,
        environment=row.environment,
        issued_by=row.issued_by,
        status=row.status,  # type: ignore[arg-type]
        token_hash=row.token_hash,
        metadata=_load_json(row.metadata, None),
    )


def list_credentials(session: Session) -> list[TemporaryCredential]:
    conn = session.connection()
    rows = conn.execute(
        select(m.temporary_credentials).order_by(
            m.temporary_credentials.c.created_at.desc(),
            m.temporary_credentials.c.credential_id,
        )
    ).fetchall()
    return [_row_to_model(r) for r in rows]


def update_status(session: Session, credential_id: str, status: str, *, metadata: dict[str, Any] | None = None) -> None:
    conn = session.connection()
    row = conn.execute(
        select(m.temporary_credentials).where(m.temporary_credentials.c.credential_id == credential_id)
    ).first()
    if row is None:
        raise ValueError(f"Unknown credential_id {credential_id!r}.")
    meta = _load_json(row.metadata, None) or {}
    if metadata:
        meta = {**meta, **metadata}
    conn.execute(
        m.temporary_credentials.update()
        .where(m.temporary_credentials.c.credential_id == credential_id)
        .values(status=status, metadata=_dump_json(meta) if meta else None)
    )


def iter_active_expired_ids(session: Session, *, now: datetime | None = None) -> list[str]:
    """Return credential_ids that are still marked active but past *expires_at* (ISO text compare)."""
    ts = _utc_now(now)
    conn = session.connection()
    rows = conn.execute(
        select(m.temporary_credentials.c.credential_id, m.temporary_credentials.c.expires_at).where(
            m.temporary_credentials.c.status == "active"
        )
    ).fetchall()
    out: list[str] = []
    for cid, exp_text in rows:
        if _parse_iso(exp_text) < ts:
            out.append(cid)
    return out
