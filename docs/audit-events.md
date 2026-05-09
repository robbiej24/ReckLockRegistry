# Audit events (Phase 2B)

## Append-only audit chains

Runtime audit entries are stored as **newline-delimited JSON** (one JSON object per line). Each record includes a **digest of its canonical content** plus an optional link to the prior record’s digest. Together this forms a **local, tamper-evident sequence**: altering an earlier entry invalidates later digests unless every subsequent record is regenerated consistently—which append-only usage avoids.

Canonical JSON for hashing uses sorted keys, stable UTC timestamps, normalized optional lists (for example `policy_ids` sorted), & excludes the digest field itself so the hash is defined over the semantic payload only.

## Why auditability matters for AI agents

Agents act on behalf of people & systems. Without durable, inspectable traces, organizations cannot answer basic accountability questions: **who** initiated or approved work, **what** was attempted, **which resources** were touched, & **whether** policy permitted it. Phase 2B records those facts in a typed model so the same inputs always serialize & hash the same way—supporting reproducible reviews & automated checks.

## Forensic value

Investigations after incidents, disputes, or compliance reviews rely on **ordered, integrity-checked history**. A chained digest lets reviewers detect accidental file edits & many intentional edits to stored logs without needing a database or external service. The log remains **evidence-shaped**: small, portable, & suitable for archival alongside manifests & policy snapshots.

## Future enterprise integrations

This phase intentionally stays **local & simple**. Later work can **export** the same records to long-term storage, ticketing, GRC tools, or customer evidence packages—always starting from the same canonical event model & verification routine so exports remain consistent with what operators verify on disk.

## Relationship to the policy engine

Phase 2A evaluates whether an action is allowed, denied, or requires approval. Phase 2B **records** what happened at runtime: actor, resource, decision outcome (`allowed`, `denied`, `pending_approval`), & optional `policy_ids`. Evaluating policy & emitting audit rows are separate steps; tying them together is a caller responsibility so audit stays orthogonal to rule definitions.

## Commands

- `recklock-registry append-audit-event path/to/event.yaml` — append one YAML-described event (hashes optional; the CLI completes the chain).
- `recklock-registry verify-audit-log` — verify per-event digests & hash continuity (defaults to `audit_logs/events.log`; override with `--log`).

See `agenttrust/audit.py` for the `AuditEvent` schema & verification helpers.
