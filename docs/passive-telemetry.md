# Passive telemetry (Phase 4A)

Phase 4A adds **opt-in, non-blocking** hooks that append small JSON lines to an evidence log. They never raise to callers on failure, never block execution, & redact obvious secret-shaped metadata keys or values.

## Observation mode

Set:

```bash
export RECKLOCK_OBSERVATION_MODE=true
```

When this is unset or false, the Python helpers (`record_agent_observation`, `record_agent_error`, `record_agent_external_call`) **no-op** unless you pass `force=True` (used internally by the API when observation is enabled server-side).

The REST API still checks **`RECKLOCK_OBSERVATION_MODE` via settings** (`observation_mode` on `ApiSettings`): when false, telemetry POST endpoints acknowledge the request but **do not persist** rows.

## Where events go

By default, events append to:

`evidence/observation_events.jsonl`

under the current working directory (CLI) or under `registry_root/evidence` when resolved through API settings.

You may override the directory with:

```bash
export RECKLOCK_EVIDENCE_DIR=/path/to/evidence
```

## What gets logged

Each line is a JSON object with:

- `event_kind`: `observation` | `error` | `external_call`
- `ts`: UTC ISO timestamp
- `agent_id`, `action`, & optional `capability`, `permission_scope`, `resource_type`, `resource_id`
- optional redacted `metadata`

## What never gets logged

- Raw API keys, bearer tokens, passwords, private keys, or long opaque secret-like strings.
- Keys whose names match common secret patterns (`api_key`, `token`, `password`, …) — values are replaced with `[REDACTED]`.

## Adding wrappers

Instrument code paths manually when safe:

```python
from recklock.discovery.telemetry import record_agent_observation

record_agent_observation(
    "agt_my-agent_deadbeef",
    "fetch_context",
    capability="llm_inference",
    permission_scope="ai.invoke",
    metadata={"route": "/chat"},
)
```

Keep metadata minimal & non-sensitive.

## Evidence reports

```bash
recklock-registry evidence-report --days 7 --registry-root .
```

Produces `evidence/evidence_report_<date>.json` & a Markdown sibling summarizing agents seen, event counts, external calls by provider, errors, risk buckets, & deterministic governance **recommendations** (suggestions only — not enforcement).

## API surface

When running `recklock-registry serve` with observation mode enabled & appropriate API keys:

- `POST /telemetry/observation`
- `POST /telemetry/error`
- `POST /telemetry/external-call`
- `GET /evidence/report?days=7`
- `GET /discovery/candidates`

RBAC: append routes require `observation.append`; read routes require `observation.read` (see role matrices in `recklock/auth/service.py`).

## Next steps after one week

Use the weekly exports to decide which agents deserve approval workflows, connector restrictions, or trust scoring in Phase 4B — still driven by evidence, not guesses.
