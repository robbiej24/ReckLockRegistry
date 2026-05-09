# ReckLock Registry API server (Phase 3A)

The HTTP layer wraps the same registry, policy engine, execution gateway, audit log, approval store, and trust-scoring code paths that the `recklock-registry` CLI uses. A network API is the default integration surface for other services, agents, and control planes, so policy & audit stay consistent without shelling out to commands.

## Why a runtime API matters

- **Service integration**: Upstream systems call JSON over HTTP instead of orchestrating YAML files & subprocesses.
- **Operational deployment**: You can run the server behind a reverse proxy, scale replicas, & attach health checks (this phase keeps storage on local files; databases & auth come later).
- **Enterprise path**: The same domain logic can later sit behind authentication, durable storage, & cross-region replication without rewriting evaluators.

## Run the server

From the package directory (or any directory where your registry paths resolve):

```bash
recklock-registry serve --host 127.0.0.1 --port 8080
```

Optional: fix the working root so relative paths (`registry/index.json`, `audit_logs/events.log`, etc.) resolve as expected:

```bash
recklock-registry serve --host 127.0.0.1 --port 8080 --registry-root /path/to/project
```

Environment overrides use the `RECKLOCK_` prefix (see `recklock.api.settings.ApiSettings`), for example `RECKLOCK_REGISTRY_ROOT`, `RECKLOCK_AUDIT_LOG_PATH`, `RECKLOCK_APPROVAL_LOG_PATH`, `RECKLOCK_TRUST_PROFILES_PATH`, `RECKLOCK_INCIDENTS_PATH`, `RECKLOCK_INDEX_PATH`.

You can also run Uvicorn directly on the factory-built app (uses environment-driven settings when `app.state` is not pre-set):

```bash
uvicorn recklock.api.app:app --host 127.0.0.1 --port 8080
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service status. |
| `GET` | `/agents/` | Agents array from `registry/index.json`. |
| `GET` | `/agents/{agent_id}` | One agent row from the index. |
| `POST` | `/policies/evaluate` | Body: `{ "request": ActionRequest, "policies": Policy[] }` → `PolicyDecision`. |
| `POST` | `/execution/request` | Body: `{ "request": ExecutionRequest, "policies": Policy[] }` → gateway result + sealed audit hashes; appends audit lines like the CLI. |
| `GET` | `/audit/events` | Read the local NDJSON audit log. |
| `POST` | `/audit/events` | Append one `AuditEvent` (chained hashing like `append_event`). |
| `GET` | `/approvals/` | Latest snapshot per approval id from the JSONL store. |
| `POST` | `/approvals/{approval_id}/approve` | Body: `{ "approver": "<id>" }`. |
| `POST` | `/approvals/{approval_id}/deny` | Body: `{ "approver": "<id>" }` (same field name as the CLI `--approver` flag). |
| `GET` | `/trust/profiles` | Trust profile snapshots (JSONL). |
| `POST` | `/trust/calculate` | Recompute scores from profiles + incident log; appends updated rows. |

Interactive schema: OpenAPI at `/docs` & `/redoc` when the server is running.

## Phase boundaries

- **In scope (3A)**: FastAPI + Uvicorn, file-backed registry & logs, thin routes delegating to core modules.
- **Not yet**: PostgreSQL, authentication, & web UI — each will plug in above this API layer without changing evaluators.
