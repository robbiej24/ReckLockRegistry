# Persistence (Phase 3B)

The ReckLock Registry API persists operational data in a relational database using **SQLAlchemy Core** (synchronous sessions). There is **no Alembic** and **no migration framework**: schema is defined in explicit SQL and applied idempotently at startup or via CLI.

## Configuration

| Input | Purpose |
|-------|---------|
| `DATABASE_URL` | Primary SQLAlchemy URL (wins over defaults when set). |
| `RECKLOCK_DATABASE_URL` | Prefixed alternative when using `ApiSettings`. |
| `RECKLOCK_DATABASE_URL` field default | Falls back to `sqlite:///./recklock.local.db` when neither env var is set. |

Runtime URL resolution order:

1. `DATABASE_URL`
2. `RECKLOCK_DATABASE_URL`
3. `ApiSettings.database_url` (default SQLite file in the current working directory)

## Local SQLite fallback

For development and tests, SQLite is the default. No separate database server is required. Tests typically point `database_url` at a temporary file (for example `sqlite:////tmp/.../test.db`).

## PostgreSQL deployment

Set `DATABASE_URL` to a PostgreSQL URL, for example:

`postgresql+psycopg://user:pass@host:5432/recklock`

Install a PostgreSQL driver (for example `psycopg[binary]`) alongside this package. The bundled `db/schema.sql` uses portable types (`TEXT`, `INTEGER`) so the same file applies to PostgreSQL and SQLite.

## `recklock-registry init-db`

Runs `db/schema.sql` and optionally `db/seed.sql`:

```bash
recklock-registry init-db
recklock-registry init-db --no-seed
recklock-registry init-db --database-url "postgresql+psycopg://..."
```

The command is **idempotent**: repeated runs rely on `CREATE TABLE IF NOT EXISTS` and do not destroy existing rows.

## Schema files

- **`db/schema.sql`** — canonical DDL checked into the repo; reviewed like application code.
- **`db/seed.sql`** — optional reference inserts (comment-only by default).

API processes should assume tables exist (run `init-db` in deploy scripts or container entrypoints).

## Why no Alembic

Alembic adds migration ordering, revision history, and operational overhead. For this registry, **additive DDL** in `schema.sql` plus idempotent `CREATE IF NOT EXISTS` keeps upgrades simple and reviewable. Breaking changes should be handled with explicit SQL scripts and coordinated releases—not implicit ORM migrations.

## What is persisted

| Area | Storage |
|------|---------|
| Audit trail | `audit_events` (hash chain fields stored per row). |
| Approvals | `approvals` (latest row per `approval_id`). |
| Trust profiles | `trust_profiles` (per-agent JSON snapshot). |
| Incidents | `incidents` (append-style rows). |
| Execution gateway | `execution_requests` and `execution_responses`. |
| Agents / policies | `agents` and `policies` tables for repository APIs (registry manifests remain the source of truth for manifest workflows until you sync them). |

Local manifest files, `registry/index.json`, and CLI file-backed logs remain supported for offline workflows; the HTTP API uses the database for the domains listed above.
