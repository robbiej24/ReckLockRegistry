# Deployment

ReckLock Registry ships as a Python package (`recklock-registry`) with a Typer CLI (`recklock-registry`), a FastAPI API, & a browser dashboard under `/ui`. This document covers container images, Compose, Kubernetes, database initialization, & production-minded defaults.

## Requirements

- Python 3.11+ when running from source or wheel.
- PostgreSQL recommended for shared production state (SQLite remains supported for single-node lab use).
- Schema is applied **without Alembic**: idempotent DDL lives in `db/schema.sql` & is applied by `recklock-registry init-db`.

## Configuration

Environment variables use the `RECKLOCK_` prefix unless noted. Common keys:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Preferred SQLAlchemy URL (also accepts `RECKLOCK_DATABASE_URL`). Use `postgresql+psycopg://…` for PostgreSQL. |
| `RECKLOCK_ENV` | Short environment label (`production`, `staging`, …). |
| `RECKLOCK_API_HOST` | Bind address for `recklock-registry serve` (for example `0.0.0.0` in containers). |
| `RECKLOCK_API_PORT` | TCP port for `recklock-registry serve`. |
| `RECKLOCK_REGISTRY_ROOT` | Filesystem root for manifests, `registry/index.json`, audit logs, & related paths. |
| `RECKLOCK_ENABLE_REAL_CONNECTORS` | When `true`, connectors may perform real external side effects (default off). |
| `RECKLOCK_SECRET_KEY` | Reserved for future signing use; optional today. |

See `.env.example` for a starting point.

## Database initialization

1. **Provision PostgreSQL** & create a database role the application can use.
2. **Optional raw DDL review**: open `db/schema.sql` (portable `CREATE TABLE IF NOT EXISTS` / index statements).
3. **Apply schema idempotently**:

   ```bash
   export DATABASE_URL='postgresql+psycopg://user:pass@host:5432/recklock'
   recklock-registry init-db
   ```

   This runs the packaged `db/schema.sql` & optionally `db/seed.sql` when it contains executable statements. Safe to run on every deploy.

4. **Create at least one API key** (required for authenticated API & UI flows):

   ```bash
   recklock-registry create-api-key --name admin --role admin
   ```

The Docker image entrypoint runs `recklock-registry init-db` before `recklock-registry serve` unless `SKIP_INIT_DB=1` is set (for advanced operator-controlled init).

## Local Docker image

From the `recklock-registry` directory:

```bash
docker build -t recklock-registry:local .
docker run --rm -p 8080:8080 \
  -e DATABASE_URL='sqlite:////tmp/recklock.db' \
  -e RECKLOCK_API_HOST=0.0.0.0 \
  -e RECKLOCK_REGISTRY_ROOT=/tmp/registry \
  recklock-registry:local
```

The API listens on port **8080** (`GET /health`, `GET /ready`). Visit `/ui` for the dashboard.

## Docker Compose

`docker-compose.yml` starts PostgreSQL & the application. Compose sets `RECKLOCK_REGISTRY_ROOT` under `/tmp` so the non-root container user can write registry files without extra volume permission tuning; swap in a mounted volume for durable manifests when you are ready to manage ownership or use Kubernetes `fsGroup`.

```bash
docker compose up --build
```

Initialize schema automatically via the image entrypoint, then browse `http://localhost:8080/ui` after creating an API key inside the container or from a workstation sharing the same `DATABASE_URL`.

## Kubernetes (Helm)

A minimal chart lives under `deploy/helm/`. Build & push your image to a registry your cluster can pull, then:

```bash
helm upgrade --install recklock-registry ./deploy/helm \
  --set image.repository=your.registry/recklock-registry \
  --set image.tag=0.1.0 \
  --set database.url='postgresql+psycopg://…'
```

Set `ingress.enabled` & related fields when you need an Ingress. Mount persistent registry storage by replacing the chart’s `emptyDir` volume with a PVC in a fork or overlay—keep changes small & explicit.

## Health checks

- **`GET /health`**: liveness — process is up.
- **`GET /ready`**: readiness — executes `SELECT 1` against the configured SQLAlchemy engine so orchestrators can detect broken DB connectivity.

## Production notes

- Run behind TLS at your proxy or Ingress; do not expose plain HTTP across trust boundaries.
- Store `DATABASE_URL` & API keys in your secrets manager (Kubernetes Secret, Vault, cloud SM, …).
- Pin image digests in Kubernetes & rebuild on security patches to the base Python image.
- Plan backups for PostgreSQL & for filesystem registry artifacts if you rely on file-backed manifests & logs.
