# ReckLock Registry

ReckLock Registry is a small, file-based **AI agent identity registry**. Phase 1A stores agent metadata as **unsigned YAML manifests** on disk and builds a machine-readable **`registry/index.json`** summary for tooling & automation.



<!-- hl-readme-agent:start -->
## Agent quick access

- New chat entry: `bash scripts/agent_task_entry.sh "<task>"` (from repo root).
- Monorepo agent map: [`AGENTS.md`](../../../../AGENTS.md).
- Stack pins: [`STACK_VERSIONS.md`](../../../../STACK_VERSIONS.md).
- Pytest: `scripts/run-pytest.sh` or package `.venv/bin/python -m pytest` (never bare Homebrew `python3 -m pytest`).
- AWS: agent shells use `AWS_PROFILE=hl-sso-ro` only; deploy/`hl-sso-admin` is human-only.

<!-- hl-readme-agent:end -->

<!-- hl-readme-stack:start -->
## Current stack versions

Direct dependencies from nearby manifests. Full monorepo inventory: [`STACK_VERSIONS.md`](../../../../STACK_VERSIONS.md). Regenerate with `python3 scripts/sync_readme_agent_sections.py`.

### `Core/ReckLockFamily/ReckLockShield/ReckLockRegistry/pyproject.toml`

- Package name: `recklock-registry`
- Runtime: python >=3.11
- Kind: `pyproject`

| Package | Spec |
|---|---|
| `fastapi` | `>=0.136.3` |
| `httpx` | `>=0.27` |
| `jinja2` | `>=3.1` |
| `psycopg[binary]` | `>=3.1` |
| `pydantic` | `>=2.5` |
| `pydantic-settings` | `>=2.2` |
| `PyNaCl` | `>=1.5` |
| `pytest` | `>=7.4` |
| `python-multipart` | `>=0.0.9` |
| `pyyaml` | `>=6.0` |
| `sqlalchemy` | `>=2.0` |
| `starlette` | `>=1.3.1` |
| `typer` | `>=0.9` |
| `uvicorn[standard]` | `>=0.27` |


<!-- hl-readme-stack:end -->

Signing, CI, audit logs, enterprise features, and a web UI are **not** part of Phase 1A.

## Requirements

- Python 3.11+

## Install locally

From this directory:

```bash
pip install -e .
```

This installs the `recklock-registry` CLI.

## Validate a manifest

```bash
recklock-registry validate path/to/manifest.yaml
```

Exit code `0` means the manifest passes schema & field rules (including `agent_id` format, allowed `agent_type` / `risk_level` values, & required nested fields).

## Build the index

From the repository root (where `registry/agents/` lives):

```bash
recklock-registry build-index
```

Options:

- `--agents-dir` — directory of YAML manifests (default: `registry/agents`)
- `--index-out` — output JSON path (default: `registry/index.json`)
- `--root` — root used to compute relative `manifest_path` entries (default: current working directory)

## Manifest layout

See `registry/agents/example-agent.yaml` for a valid example.

## ReckLock Discover (open source)

`recklock-registry scan-repo PATH` is a static-analysis scanner that discovers
AI agents, automations, scheduled jobs, CI/CD workflows, deployment
scripts, and other sensitive execution paths in any repository — even
ones not yet using ReckLock Registry. See [`docs/recklock-discover.md`](docs/recklock-discover.md)
for the full scanner guide, finding model, & risk classification rules.

```bash
recklock-registry scan-repo /path/to/repo
recklock-registry scan-repo /path/to/repo --export-manifests
recklock-registry import-scan-manifests recklock_manifest_exports/
```

## Later phases (planned)

- **Signing** — cryptographic verification of manifests & registry artifacts
- **CI** — automated validation & index builds (e.g. GitHub Actions)
- **Audit logs** — append-only history of registry changes
- **Enterprise** — policies, RBAC, & hosted registry APIs (as needed)

## License

MIT — see `LICENSE`.
