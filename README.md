# ReckLock Registry

ReckLock Registry is a small, file-based **AI agent identity registry**. Phase 1A stores agent metadata as **unsigned YAML manifests** on disk and builds a machine-readable **`registry/index.json`** summary for tooling & automation.

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
