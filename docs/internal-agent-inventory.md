# Internal agent inventory (Phase 4A)

HealthyLineups uses this monorepo as the first internal pilot for ReckLock Registry: discover automated execution paths, register draft manifests, collect passive evidence for roughly one week, then decide what to govern next.

## Purpose

- Find likely AI agents, scripts, CI/CD workflows, schedulers, deployment paths, and integrations.
- Emit unsigned manifest drafts under `registry/discovered/` for review.
- Stay **observation-only**: no blocking, no policy enforcement, no approval gates, & no production behavior changes from this phase alone.

## How discovery works

The scanner walks the repository (skipping typical vendor & cache directories), reads text-like files within a size limit, & attaches human-readable **signals** (for example OpenAI imports, GitHub Actions shape, database writes, Stripe references).

Deterministic classifiers map signals to:

- a coarse **candidate type** (AI agent, CI workflow, deployment workflow, etc.)
- guessed **capabilities** & **permission scopes**
- a heuristic **risk** band & **confidence** score

Low-confidence or unknown-type hits should be treated as a **manual review queue**, not as ground truth.

## Manifest generation

For each candidate, the tooling generates a YAML manifest draft that validates against the core `AgentManifest` schema, includes Phase 4A metadata (`observation_mode`, `governance_status`, `source_path`, `discovered_at`), & embeds a structured `discovery` block with signals & confidence.

Manifest identifiers follow `agt_<slugified-source-path>_<short-hash>`.

Existing files under `registry/discovered/` are left untouched unless you pass `--overwrite`.

## Registry index

`registry/index.json` includes manifests from **both**:

- `registry/agents/` (canonical / human-curated)
- `registry/discovered/` (draft inventory)

If the same `agent_id` appears in both trees, the **`registry/agents`** entry wins.

## Commands

Run these from the ReckLock Registry project directory (or pass `--registry-root`).

```bash
recklock-registry discover-agents --repo-root /path/to/monorepo --registry-root .
```

Writes `evidence/discovered_agents.json` & prints a short preview.

```bash
recklock-registry register-discovered-agents --registry-root .
```

Reads the discovery report, writes manifests into `registry/discovered/`, & rebuilds `registry/index.json` unless `--no-build-index` is set.

```bash
recklock-registry inventory-internal-agents --repo-root /path/to/monorepo --registry-root .
```

Runs discovery, registers drafts, prints JSON summary counts (including high / critical risk & manual-review queue).

## Manual review checklist

1. Open `evidence/discovered_agents.json` & sort by `risk_level_guess` & `confidence`.
2. For each draft under `registry/discovered/`, confirm whether the file represents a real agent or automation & adjust naming, scopes, & risk before signing anything in a later phase.
3. Keep `AGENTTRUST_OBSERVATION_MODE` enabled only while you intend to collect telemetry (see `docs/passive-telemetry.md`).
