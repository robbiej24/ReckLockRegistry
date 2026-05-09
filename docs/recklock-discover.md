# ReckLock Discover

ReckLock Discover is an open-source, **static-analysis** tool that scans a
repository to discover AI agents, automations, scheduled jobs, CI/CD
workflows, deployment scripts, and other sensitive execution paths.

It is useful even if you have not yet adopted ReckLock Registry — the
scanner answers a single high-leverage question:

> What autonomous or semi-autonomous agents and workflows already live in
> this repo, what permissions do they likely have, and which ones should be
> registered or governed first?

## Why agent discovery matters

Modern repos accumulate small autonomous workflows quickly: a Slack-posting
job, a coding assistant, a deploy script, a Stripe webhook handler, a
nightly Postgres rebuilder, an AI summarizer that calls OpenAI from CI, a
browser-automation script that scrapes a vendor portal. Most teams have
no inventory of these workflows. Without that inventory:

- New agents get added without any review.
- Risky permissions (deploy, payments, database writes) accumulate silently.
- Incident response is slower because nobody knows what's running where.
- Policy & approval programs have nothing to attach to.

ReckLock Discover produces a deterministic inventory you can read in
GitHub, hand to security, or pipe into ReckLock Registry as draft
manifests for review.

## What it detects

ReckLock Discover emits **findings** for files that contain one or more
of the following signals.

| Category | Examples |
| --- | --- |
| LLM / AI | OpenAI, Anthropic, Google Generative AI, Vertex, LangChain/LangGraph, CrewAI, AutoGen, LlamaIndex, Ollama, LiteLLM, Instructor, Semantic Kernel, tool/function calling, agent framework references |
| Outbound communications | smtplib, SendGrid, Postmark, Resend, Mailgun, Slack SDK & webhooks, Discord, Twilio, generic webhooks |
| Browser & HTTP automation | Playwright, Selenium, Puppeteer, browser-use, requests, httpx, aiohttp |
| Deployment & infra | Docker, kubectl, Helm, Terraform, Pulumi, AWS/gcloud/azure CLIs, boto3, Vercel, Netlify, Railway, Fly.io |
| Database | DATABASE_URL, psycopg, SQLAlchemy, Prisma, Supabase, Firebase, Redis, INSERT/UPDATE/DELETE, ORM writes |
| Payments / financial | Stripe, Plaid, Dwolla, PayPal, banking/wallet/payment/payout/transfer/ACH/KYC keywords |
| Secrets / credentials | API_KEY/SECRET/TOKEN/PRIVATE_KEY/PASSWORD env vars, Authorization & Bearer headers, common provider key formats |
| Scheduling / background | cron, schedule, APScheduler, Celery, RQ, GitHub Actions schedule blocks |
| Shell execution | subprocess, os.system, os.popen, exec/eval, Node child_process/spawn |
| CI/CD | `.github/workflows/*.yml`, GitHub Actions job bodies |

## Finding model

Every finding is a `ScannerFinding`:

| Field | Description |
| --- | --- |
| `finding_id` | Stable id derived from the file path |
| `name` | Human-readable label |
| `path` | Repo-relative path |
| `line_numbers` | Line numbers of detected signals |
| `finding_type` | One of: `ai_agent`, `llm_tool`, `automation_agent`, `outbound_agent`, `browser_agent`, `scheduled_job`, `ci_cd_workflow`, `deployment_workflow`, `database_writer`, `payment_or_financial_workflow`, `secret_using_workflow`, `shell_execution_workflow`, `unknown` |
| `confidence` | `low`, `medium`, `high` |
| `risk_level` | `low`, `medium`, `high`, `critical` |
| `signals` | Detected signal labels with line number & redacted snippet |
| `likely_capabilities` | Inferred capabilities (e.g. `write_database`, `deploy_code`) |
| `likely_permission_scopes` | Inferred ReckLock Registry scopes (e.g. `database.write`, `production.deploy`) |
| `recommended_action` | `monitor`, `register`, `govern`, `manual_review` |
| `rationale` | Plain-English summary of how the classification was reached |

## Risk classification (deterministic rules)

The scanner uses a deterministic ladder — no LLMs, no probabilities.

- **Critical** — payments combined with money-movement verbs or a database
  write, deployment combined with secrets, deploy + secrets + shell, or
  database writes inside a production-deploy file.
- **High** — outbound communication, shell execution, database writes,
  cloud/deploy tooling, or LLM usage with tool calling.
- **Medium** — LLM usage without tool calling, scheduled automation, CI
  workflows without deploy permissions, browser/HTTP clients, secret env
  references, scripts referencing `DATABASE_URL`.
- **Low** — read-only scripts, public-data tools, or ambiguous matches.

Recommendations follow risk:

- `critical` → **govern**
- `high` → **register**
- `medium` → **register** (if confidence is high) else **monitor**
- `low` → **monitor**
- Low-confidence high/critical signals → **manual_review**

## How to run a scan

```bash
pip install -e .

recklock-registry scan-repo /path/to/repo
```

Default behavior:

- Walks the repo, skipping `.git`, `node_modules`, `.venv`, `dist`, `build`,
  `.next`, `.turbo`, `__pycache__`, `.pytest_cache`, etc.
- Reads only relevant file types (`.py`, `.ts/.tsx`, `.js/.jsx`, `.sh/.bash/.zsh`,
  `.yml/.yaml`, `.json`, `Dockerfile`, `docker-compose.yml`, `package.json`,
  `pyproject.toml`, `requirements.txt`, `.github/workflows/*`).
- Writes both `recklock_discover_scan_report.json` & `recklock_discover_scan_report.md`.

### Options

```bash
recklock-registry scan-repo PATH --output-dir reports/
recklock-registry scan-repo PATH --add-to-registry
recklock-registry scan-repo PATH --export-manifests
recklock-registry scan-repo PATH --min-confidence medium
recklock-registry scan-repo PATH --include "*.py,*.ts,.github/workflows/*.yml"
recklock-registry scan-repo PATH --exclude "fixtures,*.min.js"
recklock-registry scan-repo PATH --format json
```

## Exporting manifests

Pass `--export-manifests` to generate **unsigned ReckLock Registry manifest drafts**
for every finding whose `recommended_action` is `register`, `govern`, or
`manual_review`:

```bash
recklock-registry scan-repo /path/to/repo --export-manifests
```

Local human runs can also opt in after the scan:

> ReckLock Discover found 6 AI agents. Add them to your ReckLock Registry so you can display:
>
> - That you own them
> - What their capabilities are
> - Which risks they carry &
> - Allow other people who want to license your agents to contact you?

Choose yes, or pass `--add-to-registry`, to write draft manifests and copy
them into `registry/discovered/`. Pass `--skip-registry` to explicitly skip.
Non-interactive runs and `--format json` never prompt.

Default output directory:

```
recklock_manifest_exports/
  agt_<slug>_<hash>.yaml
  agt_<slug>_<hash>.yaml
  ...
```

Each manifest includes:

- A stable `agent_id`
- `developer.name: "Unknown"` (edit before publishing)
- `agent_type` mapped from the finding type
- Inferred `capabilities` & `permission_scopes`
- `risk_level` from the scan
- `requires_human_approval: false` (review and tighten)
- A `metadata` block with:
  - `scanner_generated: true`
  - `scanner_version`
  - `source_path`
  - `detected_signals`
  - `recommended_action`
  - `created_at` / `updated_at`
  - `registry_version`

Manifests are **never auto-signed**. They are not added to the registry
unless you explicitly run the import command below.

## Importing manifests into ReckLock Registry

```bash
recklock-registry import-scan-manifests path/to/recklock_manifest_exports/ \
  --registry-root /path/to/your/registry
```

The import command:

1. Validates each manifest against the ReckLock Registry schema.
2. Copies valid manifests into `registry/discovered/`.
3. Skips files that already exist (use `--overwrite` to replace them).
4. Rebuilds `registry/index.json` (use `--no-build-index` to skip).

## How to review findings manually

1. Open `recklock_discover_scan_report.md` and start with the **Top candidates to
   govern first** section.
2. For each finding, read the `signals` block and open the file at the
   listed line numbers to confirm the behavior.
3. Edit the corresponding manifest in `recklock_manifest_exports/` to
   replace `developer.name`, refine `capabilities` / `permission_scopes`,
   and decide whether `requires_human_approval` should be `true`.
4. When the manifest reflects reality, run `recklock-registry import-scan-manifests`
   to land it in `registry/discovered/`, then optionally promote it to
   `registry/agents/`.

## Why scanner results are heuristic, not absolute proof

ReckLock Discover is intentionally simple and deterministic:

- It uses regex/substring detectors, not an LLM.
- It does not execute any code.
- It does not infer behavior across files — each finding is per-file.
- It cannot distinguish a real agent from a test fixture without context.

Treat findings as **review prompts**, not verdicts. The scanner can have
false positives (e.g. a `requests` import in a single helper) and false
negatives (e.g. an exotic homemade scheduler). Always confirm by reading
the source.

## Safety & redaction

The scanner is designed to surface dangerous code paths without leaking
the credentials it finds.

- All matched lines are passed through `recklock.scanner.redaction.redact_line`
  before being placed in a finding.
- Env-style assignments (`API_KEY=...`, `STRIPE_SECRET_KEY=...`,
  `DATABASE_URL=...`), bearer tokens, common provider key formats
  (`sk-...`, `ghp_...`, `AKIA...`), and long high-entropy strings are
  replaced with `[REDACTED]`.
- Block-form private keys (`-----BEGIN PRIVATE KEY-----`) are redacted entirely.
- Reports never include the full content of files — only the matched line
  with secrets removed, capped to 240 characters.

The scanner does not perform any of the following:

- No network calls
- No LLM calls
- No telemetry
- No SaaS upload
- No enforcement, blocking, or approval workflows
- No modifications to your registry unless you explicitly run
  `recklock-registry import-scan-manifests`
