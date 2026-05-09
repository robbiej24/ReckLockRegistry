# ReckLock Registry operational web dashboard (Phase 3F)

The dashboard is a **minimal, server-rendered** UI for operators & auditors. It explains what ReckLock Registry is doing in production: registered agents, policies (counts), audit volume, approvals, trust posture, broker credentials, & gateway executions.

## Why operational visibility matters

Enterprise buyers need evidence that controls are **actually enforced**, not only documented. A thin operational UI turns registry data into **explainable posture**: what is registered, what was approved, what the gateway decided, & what the audit chain recorded. That narrative supports security reviews, procurement diligence, & ongoing governance without standing up a separate analytics product.

## How to run the dashboard

Start the API server the same way you run ReckLock Registry today (for example `uvicorn agenttrust.api.app:app` from the package root with `AGENTTRUST_*` env vars set). Then open:

- **Overview:** `/ui/`
- **Static assets:** `/ui/static/app.css`

### Authentication

HTML routes use the **same API keys** as the JSON API:

1. **Bearer header** — `Authorization: Bearer <token>` (ideal for automation & tools that can set headers).
2. **Browser cookie** — POST to `/ui/sign-in` with form field `token` (API key). A successful sign-in sets an HTTP-only cookie used on subsequent `/ui/*` requests for seven days.

Roles & permissions match `docs/auth-rbac.md`. Each page checks the same permission strings the REST surface uses (for example `agents.read`, `audit.read`, `approvals.read`).

## What each page shows

| Path | Content |
|------|---------|
| `/ui/` | Snapshot cards: agent count, audit event total, pending approvals, active credentials, high-risk agents (trust band), & registered policy count when your role can evaluate policies. |
| `/ui/agents` | Table of agents persisted in the registry database (`list_agents`). |
| `/ui/audit` | Latest audit events (newest first), sealed chain metadata surfaced through repository helpers — **no raw secrets**. |
| `/ui/approvals` | Pending approval rows; approve/deny forms appear only when the caller holds `approvals.approve` / `approvals.deny`. Human approver identity is collected per action (same concept as the REST API body field `approver`). |
| `/ui/trust` | Trust profiles with scores & bands; short explanation of bands (`trusted` through `critical_risk`). |
| `/ui/credentials` | Broker credentials with status (active vs expired vs revoked). Only a **short hash fingerprint** is shown — never the temporary token. |
| `/ui/executions` | Recent execution request/response pairs stored after gateway runs (joined rows). |

Empty tables show a clear **empty state** instead of failing silently.

## Future enterprise dashboard features (not in this phase)

Reasonable next steps if you outgrow this minimal UI:

- SSO / OIDC behind a reverse proxy instead of shared API keys for humans.
- Saved filters, CSV export, & scheduled posture PDFs for audit customers.
- Per-tenant namespaces & delegated admin scopes.
- Deeper drill-down from an audit row to related approvals & executions (still without secret material).

This phase intentionally avoids React stacks, billing, marketing pages, & heavy charting so the registry stays easy to deploy & review.
