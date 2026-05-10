# ReckLock Discover Report

- Scanner version: `0.1.0`
- Scanned path: `/path/to/your/repo`
- Scanned at: `2026-05-08T00:00:00Z`
- Files scanned: **4**
- Files with findings: **4**
- Total findings: **4**

## Findings by Type

| Bucket | Count |
| --- | --- |
| `deployment_workflow` | 2 |
| `llm_tool` | 1 |
| `payment_or_financial_workflow` | 1 |

## Findings by Risk

| Bucket | Count |
| --- | --- |
| `critical` | 3 |
| `high` | 1 |

## Findings by Recommended Action

| Bucket | Count |
| --- | --- |
| `govern` | 3 |
| `register` | 1 |

## Top candidates to govern first

_These are critical-risk findings the scanner recommends governing with strict approval & policy._

- `.github/workflows/deploy.yml` — **deployment_workflow** (critical, high) → action: `govern`
- `deploy.sh` — **deployment_workflow** (critical, medium) → action: `govern`
- `workers/nightly_billing.py` — **payment_or_financial_workflow** (critical, high) → action: `govern`

## Top candidates to register with ReckLock Registry

_These are high-risk findings the scanner recommends registering before governing._

- `ai_agent.py` — **llm_tool** (high, medium) → action: `register`

## All findings

### `.github/workflows/deploy.yml` — Deploy

- finding_id: `find_28802fbf11c8`
- finding_type: `deployment_workflow`
- risk_level: **critical**
- confidence: `high`
- recommended_action: **govern**
- likely_capabilities: `ci_pipeline`, `deploy_code`, `infrastructure_mutate`
- likely_permission_scopes: `ci.execute`, `infrastructure.write`, `production.deploy`, `repository.write`, `secrets.read`
- rationale: _Classified as deployment_workflow (high confidence) at risk=critical. Recommended action: govern. Top signals: GitHub Actions workflow body, GitHub Actions workflow file, kubectl invocation, secret env var._
- signals:
  - **GitHub Actions workflow file** (ci_cd, filename match)
  - **kubectl invocation** (deploy_infra, line 10) — `      - run: kubectl apply -f infra.yml`
  - **secret env var** (secrets, line 12) — `          AWS_SECRET_ACCESS_KEY=[REDACTED]`
  - **GitHub Actions workflow body** (ci_cd, line 9) — `      - uses: actions/checkout@v6`

### `ai_agent.py` — Ai Agent

- finding_id: `find_87813ac5608a`
- finding_type: `llm_tool`
- risk_level: **high**
- confidence: `medium`
- recommended_action: **register**
- likely_capabilities: `llm_inference`, `write_database`
- likely_permission_scopes: `ai.invoke`, `database.write`
- rationale: _Classified as llm_tool (medium confidence) at risk=high. Recommended action: register. Top signals: database write operation, imports or calls Anthropic, imports or calls OpenAI._
- signals:
  - **imports or calls OpenAI** (llm_ai, line 2) — `import openai`
  - **imports or calls Anthropic** (llm_ai, line 3) — `from anthropic import Anthropic`
  - **database write operation** (database, line 6) — `response = client.chat.completions.create(`

### `deploy.sh` — Deploy

- finding_id: `find_30883d1df2fc`
- finding_type: `deployment_workflow`
- risk_level: **critical**
- confidence: `medium`
- recommended_action: **govern**
- likely_capabilities: `deploy_code`, `infrastructure_mutate`
- likely_permission_scopes: `infrastructure.write`, `production.deploy`, `secrets.read`
- rationale: _Classified as deployment_workflow (medium confidence) at risk=critical. Recommended action: govern. Top signals: kubectl invocation, secret env var._
- signals:
  - **kubectl invocation** (deploy_infra, line 3) — `kubectl apply -f infra.yml`
  - **secret env var** (secrets, line 4) — `export AWS_SECRET_ACCESS_KEY=[REDACTED]`

### `workers/nightly_billing.py` — Nightly Billing

- finding_id: `find_5c914d2eb241`
- finding_type: `payment_or_financial_workflow`
- risk_level: **critical**
- confidence: `high`
- recommended_action: **govern**
- likely_capabilities: `financial_data_access`, `initiate_payment`, `scheduled_execution`, `write_database`
- likely_permission_scopes: `database.write`, `finance.read`, `payments.initiate`, `scheduler.trigger`, `secrets.read`
- rationale: _Classified as payment_or_financial_workflow (high confidence) at risk=critical. Recommended action: govern. Top signals: API key reference, Stripe SDK / API, database write operation, schedule library, secret env var._
- signals:
  - **database write operation** (database, line 6) — `    stripe.PaymentIntent.create(amount=1000, currency="usd")`
  - **Stripe SDK / API** (payments_financial, line 2) — `import stripe`
  - **API key reference** (secrets, line 4) — `stripe.api_key=[REDACTED]`
  - **secret env var** (secrets, line 4) — `stripe.api_key=[REDACTED]`
  - **schedule library** (schedule, line 7) — `schedule.every().day.at("02:00").do(charge)`

---

_ReckLock Discover is a heuristic static analyzer. Findings are educated guesses, not absolute proof. Always review high-risk paths manually before acting._
