# ReckLock Registry connectors (Phase 3D)

Connectors are **small enforcement adapters** that sit between validated ReckLock Registry execution decisions & **external systems** (issue trackers, chat, email, cloud APIs, banks). The registry & gateway prove **who** the agent is & **what** policies allow; connectors carry **how** that intent becomes a real-world action under guardrails.

## Connector framework

Each connector exposes stable metadata & lifecycle hooks:

| Surface | Purpose |
|--------|---------|
| `connector_id` | Stable identifier (e.g. `mock`, `github`, `slack`, `email`). |
| `name` | Human label for listings & audit. |
| `supported_capabilities` | Allowed action names (`create_issue`, `send_message`, …). |
| `required_permission_scopes` | Minimum manifest / request scopes; use `*` when any scope is acceptable (testing only). |
| `validate_config(dict)` | Structural validation before any side effect. |
| `dry_run(ConnectorRequest)` | Cheap validation path — **no** external calls in shipped integrations. |
| `execute(ConnectorRequest)` | Real side effects — **disabled by default** (see below). |

Wire models (`ConnectorConfig`, `ConnectorRequest`, `ConnectorResponse`) normalize payloads & audit-friendly outcomes. **`ConnectorResponse`** records `connector_id`, `action`, `dry_run`, `success`, `message`, optional `external_reference`, & optional redacted `metadata`.

Discovery:

- **HTTP:** `GET /connectors` (authenticated)
- **CLI:** `recklock-registry list-connectors`

Direct invocation (policy bypass — ops / demos only):

- `POST /connectors/dry-run`
- `POST /connectors/execute`

CLI dry-run:

```bash
recklock-registry connector-dry-run path/to/connector-request.yaml
```

## Gateway integration

The execution gateway (`POST /execution/request`, CLI `execute-request`) follows:

1. Receive `ExecutionRequest` (optional `connector_id`, `connector_action`, `connector_config`, `dry_run`).
2. Validate agent manifest & registry membership.
3. Evaluate policies & approvals (existing Phase 2D behavior).
4. If **allowed**, optionally invoke the connector registry (`dry_run` vs `execute` follows `ExecutionRequest.dry_run`, default **`true`**).
5. Append audit metadata under `connector_result` (**secrets stripped** via redaction helpers).
6. Return `ExecutionResponse` including nested `connector` when a connector ran.

Denied policy outcomes **do not** invoke connectors.

## Dry-run safety

- **`dry_run` defaults to `true`** on execution requests & connector HTTP helpers unless explicitly set otherwise.
- Dry-run paths validate envelopes & return structured responses **without** turning on external integrations.
- Audit trails record connector outcomes without embedding raw tokens or passwords.

## Real execution guardrail

Non-mock external execution is gated globally:

```bash
export AGENTTRUST_ENABLE_REAL_CONNECTORS=true
```

Until set, GitHub / Slack / Email `execute()` responses report that real execution is disabled. **No payment movement, bank APIs, or cloud credential brokering** are implemented in this phase.

## Monetization & infrastructure positioning

Connectors turn ReckLock Registry from a compliance ledger into **paid enforcement infrastructure**: customers integrate once at the gateway, then ship incremental connectors (ticketing, CRM, infra) without bypassing policy & audit. Billing hooks belong outside this package; the monetizable surface is **controlled outbound action** with attestable decisions.

## Future connectors

Likely next integrations — still behind the same dry-run default & explicit enablement pattern:

- **Stripe** & payments rails (with PCI-isolated execution environments).
- **AWS** / **GCP** scoped IAM sessions (no long-lived keys in ReckLock Registry).
- **GitHub Actions** deployment approvals tied to registry identities.
- **Banking** & treasury APIs via hosted connectors & contractual review.
- **CI/CD** (CircleCI, Jenkins) gated deploy connectors.

Each addition should extend `supported_capabilities`, tighten `required_permission_scopes`, & keep secrets out of logs & API payloads.
