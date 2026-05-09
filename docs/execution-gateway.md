# Execution gateway (Phase 2C)

## Runtime interception

The execution gateway sits **between** an AI agent’s intent and any side-effecting tool call (payments, deployments, data export, privileged APIs). Instead of invoking capabilities directly, the runtime submits an **execution request**: who is acting, what capability is requested, and under which permission scope.

The gateway answers with a single structured decision before work proceeds:

- **allowed** — policy & registry checks passed; the host runtime may execute.
- **denied** — blocked (unknown agent, invalid manifest path, undeclared capability or scope, or explicit deny rule).
- **pending_approval** — policy requires human approval before execution.

This phase keeps evaluation **local**, **synchronous**, and **deterministic**: same inputs yield the same decision and the same deterministic audit event identifier (before append-only sealing hashes the stored record).

## Why execution gateways matter

A registry alone proves **what was registered**. An execution gateway proves **what was attempted at runtime** and whether it was permitted under policy. Together they reduce “shadow automation”: agents cannot silently exceed declared capabilities or scopes if the host routes sensitive actions through the gateway.

## Relationship to policy enforcement

The gateway reuses the Phase 2A **policy engine** (`evaluate_action`). Registry validation narrows the request to manifest-declared capabilities & scopes; policies then encode organizational rules (deny production deploys, require approval over monetary thresholds, etc.). Deny still wins over approval, which wins over allow, matching the policy engine’s precedence.

## Relationship to audit events

Every gateway evaluation produces an **audit template** (`AuditEvent` with `event_type: gateway.execution`). The CLI command `recklock-registry execute-request` appends that record to the Phase 2B **hash-chained** NDJSON log so decisions are tamper-evident in sequence.

Gateway responses include `audit_event_id`, which matches the `event_id` written after sealing.

## Future enterprise runtime integrations

Later phases can swap **local YAML + JSON files** for enterprise controls without changing the core flow: submit execution request → validate identity against registry → evaluate policies → emit audit → return allow/deny/pending. Plausible integrations include centralized policy APIs, HSM-backed signing, IAM-bound scopes, ticketing systems for approvals, and fleet-wide audit sinks — still behind the same conceptual gateway boundary.

No network listener, OAuth provider, or cloud deployment is required for the Phase 2C reference implementation; it is intentionally host-local & testable.
