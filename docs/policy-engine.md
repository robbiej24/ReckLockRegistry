# Policy engine (Phase 2A)

## Why enforcement matters

Identity manifests describe who an agent is; **policy** decides whether a proposed action is acceptable under governance rules. Without a shared, testable policy layer, organizations cannot consistently block unsafe behavior, route high‑risk work to humans, or prove how decisions were made. Phase 2A adds a **deterministic policy evaluator** so the same request & policies always yield the same decision trace (aside from timestamps).

## How policies work

Policies are YAML‑serializable documents modeled with Pydantic:

- **`policy_id`** — Stable identifier; policies are evaluated in ascending order by this field.
- **`description`** — Human context (not used in logic).
- **`enabled`** — When false, the entire policy & its rules are skipped.
- **`rules`** — Ordered list. Each rule has:
  - **`rule_id`** — Identifier for audit traces.
  - **`effect`** — One of `allow`, `deny`, or `require_approval`.
  - **`conditions`** — Optional. When omitted, the rule matches every request. When present, every specified field must match the incoming **action request** (see below). Unspecified condition fields do not constrain the match.

### Action request

An action request describes one proposed operation:

- **`agent_id`**, **`capability`**, **`permission_scope`**, **`risk_level`** (required core fields)
- **`requires_human_approval`**, **`environment`**, **`amount`**, **`metadata`** — Optional context used by conditions.

### Example shapes

**Deny production deploy in production**

- Conditions: `capability: production.deploy`, `environment: production`
- Effect: `deny`

**Require approval for payments above a threshold**

- Conditions: `capability: payment.transfer`, `amount_gt: 1000`
- Effect: `require_approval`

**Deny critical agents operating without human approval**

- Conditions: `risk_level: critical`, `requires_human_approval: false`
- Effect: `deny`

**Allow low‑risk research actions**

- Conditions: `risk_level: low`, `capability: research.query` (or similar)
- Effect: `allow`

Amount comparisons use **`amount_gt`** / **`amount_lt`** against the optional **`amount`** field on the request (`>` / `<`, strict).

## Evaluation precedence

Only **enabled** policies participate. Within them:

1. Policies run in ascending **`policy_id`** order.
2. Rules run in **list order** inside each policy.
3. Every rule that matches is recorded (policy ids & rule ids preserve evaluation order; policy ids are listed once in first‑seen order).

Among all matched rules:

1. **`deny`** wins over everything else.
2. Otherwise **`require_approval`** wins over **`allow`**.
3. Otherwise **`allow`** if at least one matched rule had effect **`allow`**.
4. If **no** rule matched, the decision is **`allow`** (implicit default).

The resulting **`PolicyDecision`** includes **`decision`**, **`matched_policy_ids`**, **`matched_rule_ids`**, **`reason`**, & **`evaluated_at`** (UTC).

## CLI

```bash
recklock-registry evaluate-policy path/to/request.yaml path/to/policies.yaml
```

Loads the request & policies, evaluates, & prints JSON (sorted keys for stable output).

## Future runtime enforcement

Phase 2A is intentionally **local, synchronous, & storage‑free**. Later phases can:

- Attach the evaluator to runtime gateways (tool calls, deployments, payments).
- Persist decisions & hashes for audit.
- Combine manifests (identity) with policy packs (organization rules) & approvals workflows.

The precedence model here is designed to stay compatible with those extensions without changing the core semantics.
