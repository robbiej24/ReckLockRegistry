# Temporary credential broker (Phase 3E)

## Why not permanent agent credentials?

Long-lived secrets embedded in agents are hard to rotate, easy to exfiltrate, and blur accountability when something goes wrong. AI-native workloads benefit from **short-lived, scoped credentials** issued **after** policy evaluation and optional human approval — the same control plane ideas as privileged access management (PAM), adapted for automated actors.

## What this broker does

The broker mints an opaque bearer token **once**, returns it to the caller, and persists **only a SHA-256 hash** of that token plus metadata (scopes, resource, environment, TTL). Verification re-hashes the presented token and compares it to stored state (constant-time compare on the digest path). **Raw tokens are never written to disk.**

Defaults enforce a **short TTL** (300 seconds) and a **maximum duration cap** (3600 seconds). Expired rows are marked `expired`; administrators can **revoke** active credentials early.

## Policy & approval integration

Issuance requires:

1. The agent appears in `registry/index.json` with a readable manifest.
2. The manifest declares the `credential.issue` capability and **every** requested scope in `permission_scopes`.
3. Policies evaluate an internal `ActionRequest` with capability `credential.issue` and `permission_scope` equal to the sorted, comma-joined requested scopes.
4. If the policy outcome is `require_approval`, an approval row is created (same deterministic approval id scheme as the execution gateway). Issuance proceeds only after approvals satisfy the configured rules.

## Audit trail

Sealed audit events (same append-only chain as the rest of the registry API) record:

- `credential.requested`
- `credential.issued`
- `credential.denied`
- `credential.revoked`
- `credential.expired`

Approval lifecycle events (`approval.*`) still emit when approvals are created or updated.

## API surface

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/credentials/request` | Evaluate policies & optionally mint a credential |
| `POST` | `/credentials/verify` | Validate a bearer token against stored hash & lifecycle |
| `POST` | `/credentials/{credential_id}/revoke` | Revoke an active credential |
| `GET` | `/credentials/` | List metadata rows (never includes raw tokens) |

RBAC permissions: `credentials.request`, `credentials.read`, `credentials.revoke`, `credentials.verify`.

## CLI

```bash
recklock-registry request-credential path/to/credential-request.yaml path/to/policies.yaml
recklock-registry revoke-credential CREDENTIAL_ID
recklock-registry verify-credential TOKEN
```

Flags mirror other DB-backed commands (`--root`, `--database-url`, `--seed/--no-seed`). `--actor` records who requested or revoked from the CLI.

## Future cloud integrations

This phase intentionally **does not** call AWS, GCP, or Azure. The same broker boundary can later exchange these opaque tokens for cloud-session credentials (STS, federation, workload identity) **after** policy & approval — keeping cloud issuance out of agent prompts & long-lived config.
