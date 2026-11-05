# ReckLock Registry — API authentication & RBAC (Phase 3C)

This service protects non-health HTTP endpoints with **Bearer API keys** & **scoped roles**. Raw secrets are **never** persisted; only a **SHA-256 hash** of the full token is stored.

## API key generation

Set `RECKLOCK_SECRET_KEY` before creating or verifying keys (used as the hashing pepper). There is no in-repo default.

Use the CLI against your configured database (same URL rules as `recklock-registry init-db`):

```bash
export RECKLOCK_SECRET_KEY='your-local-pepper'
recklock-registry create-api-key --name "Local Admin" --role admin
```

The command prints the **raw bearer token once**. Copy it to a password manager or secret store. The database row stores `key_id`, `key_hash`, `name`, `role`, timestamps, optional `expires_at`, & `disabled`.

Optional expiry:

```bash
recklock-registry create-api-key --name "Short-lived" --role operator --expires-at 2027-01-01T00:00:00Z
```

## HTTP usage

Send the token on every mutating & registry call:

```http
Authorization: Bearer <api_key>
```

Unauthenticated requests to protected routes receive **401**. Authenticated requests without permission receive **403**.

**Public (no key):** `GET /health` only.

## Roles & permissions

Fixed roles (stored as lowercase strings on each key):

| Role | Purpose |
|------|---------|
| `admin` | Full access to all registry & governance endpoints exposed by this API. |
| `auditor` | Read-only safety posture: agents, audit events, trust profiles. |
| `approver` | Approval workflow: list approvals, approve, deny. |
| `operator` | Run gateway execution, evaluate policies, read agents, append audit via API, recalculate trust scores. |
| `developer` | Register/update flows aligned with manifests in practice: read agents & evaluate policies (manifest validation via policy engine). |
| `read_only` | Read agents & public registry index data. |

Permission checks are explicit per route (examples):

| Endpoint | Permission |
|----------|------------|
| `GET /agents`, `GET /agents/{id}` | `agents.read` |
| `POST /policies/evaluate` | `policies.evaluate` |
| `POST /execution/request` | `execution.request` |
| `GET /audit/events` | `audit.read` |
| `POST /audit/events` | `audit.append` |
| `GET /approvals`, `POST .../approve`, `POST .../deny` | `approvals.read`, `approvals.approve`, `approvals.deny` |
| `GET /trust/profiles` | `trust.read` |
| `POST /trust/calculate` | `trust.calculate` |

`admin` implicitly grants every permission above.

## Limitations (current phase)

- **No SSO / interactive login** — only static API keys.
- **No OAuth / OIDC providers** — keys are issued via CLI & stored locally.
- **No multi-tenant billing or org hierarchy** — roles are flat scopes on each key.
- **Keys are revocable** via `disabled` or expiry in the database; there is no external IdP revoke webhook yet.
- Hashing uses **SHA-256** of the UTF-8 bearer string; rotate keys by issuing a new key & disabling the old row.

## Future SSO / OIDC path

A typical evolution keeps these RBAC permission names & maps OIDC claims or IdP group membership to the same internal permission checks: an OIDC middleware would resolve identity, then attach an effective principal equivalent to today’s `AuthenticatedPrincipal`, while API keys remain supported for automation & break-glass accounts.
