# Trust scoring & incidents (Phase 2E)

## Why trust scoring matters

Operating AI agents next to sensitive workflows creates **decision risk**: policies can be misconfigured, approvals can be bypassed in emergencies, or verification can fail under pressure. A **trust score** is not a prediction of future behavior; it is a **transparent rollup of observable signals** so humans, auditors, and downstream systems can compare agents consistently.

## Relationship to insurance & compliance

Insurance underwriting & enterprise compliance both ask the same structural question: **what evidence exists that controls were applied, & what adverse events occurred?** Phase 2E stores **deterministic counters & incidents** locally so teams can:

- explain posture during reviews without invoking opaque models;
- correlate incidents with audit event identifiers where provided;
- evolve toward richer governance programs without rewriting the core schema.

This phase intentionally avoids integrations & databases so the contract stays portable & testable.

## Deterministic & explainable scoring

Scores are integers on **[0, 1000]** derived from fixed weights:

- **Baseline** starts at **750** (trusted band when no adverse signals exist).
- **Successful verified actions** add a **small capped bonus** (reward steady compliant execution).
- **Denials**, **failed verifications**, **policy violations**, **tamper signals**, & **approval-heavy workloads** reduce the score using explicit arithmetic (see `recklock/trust.py`).
- **Repeated policy violations** add **extra penalty** beyond the first violation.
- **Incidents** apply severity weights (**low → critical**) so executive incidents move scores sharply.

Every adjustment maps to **human-readable inputs**. There is **no randomness**, **no ML**, & **no hidden state** beyond what is stored in `trust_profiles.jsonl` & `incidents.jsonl`.

## Why opaque AI scoring should be avoided here

Black-box scores undermine audits: stakeholders cannot reconstruct *why* an agent was classified as elevated risk. Deterministic scoring supports **appeals**, **replay**, & **regression tests**. If machine learning is introduced later, it should sit **above** this layer as an optional overlay—not replace accountable bookkeeping.

## Future enterprise trust systems

Phase 2E is a **foundation**: richer reputation graphs, federation, & insurer-facing attestations can consume the same incident records & counter snapshots. Keeping storage local & typed lets teams swap backends later without changing scoring semantics.

## CLI quick reference

- `recklock-registry calculate-trust` — recompute every profile row using stored counters & the incident log.
- `recklock-registry list-trust-profiles` — print latest snapshot per `agent_id`.
- `recklock-registry record-incident path/to/incident.yaml` — append an incident & refresh the affected profile.

Default paths are `trust_data/trust_profiles.jsonl` & `trust_data/incidents.jsonl` (see `recklock.constants`).
