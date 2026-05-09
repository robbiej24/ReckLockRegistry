# Enterprise architecture

ReckLock Registry is designed for **self-hosted** operation: you choose where it runs, which registry hosts your container images, & how secrets & backups are governed. This document outlines a pragmatic enterprise posture without prescribing a single cloud vendor.

## Self-hosted deployment

Typical patterns:

- **Single-node Docker Compose** for pilots & labs (PostgreSQL colocated or managed elsewhere).
- **Kubernetes** using the bundled Helm chart as a starting point: adjust images, resources, Ingress, & storage classes to match your platform standards.
- **VM or systemd** deployments run `recklock-registry serve` under a dedicated service account with environment files injected by config management — same binaries & schema as containers.

Keep networking controls (firewalls, service mesh, private subnets) aligned with how agents & operators reach the API & UI.

## Private registry

Build the Dockerfile in your CI pipeline, push tags to **your** container registry (on-premises Harbor, ECR, GCR, ACR, GitHub Container Registry, etc.), & reference digests or immutable tags from Helm values. No upstream SaaS subscription is required to distribute the software artifact itself.

## Audit retention

Audit events land in the relational store & optional append-only logs depending on feature usage. Enterprises usually:

- Define retention windows per policy & jurisdiction.
- Export archives to object storage with immutability controls where required.
- Restrict read paths (`auditor` roles in ReckLock Registry & DB read replicas) so investigations do not broaden blast radius.

Future enhancements may add automated export streams; today you can scheduledump queries & ship NDJSON to long-term storage.

## Secrets management

Treat these as **secrets**, never as plain ConfigMaps in Git:

- `DATABASE_URL` & database credentials.
- Raw API keys shown once at issuance (operators must store them in a vault or password manager).
- Connector configuration tokens when real connectors are enabled (`AGENTTRUST_ENABLE_REAL_CONNECTORS=true`).

Mount secrets via Kubernetes Secrets, Docker secrets, systemd credentials, or your centralized vault with sidecar injection — ReckLock Registry reads standard environment variables.

## SSO future path

Today the UI authenticates via API keys (Bearer header or cookie after `/ui/sign-in`). A natural evolution is delegating interactive login to your IdP using OpenID Connect or SAML, then mapping IdP groups to ReckLock Registry roles. That integration would sit alongside API-key automation for agents & CI.

## SIEM future path

Structured audit logs & HTTP access logs can already be forwarded by your platform (Fluent Bit, Vector, Splunk Universal Forwarder, Datadog Agent, etc.). A deeper SIEM story would add normalized event schemas & signing hooks so SOC workflows can correlate ReckLock Registry decisions with upstream identity & infrastructure signals — design intentionally stays vendor-neutral.

## Compliance evidence future path

Organizations often need downloadable evidence packs (who approved what, when credentials were issued, policy versions in force). Today much of this is queryable via SQL & API; packaging signed PDF or CSV bundles, immutable timestamps, & workflow attestations is a logical extension without locking deployments to a specific compliance SaaS.
