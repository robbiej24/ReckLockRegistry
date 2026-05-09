"""Typer CLI for ReckLock Registry."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from pydantic import ValidationError

from agenttrust.crypto import (
    generate_keypair,
    save_private_key,
    sign_manifest,
    verify_manifest,
)
from agenttrust.manifest import (
    format_validation_errors,
    validate_manifest,
    write_manifest_schema,
)
from agenttrust.audit import (
    DEFAULT_AUDIT_LOG_PATH,
    append_event,
    load_audit_event_yaml,
    verify_log_integrity,
)
from agenttrust.approvals import (
    approve_request as approval_signoff,
    create_approval_request,
    deny_request as deny_approval_record,
    deterministic_approval_id,
    load_approval_creation_yaml,
    load_approvals,
)
from agenttrust.policy import evaluate_action, load_action_request_yaml, load_policies_yaml
from agenttrust.constants import (
    DEFAULT_APPROVAL_LOG_PATH,
    DEFAULT_DISCOVERED_AGENTS_DIR,
    DEFAULT_EVIDENCE_DIR,
    DEFAULT_INDEX_PATH,
)
from agenttrust.gateway import (
    execute_request,
    load_execution_request_yaml,
    load_registry_index,
)
from agenttrust.discovery.evidence import build_evidence_report, write_evidence_reports
from agenttrust.discovery.manifest_generator import compute_agent_id, write_manifest_draft
from agenttrust.discovery.models import DiscoveredAgentCandidate
from agenttrust.discovery.scanner import scan_repository
from agenttrust.registry import build_index
from agenttrust.scanner.cli import (
    import_scan_manifests as import_scan_manifests_fn,
    report_to_json as scanner_report_to_json,
    run_scan as run_scanner,
    summarize_report_text as summarize_scanner_report,
)
from agenttrust.trust import (
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_TRUST_PROFILES_PATH,
    load_incident_yaml,
    load_trust_profiles,
    recalculate_all_profiles,
    record_incident,
)
from agenttrust.auth.service import create_api_key
from agenttrust.db.init_db import init_database
from agenttrust.db.session import create_engine_from_settings, effective_database_url
from agenttrust.api.settings import ApiSettings

app = typer.Typer(
    name="recklock-registry",
    help="ReckLock Registry — validate manifests and build the registry index.",
    no_args_is_help=True,
)


@app.command("validate")
def validate_cmd(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Path to manifest.yaml"),
) -> None:
    """Validate a single manifest file."""
    try:
        validate_manifest(path)
    except (ValidationError, ValueError) as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(f"OK: {path}")


@app.command("build-index")
def build_index_cmd(
    agents_dir: Path | None = typer.Option(
        None,
        "--agents-dir",
        help="Directory containing YAML manifests (default: registry/agents)",
    ),
    index_out: Path | None = typer.Option(
        None,
        "--index-out",
        help="Output path for index.json (default: registry/index.json)",
    ),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Repository root for relative manifest_path entries (default: cwd)",
    ),
) -> None:
    """Validate all manifests under the agents directory and write registry/index.json."""
    try:
        idx = build_index(
            agents_dir=agents_dir,
            index_path=index_out,
            root=root,
        )
    except (ValidationError, ValueError) as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(
        f"Wrote index: {idx.agent_count} agent(s), registry_version={idx.registry_version}"
    )


@app.command("export-schema")
def export_schema_cmd(
    out: Path = typer.Option(
        Path("schemas/agent_manifest.schema.json"),
        "--out",
        help="Output path for the JSON Schema file",
    ),
) -> None:
    """Write the AgentManifest JSON Schema (generated from the Pydantic model)."""
    try:
        write_manifest_schema(out)
    except OSError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(f"Wrote schema: {out}")


@app.command("keygen")
def keygen_cmd(
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="Path to write the new Ed25519 private key seed (32 bytes)",
    ),
    key_id: str = typer.Option(
        "default",
        "--key-id",
        help="Human-readable id for this key (use the same value with ``recklock-registry sign``)",
    ),
) -> None:
    """Generate an Ed25519 keypair and write the private seed to disk."""
    sk = generate_keypair()
    try:
        save_private_key(private_key, sk)
    except OSError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(f"Wrote Ed25519 private key seed to {private_key}")
    typer.echo(f"When signing manifests, pass --key-id {key_id!r}.")


@app.command("sign")
def sign_cmd(
    manifest: Path = typer.Argument(..., exists=True, readable=True, help="Manifest YAML path"),
    key: Path = typer.Option(
        ...,
        "--key",
        exists=True,
        readable=True,
        help="Path to the Ed25519 private key seed file",
    ),
    key_id: str = typer.Option(
        ...,
        "--key-id",
        help="Key id (must match the id used when distributing the verify key)",
    ),
) -> None:
    """Sign a manifest using canonical JSON (excluding any existing signature block)."""
    try:
        sign_manifest(manifest, key, key_id)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(f"Signed {manifest}")


@app.command("execute-request")
def execute_request_cmd(
    request_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML file describing the execution request (Phase 2C gateway)",
    ),
    policies_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML policies file (same format as evaluate-policy)",
    ),
    index_path: Path = typer.Option(
        DEFAULT_INDEX_PATH,
        "--index",
        help="Path to registry/index.json",
    ),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Repository root for resolving manifest paths (default: cwd)",
    ),
    log_path: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--log",
        help="Append-only audit log for sealed gateway events",
    ),
    approvals_log: Path = typer.Option(
        Path(DEFAULT_APPROVAL_LOG_PATH),
        "--approvals-log",
        help="JSONL store for approval lifecycle rows (Phase 2D)",
    ),
) -> None:
    """Load the registry, evaluate an execution request, append audit, print JSON response."""
    cwd = Path(root or ".").resolve()
    idx_path = Path(index_path)
    if not idx_path.is_absolute():
        idx_path = cwd / idx_path
    try:
        index = load_registry_index(idx_path)
        req = load_execution_request_yaml(request_yaml)
        policies = load_policies_yaml(policies_yaml)
        outcome = execute_request(
            req,
            policies,
            index,
            registry_root=cwd,
            approval_log_path=approvals_log,
        )
        sealed = append_event(outcome.audit_event, log_path=log_path)
        last_hash = sealed.event_hash
        for approval_ev in outcome.approval_audit_events:
            sealed_ap = append_event(approval_ev, log_path=log_path)
            last_hash = sealed_ap.event_hash
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    payload = outcome.response.model_dump(mode="json")
    payload["appended_audit_event_hash"] = last_hash
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("create-approval")
def create_approval_cmd(
    yaml_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML describing request_id, agent_id, requested_action, approvers",
    ),
    approvals_log: Path = typer.Option(
        Path(DEFAULT_APPROVAL_LOG_PATH),
        "--approvals-log",
        help="JSONL store for approval lifecycle rows",
    ),
    audit_log: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--audit-log",
        help="Append-only audit log for sealed approval events",
    ),
) -> None:
    """Create a pending approval row from YAML (offline workflow bootstrap)."""
    try:
        doc = load_approval_creation_yaml(yaml_path)
        cap = str(doc.requested_action.get("capability", ""))
        scope = str(doc.requested_action.get("permission_scope", ""))
        aid = deterministic_approval_id(
            request_id=doc.request_id,
            agent_id=doc.agent_id,
            capability=cap,
            permission_scope=scope,
        )
        rec, audit = create_approval_request(
            approval_id=aid,
            request_id=doc.request_id,
            agent_id=doc.agent_id,
            requested_action=dict(doc.requested_action),
            required_approvers=list(doc.required_approvers),
            min_distinct_approvers=doc.min_distinct_approvers,
            expires_at=doc.expires_at,
            metadata=doc.metadata,
            log_path=approvals_log,
        )
        sealed = append_event(audit, log_path=audit_log)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(
        json.dumps(
            {
                "approval_id": rec.approval_id,
                "status": rec.status,
                "appended_audit_event_hash": sealed.event_hash,
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("approve-request")
def approve_request_cmd(
    approval_id: str = typer.Argument(..., help="Approval id (apr_…)"),
    approver: str = typer.Option(
        ...,
        "--approver",
        help="Approver identity recorded on the approval row",
    ),
    approvals_log: Path = typer.Option(
        Path(DEFAULT_APPROVAL_LOG_PATH),
        "--approvals-log",
        help="JSONL approval store",
    ),
    audit_log: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--audit-log",
        help="Append-only audit log for sealed approval events",
    ),
) -> None:
    """Record an approval sign-off (writes audit events for each transition)."""
    try:
        rec, events = approval_signoff(approval_id, approver, log_path=approvals_log)
        last_hash = ""
        for ev in events:
            sealed = append_event(ev, log_path=audit_log)
            last_hash = sealed.event_hash or ""
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(
        json.dumps(
            {
                "approval_id": rec.approval_id,
                "status": rec.status,
                "approved_by": rec.approved_by,
                "appended_audit_event_hash": last_hash,
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("deny-request")
def deny_request_cmd(
    approval_id: str = typer.Argument(..., help="Approval id (apr_…)"),
    approver: str = typer.Option(
        ...,
        "--approver",
        help="Human identity denying the request",
    ),
    approvals_log: Path = typer.Option(
        Path(DEFAULT_APPROVAL_LOG_PATH),
        "--approvals-log",
        help="JSONL approval store",
    ),
    audit_log: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--audit-log",
        help="Append-only audit log for sealed denial events",
    ),
) -> None:
    """Finalize an approval as denied."""
    try:
        rec, audit = deny_approval_record(approval_id, approver, log_path=approvals_log)
        sealed = append_event(audit, log_path=audit_log)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(
        json.dumps(
            {
                "approval_id": rec.approval_id,
                "status": rec.status,
                "appended_audit_event_hash": sealed.event_hash,
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("list-approvals")
def list_approvals_cmd(
    approvals_log: Path = typer.Option(
        Path(DEFAULT_APPROVAL_LOG_PATH),
        "--approvals-log",
        help="JSONL approval store",
    ),
) -> None:
    """Print all approval rows (last snapshot per id)."""
    try:
        rows = load_approvals(approvals_log)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    payload = [r.model_dump(mode="json") for r in sorted(rows.values(), key=lambda r: r.approval_id)]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("evaluate-policy")
def evaluate_policy_cmd(
    request_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML file describing the action request",
    ),
    policies_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML file containing one policy, a list of policies, or a mapping with key policies",
    ),
) -> None:
    """Evaluate an action request against policy rules and print a JSON decision."""
    try:
        request = load_action_request_yaml(request_yaml)
        policies = load_policies_yaml(policies_yaml)
        decision = evaluate_action(request, policies)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    payload = decision.model_dump(mode="json")
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("append-audit-event")
def append_audit_event_cmd(
    event_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML file describing the audit event (hashes optional)",
    ),
    log_path: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--log",
        help="Append-only audit log (newline-delimited JSON)",
    ),
) -> None:
    """Append one audit event with chained hashing to the local NDJSON log."""
    try:
        ev = load_audit_event_yaml(event_yaml)
        sealed = append_event(ev, log_path=log_path)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(f"Appended event_id={sealed.event_id} event_hash={sealed.event_hash}")


@app.command("verify-audit-log")
def verify_audit_log_cmd(
    log_path: Path = typer.Option(
        DEFAULT_AUDIT_LOG_PATH,
        "--log",
        help="Audit log file to verify",
    ),
) -> None:
    """Verify hash continuity and per-event digests for an audit log."""
    ok, msg = verify_log_integrity(log_path)
    if ok:
        typer.echo(msg)
        return
    typer.secho(msg, fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


@app.command("calculate-trust")
def calculate_trust_cmd(
    profiles_path: Path = typer.Option(
        DEFAULT_TRUST_PROFILES_PATH,
        "--profiles",
        help="JSONL path for trust profile snapshots",
    ),
    incidents_path: Path = typer.Option(
        DEFAULT_INCIDENTS_PATH,
        "--incidents",
        help="JSONL append-only incident log",
    ),
) -> None:
    """Recompute scores for every agent row using counters plus the incident log."""
    try:
        updated = recalculate_all_profiles(
            profiles_path=profiles_path,
            incidents_path=incidents_path,
        )
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    payload = {
        aid: prof.model_dump(mode="json")
        for aid, prof in sorted(updated.items(), key=lambda kv: kv[0])
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("list-trust-profiles")
def list_trust_profiles_cmd(
    profiles_path: Path = typer.Option(
        DEFAULT_TRUST_PROFILES_PATH,
        "--profiles",
        help="JSONL path for trust profile snapshots",
    ),
) -> None:
    """Print the latest trust profile per agent_id."""
    try:
        rows = load_trust_profiles(profiles_path)
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    payload = [r.model_dump(mode="json") for r in sorted(rows.values(), key=lambda r: r.agent_id)]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("record-incident")
def record_incident_cmd(
    yaml_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML describing agent_id, timestamp, incident_type, severity, description",
    ),
    profiles_path: Path = typer.Option(
        DEFAULT_TRUST_PROFILES_PATH,
        "--profiles",
        help="JSONL path for trust profile snapshots",
    ),
    incidents_path: Path = typer.Option(
        DEFAULT_INCIDENTS_PATH,
        "--incidents",
        help="JSONL append-only incident log",
    ),
) -> None:
    """Append one incident and upsert the affected agent trust profile."""
    try:
        doc = load_incident_yaml(yaml_path)
        rec, profile = record_incident(
            doc,
            incidents_path=incidents_path,
            profiles_path=profiles_path,
        )
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(
        json.dumps(
            {
                "incident_id": rec.incident_id,
                "trust_profile": profile.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("create-api-key")
def create_api_key_cmd(
    name: str = typer.Option(..., "--name", help="Human-readable label stored with the key record"),
    role: str = typer.Option(
        ...,
        "--role",
        help="Role: admin | auditor | approver | operator | developer | read_only",
    ),
    expires_at: str | None = typer.Option(
        None,
        "--expires-at",
        help="Optional expiry as ISO-8601 UTC (e.g. 2027-01-01T00:00:00Z)",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        help="SQLAlchemy URL (defaults to DATABASE_URL / AGENTTRUST_DATABASE_URL / configured SQLite)",
    ),
    seed: bool = typer.Option(
        True,
        "--seed/--no-seed",
        help="Apply optional db/seed.sql when it contains executable statements.",
    ),
) -> None:
    """Create an API key row (stores hash only) & print the raw bearer secret once."""
    from datetime import datetime, timezone

    def _parse_expiry(text: str | None) -> datetime | None:
        if text is None or text.strip() == "":
            return None
        s = text.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    settings = ApiSettings()
    url = database_url or effective_database_url(settings)
    init_database(url, run_seed=seed)
    exp = _parse_expiry(expires_at)
    eng = create_engine_from_settings(ApiSettings(database_url=url))
    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(bind=eng, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        raw, rec = create_api_key(session, name=name, role=role, expires_at=exp)
        session.commit()
    typer.secho("API key created. Save this value — it will not be shown again:", fg=typer.colors.YELLOW, err=True)
    typer.echo(raw)
    typer.echo(f"key_id={rec.key_id} role={rec.role}")


@app.command("list-connectors")
def list_connectors_cmd() -> None:
    """Print registered connector descriptors as JSON."""
    import json

    from agenttrust.connectors.registry import list_connector_descriptors

    typer.echo(json.dumps(list_connector_descriptors(), indent=2, sort_keys=True))


@app.command("connector-dry-run")
def connector_dry_run_cmd(
    yaml_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML mapping with connector_id, action, agent_id, capability, permission_scope, config",
    ),
) -> None:
    """Validate a connector invocation without calling external systems (dry-run)."""
    import json

    import yaml

    from agenttrust.connectors.invoke import ConnectorHttpError, run_connector
    from agenttrust.connectors.schemas import ConnectorInvokeBody

    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        typer.secho("YAML must be a mapping at the top level.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    try:
        body = ConnectorInvokeBody.model_validate(raw)
        out = run_connector(body, dry_run=True)
    except ConnectorHttpError as exc:
        typer.secho(exc.detail, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(out.model_dump(mode="json"), indent=2, sort_keys=True))


@app.command("request-credential")
def request_credential_cmd(
    yaml_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="YAML describing agent_id, requested_scopes, resource, environment, duration_seconds, …",
    ),
    policies_yaml: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Policies YAML (same formats as evaluate-policy)",
    ),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Repository root for registry resolution (default: cwd)",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        help="SQLAlchemy URL (defaults to DATABASE_URL / AGENTTRUST_DATABASE_URL / configured SQLite)",
    ),
    actor: str = typer.Option(
        "cli",
        "--actor",
        help="Recorded issuer identity for audit & issued_by",
    ),
    seed: bool = typer.Option(
        True,
        "--seed/--no-seed",
        help="Apply optional db/seed.sql when initializing the database file.",
    ),
) -> None:
    """Request a temporary credential via the broker (prints JSON; raw token only in this output)."""
    from sqlalchemy.orm import sessionmaker

    from agenttrust.api.settings import resolve_paths
    from agenttrust.credentials.broker import issue_credential
    from agenttrust.credentials.models import load_credential_request_yaml
    from agenttrust.gateway import load_registry_index
    from agenttrust.policy import load_policies_yaml

    cwd = Path(root or ".").resolve()
    settings = ApiSettings(registry_root=cwd)
    url = database_url or effective_database_url(settings)
    init_database(url, run_seed=seed)
    db_settings = ApiSettings(registry_root=cwd, database_url=url)
    paths = resolve_paths(db_settings)
    engine = create_engine_from_settings(db_settings)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    try:
        cred_req = load_credential_request_yaml(yaml_path)
        policies = load_policies_yaml(policies_yaml)
        index = load_registry_index(paths.index_path)
        with SessionLocal() as session:
            result = issue_credential(
                session,
                cred_req,
                policies,
                registry_root=paths.registry_root,
                registry_index=index,
                issued_by=actor,
            )
            session.commit()
    except (OSError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    except ValidationError as e:
        typer.secho(format_validation_errors(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


@app.command("revoke-credential")
def revoke_credential_cmd(
    credential_id: str = typer.Argument(..., help="cred_… id"),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Repository root (default: cwd)",
    ),
    database_url: str | None = typer.Option(None, "--database-url"),
    actor: str = typer.Option("cli", "--actor", help="Human identity recorded on the audit row"),
    seed: bool = typer.Option(True, "--seed/--no-seed"),
) -> None:
    """Revoke an active temporary credential."""
    from sqlalchemy.orm import sessionmaker

    from agenttrust.credentials.broker import revoke_credential

    cwd = Path(root or ".").resolve()
    settings = ApiSettings(registry_root=cwd)
    url = database_url or effective_database_url(settings)
    init_database(url, run_seed=seed)
    db_settings = ApiSettings(registry_root=cwd, database_url=url)
    engine = create_engine_from_settings(db_settings)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    try:
        with SessionLocal() as session:
            revoke_credential(session, credential_id, actor_id=actor)
            session.commit()
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo(json.dumps({"credential_id": credential_id, "status": "revoked"}, indent=2, sort_keys=True))


@app.command("verify-credential")
def verify_credential_cmd(
    token: str = typer.Argument(..., help="Raw bearer token returned at issuance"),
    root: Path | None = typer.Option(None, "--root", help="Repository root (default: cwd)"),
    database_url: str | None = typer.Option(None, "--database-url"),
    seed: bool = typer.Option(True, "--seed/--no-seed"),
) -> None:
    """Verify a temporary credential token against stored hash & TTL."""
    from sqlalchemy.orm import sessionmaker

    from agenttrust.credentials.broker import verify_credential

    cwd = Path(root or ".").resolve()
    settings = ApiSettings(registry_root=cwd)
    url = database_url or effective_database_url(settings)
    init_database(url, run_seed=seed)
    db_settings = ApiSettings(registry_root=cwd, database_url=url)
    engine = create_engine_from_settings(db_settings)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        out = verify_credential(session, token)
        session.commit()
    typer.echo(json.dumps(out.model_dump(mode="json"), indent=2, sort_keys=True))


@app.command("init-db")
def init_db_cmd(
    seed: bool = typer.Option(
        True,
        "--seed/--no-seed",
        help="Apply optional db/seed.sql when it contains executable statements.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        help="SQLAlchemy URL (defaults to DATABASE_URL / AGENTTRUST_DATABASE_URL / configured SQLite).",
    ),
) -> None:
    """Apply db/schema.sql idempotently (safe to run repeatedly)."""
    settings = ApiSettings()
    url = database_url or effective_database_url(settings)
    init_database(url, run_seed=seed)
    typer.echo(f"Database schema ensured for {url!r}")


@app.command("serve")
def serve_cmd(
    host: str | None = typer.Option(
        None,
        "--host",
        help="Bind address (default: AGENTTRUST_API_HOST or 127.0.0.1)",
    ),
    port: int | None = typer.Option(
        None,
        "--port",
        help="TCP port (default: AGENTTRUST_API_PORT or 8080)",
    ),
    registry_root: Path | None = typer.Option(
        None,
        "--registry-root",
        help="Working directory for registry files (default: current directory)",
    ),
) -> None:
    """Run the ReckLock Registry REST API & bundled dashboard."""
    import uvicorn

    from agenttrust.api.app import create_app
    from agenttrust.api.settings import ApiSettings

    if registry_root is not None:
        settings = ApiSettings(registry_root=registry_root.resolve())
    else:
        settings = ApiSettings()
    bind_host = settings.api_host if host is None else host
    bind_port = settings.api_port if port is None else port
    app_instance = create_app(settings)
    uvicorn.run(app_instance, host=bind_host, port=bind_port)


@app.command("verify")
def verify_cmd(
    manifest: Path = typer.Argument(..., exists=True, readable=True, help="Manifest YAML path"),
) -> None:
    """Verify manifest signature against embedded Ed25519 public keys."""
    ok, msg = verify_manifest(manifest)
    if ok:
        typer.echo(msg)
        return
    typer.secho(msg, fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


@app.command("discover-agents")
def discover_agents_cmd(
    repo_root: Path | None = typer.Option(
        None,
        "--repo-root",
        help="Repository root to scan (defaults to --registry-root)",
    ),
    registry_root: Path = typer.Option(
        Path("."),
        "--registry-root",
        help="Working directory for evidence output paths",
    ),
) -> None:
    """Scan a repository for automation signals & write evidence/discovered_agents.json."""
    root = registry_root.resolve()
    scan_base = repo_root.resolve() if repo_root is not None else root
    candidates = scan_repository(scan_base)
    evidence_dir = root / DEFAULT_EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / "discovered_agents.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(scan_base),
        "registry_root": str(root),
        "candidate_count": len(candidates),
        "candidates": [c.model_dump(mode="json") for c in candidates],
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    typer.echo(f"Wrote {out_path} ({len(candidates)} candidate(s))")
    for c in candidates[:50]:
        typer.echo(f"- {c.candidate_id} [{c.candidate_type}] {c.source_path} risk={c.risk_level_guess}")
    if len(candidates) > 50:
        typer.echo(f"... ({len(candidates) - 50} more)")


@app.command("register-discovered-agents")
def register_discovered_agents_cmd(
    registry_root: Path = typer.Option(Path("."), "--registry-root"),
    report_path: Path | None = typer.Option(
        None,
        "--from-report",
        help="Path to evidence/discovered_agents.json (default: <registry-root>/evidence/discovered_agents.json)",
    ),
    discovered_dir: Path | None = typer.Option(
        None,
        "--discovered-dir",
        help="Directory for generated manifests (default: <registry-root>/registry/discovered)",
    ),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing manifest drafts"),
    build_index_after: bool = typer.Option(
        True,
        "--build-index/--no-build-index",
        help="Rebuild registry/index.json after writing manifests",
    ),
) -> None:
    """Generate manifest drafts into registry/discovered/ and refresh the registry index."""
    root = registry_root.resolve()
    src = report_path or (root / DEFAULT_EVIDENCE_DIR / "discovered_agents.json")
    if not src.is_file():
        typer.secho(f"Discovery report not found: {src}", fg=typer.colors.RED, err=True)
        typer.secho("Run ``recklock-registry discover-agents`` first.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    raw = json.loads(src.read_text(encoding="utf-8"))
    items = raw["candidates"] if isinstance(raw, dict) and "candidates" in raw else raw
    if not isinstance(items, list):
        typer.secho("Invalid discovery report: expected candidates list.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    out_dir = discovered_dir or (root / DEFAULT_DISCOVERED_AGENTS_DIR)
    if not out_dir.is_absolute():
        out_dir = root / out_dir

    written = 0
    skipped = 0
    for row in items:
        cand = DiscoveredAgentCandidate.model_validate(row)
        aid = compute_agent_id(cand.source_path)
        dest = out_dir / f"{aid}.yaml"
        if dest.exists() and not overwrite:
            skipped += 1
            continue
        if write_manifest_draft(cand, dest, overwrite=overwrite):
            written += 1

    typer.echo(f"Manifest drafts written: {written} skipped(existing): {skipped} dir={out_dir}")

    if build_index_after:
        try:
            idx = build_index(root=root)
        except Exception as e:  # noqa: BLE001
            typer.secho(str(e), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from e
        typer.echo(f"Registry index rebuilt: {idx.agent_count} agent(s)")


@app.command("inventory-internal-agents")
def inventory_internal_agents_cmd(
    repo_root: Path | None = typer.Option(None, "--repo-root"),
    registry_root: Path = typer.Option(Path("."), "--registry-root"),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Run discovery, register drafts, print risk summary (Phase 4A pilot)."""
    root = registry_root.resolve()
    scan_base = repo_root.resolve() if repo_root is not None else root
    candidates = scan_repository(scan_base)
    evidence_dir = root / DEFAULT_EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report_path = evidence_dir / "discovered_agents.json"
    report_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "repo_root": str(scan_base),
                "registry_root": str(root),
                "candidate_count": len(candidates),
                "candidates": [c.model_dump(mode="json") for c in candidates],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    out_dir = root / DEFAULT_DISCOVERED_AGENTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for cand in candidates:
        dest = out_dir / f"{compute_agent_id(cand.source_path)}.yaml"
        if dest.exists() and not overwrite:
            continue
        if write_manifest_draft(cand, dest, overwrite=overwrite):
            written += 1

    try:
        idx = build_index(root=root)
    except Exception as e:  # noqa: BLE001
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    high = [c for c in candidates if c.risk_level_guess == "high"]
    critical = [c for c in candidates if c.risk_level_guess == "critical"]
    review = [
        c
        for c in candidates
        if c.confidence == "low" or c.candidate_type == "unknown" or (c.notes or "") != ""
    ]

    typer.echo(json.dumps({
        "candidates_found": len(candidates),
        "manifests_written_this_run": written,
        "registry_agent_count": idx.agent_count,
        "high_risk_count": len(high),
        "critical_risk_count": len(critical),
        "manual_review_queue": len(review),
    }, indent=2, sort_keys=True))


@app.command("evidence-report")
def evidence_report_cmd(
    days: int = typer.Option(7, "--days", min=1, max=366),
    registry_root: Path = typer.Option(Path("."), "--registry-root"),
) -> None:
    """Aggregate passive telemetry into JSON & Markdown evidence reports."""
    root = registry_root.resolve()
    ev_dir = root / DEFAULT_EVIDENCE_DIR
    events_path = ev_dir / "observation_events.jsonl"
    report = build_evidence_report(days=days, events_path=events_path)
    json_path, md_path = write_evidence_reports(report, evidence_dir=ev_dir)
    typer.echo(f"Wrote {json_path}")
    typer.echo(f"Wrote {md_path}")


@app.command("scan-repo")
def scan_repo_cmd(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository path to scan",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        help="Directory for scan reports (default: current working directory)",
    ),
    export_manifests: bool = typer.Option(
        False,
        "--export-manifests",
        help="Generate unsigned ReckLock Registry manifest drafts for register/govern/manual_review findings",
    ),
    manifest_dir: Path | None = typer.Option(
        None,
        "--manifest-dir",
        help="Directory for exported manifests (default: <output-dir>/recklock_manifest_exports)",
    ),
    min_confidence: str | None = typer.Option(
        None,
        "--min-confidence",
        help="Filter findings below this confidence (low | medium | high)",
    ),
    include: str | None = typer.Option(
        None,
        "--include",
        help='Comma-separated include globs, e.g. "*.py,*.ts,.github/workflows/*.yml"',
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help='Comma-separated extra excludes (dir names or globs), e.g. "node_modules,dist,*.min.js"',
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help='Terminal output format: "human" (default) or "json"',
    ),
) -> None:
    """Scan a repo for AI agents, automation, schedules, deploys & sensitive workflows."""
    if min_confidence is not None and min_confidence not in {"low", "medium", "high"}:
        typer.secho(
            f"Invalid --min-confidence: {min_confidence!r}. Use low | medium | high.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if output_format not in {"human", "json"}:
        typer.secho(
            f"Invalid --format: {output_format!r}. Use human or json.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        report, json_path, md_path, manifest_export_dir, manifest_results = run_scanner(
            path=path,
            output_dir=output_dir,
            include=include,
            exclude=exclude,
            min_confidence=min_confidence,  # type: ignore[arg-type]
            export_manifests_flag=export_manifests,
            manifest_export_dir=manifest_dir,
        )
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    if output_format == "json":
        typer.echo(scanner_report_to_json(report))
        return

    typer.echo(summarize_scanner_report(report))
    typer.echo(f"  json_report:   {json_path}")
    typer.echo(f"  md_report:     {md_path}")
    if manifest_export_dir is not None:
        written = sum(1 for _, w, _ in manifest_results if w)
        skipped = sum(1 for _, w, _ in manifest_results if not w)
        typer.echo(f"  manifests_written: {written} (skipped existing: {skipped})")
        typer.echo(f"  manifest_dir:  {manifest_export_dir}")


@app.command("import-scan-manifests")
def import_scan_manifests_cmd(
    export_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Path to a directory of scanner-generated manifest YAMLs",
    ),
    registry_root: Path = typer.Option(
        Path("."),
        "--registry-root",
        help="Working directory for the registry (default: current directory)",
    ),
    discovered_dir: Path | None = typer.Option(
        None,
        "--discovered-dir",
        help="Override registry/discovered destination directory",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing manifests in registry/discovered",
    ),
    build_index_after: bool = typer.Option(
        True,
        "--build-index/--no-build-index",
        help="Rebuild registry/index.json after copying manifests",
    ),
) -> None:
    """Validate exported scanner manifests and copy them into registry/discovered."""
    try:
        summary = import_scan_manifests_fn(
            export_dir=export_dir,
            registry_root=registry_root,
            discovered_dir=discovered_dir,
            overwrite=overwrite,
            rebuild_index=build_index_after,
        )
    except (NotADirectoryError, OSError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(json.dumps(summary, indent=2, sort_keys=True))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
