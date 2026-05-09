"""SQLAlchemy Core table definitions for ReckLock Registry persistence."""

from __future__ import annotations

from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, Text

metadata = MetaData()

agents = Table(
    "agents",
    metadata,
    Column("agent_id", Text, primary_key=True),
    Column("record_json", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

policies = Table(
    "policies",
    metadata,
    Column("policy_id", Text, primary_key=True),
    Column("policy_json", Text, nullable=False),
    Column("enabled", Integer, nullable=False, default=1),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("timestamp", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("actor_type", Text, nullable=False),
    Column("actor_id", Text, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("resource_type", Text, nullable=False),
    Column("resource_id", Text, nullable=False),
    Column("permission_scope", Text),
    Column("decision", Text, nullable=False),
    Column("policy_ids", Text),
    Column("metadata", Text),
    Column("previous_event_hash", Text),
    Column("event_hash", Text),
    Column("created_at", Text, nullable=False),
)

approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", Text, primary_key=True),
    Column("request_id", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("requested_action", Text, nullable=False),
    Column("required_approvers", Text, nullable=False),
    Column("min_distinct_approvers", Integer, nullable=False),
    Column("approved_by", Text, nullable=False),
    Column("expires_at", Text),
    Column("metadata", Text),
    Column("updated_at", Text, nullable=False),
)

trust_profiles = Table(
    "trust_profiles",
    metadata,
    Column("agent_id", Text, primary_key=True),
    Column("profile_json", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

incidents = Table(
    "incidents",
    metadata,
    Column("incident_id", Text, primary_key=True),
    Column("agent_id", Text, nullable=False),
    Column("timestamp", Text, nullable=False),
    Column("incident_type", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("description", Text, nullable=False),
    Column("related_event_ids", Text),
    Column("created_at", Text, nullable=False),
)

execution_requests = Table(
    "execution_requests",
    metadata,
    Column("request_id", Text, primary_key=True),
    Column("agent_id", Text, nullable=False),
    Column("request_json", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

execution_responses = Table(
    "execution_responses",
    metadata,
    Column("request_id", Text, ForeignKey("execution_requests.request_id"), primary_key=True),
    Column("response_json", Text, nullable=False),
    Column("evaluated_at", Text, nullable=False),
    Column("audit_event_ids", Text),
    Column("created_at", Text, nullable=False),
)

api_keys = Table(
    "api_keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column("key_hash", Text, nullable=False, unique=True),
    Column("name", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text),
    Column("disabled", Integer, nullable=False, default=0),
)

temporary_credentials = Table(
    "temporary_credentials",
    metadata,
    Column("credential_id", Text, primary_key=True),
    Column("agent_id", Text, nullable=False),
    Column("issued_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("scopes", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("environment", Text, nullable=False),
    Column("issued_by", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("token_hash", Text, nullable=False),
    Column("metadata", Text),
    Column("created_at", Text, nullable=False),
)
