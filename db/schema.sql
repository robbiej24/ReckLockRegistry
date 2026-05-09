-- ReckLock Registry — portable DDL (PostgreSQL & SQLite).
-- JSON payloads stored as TEXT for cross-dialect compatibility.
-- Timestamps stored as ISO-8601 TEXT (UTC).

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  record_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  policy_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  permission_scope TEXT,
  decision TEXT NOT NULL,
  policy_ids TEXT,
  metadata TEXT,
  previous_event_hash TEXT,
  event_hash TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events (created_at);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_action TEXT NOT NULL,
  required_approvers TEXT NOT NULL,
  min_distinct_approvers INTEGER NOT NULL,
  approved_by TEXT NOT NULL,
  expires_at TEXT,
  metadata TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals (agent_id);

CREATE TABLE IF NOT EXISTS trust_profiles (
  agent_id TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT NOT NULL,
  related_event_ids TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents (agent_id);

CREATE TABLE IF NOT EXISTS execution_requests (
  request_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_responses (
  request_id TEXT PRIMARY KEY,
  response_json TEXT NOT NULL,
  evaluated_at TEXT NOT NULL,
  audit_event_ids TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (request_id) REFERENCES execution_requests (request_id)
);

-- API authentication (Phase 3C). Raw keys are never stored; only key_hash.
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  disabled INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys (key_hash);

-- Phase 3E: temporary credential broker (raw tokens never stored; token_hash only).
CREATE TABLE IF NOT EXISTS temporary_credentials (
  credential_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  environment TEXT NOT NULL,
  issued_by TEXT NOT NULL,
  status TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  metadata TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_temp_cred_agent ON temporary_credentials (agent_id);
CREATE INDEX IF NOT EXISTS idx_temp_cred_expires ON temporary_credentials (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_temp_cred_token_hash ON temporary_credentials (token_hash);
