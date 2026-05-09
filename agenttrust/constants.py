"""Shared constants for ReckLock Registry."""

# Semantic version of the index file schema / tooling release line.
REGISTRY_INDEX_VERSION = "0.1.0"

# Expected value for metadata.registry_version in manifests (Phase 1A).
MANIFEST_REGISTRY_VERSION = "0.1.0"

DEFAULT_AGENTS_DIR = "registry/agents"
DEFAULT_DISCOVERED_AGENTS_DIR = "registry/discovered"
DEFAULT_INDEX_PATH = "registry/index.json"
DEFAULT_EVIDENCE_DIR = "evidence"
DEFAULT_APPROVAL_LOG_PATH = "approval_logs/approvals.jsonl"

# Phase 2E: local trust profiles & incidents (JSONL under trust_data/).
DEFAULT_TRUST_PROFILES_PATH = "trust_data/trust_profiles.jsonl"
DEFAULT_INCIDENTS_PATH = "trust_data/incidents.jsonl"
