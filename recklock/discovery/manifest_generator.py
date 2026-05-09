"""Generate unsigned ReckLock Registry manifest drafts from discovery candidates."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from recklock.constants import MANIFEST_REGISTRY_VERSION
from recklock.discovery.models import DiscoveredAgentCandidate
from recklock.manifest import AgentManifest, AgentType

_SLUG_SAFE = re.compile(r"[^a-z0-9\-]+")


def _utc_now_meta() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify_for_agent_id(source_path: str) -> str:
    """Produce slug portion matching ``manifest.agent_id`` validation."""
    s = source_path.replace("\\", "/").lower()
    s = s.replace("/", "-").replace(".", "-")
    s = _SLUG_SAFE.sub("-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        s = "discovered"
    # Pattern expects agt_<slug>_<hex> where slug has lowercase letters, digits, hyphens
    return s[:56]


def short_hash(source_path: str) -> str:
    return hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:8]


def compute_agent_id(source_path: str) -> str:
    slug = slugify_for_agent_id(source_path)
    return f"agt_{slug}_{short_hash(source_path)}"


def candidate_to_agent_type(candidate: DiscoveredAgentCandidate) -> AgentType:
    m: dict[str, AgentType] = {
        "ai_agent": "workflow_agent",
        "coding_agent": "coding_agent",
        "outbound_agent": "other",
        "automation_agent": "workflow_agent",
        "deployment_workflow": "workflow_agent",
        "scheduled_job": "workflow_agent",
        "ci_cd_workflow": "workflow_agent",
        "script": "other",
        "unknown": "other",
    }
    return m.get(candidate.candidate_type, "other")


def infer_model_providers(signals: list[str]) -> list[str]:
    providers: list[str] = []
    blob = " ".join(signals).lower()
    if "openai" in blob:
        providers.append("openai")
    if "anthropic" in blob:
        providers.append("anthropic")
    if "gemini" in blob or "generative" in blob:
        providers.append("google")
    if not providers:
        providers.append("unspecified")
    return sorted(set(providers))


def build_manifest_dict(candidate: DiscoveredAgentCandidate, *, discovered_at_iso: str | None = None) -> dict[str, Any]:
    """Build a YAML-serializable manifest mapping."""
    aid = compute_agent_id(candidate.source_path)
    now = _utc_now_meta()
    discovered_at = discovered_at_iso or now
    agent_type = candidate_to_agent_type(candidate)
    providers = infer_model_providers(candidate.detected_signals)

    description = (
        "Auto-discovered automation path during the HealthyLineups internal ReckLock Registry pilot "
        f"(Phase 4A). Source file: {candidate.source_path}. "
        "This manifest is observation-only and does not imply approval or production enrollment."
    )

    meta = {
        "created_at": now,
        "updated_at": now,
        "registry_version": MANIFEST_REGISTRY_VERSION,
        "observation_mode": True,
        "governance_status": "observed_only",
        "source_path": candidate.source_path,
        "discovered_at": discovered_at,
    }

    return {
        "agent_id": aid,
        "name": candidate.name[:120],
        "version": "0.0.0-discovered",
        "developer": {"name": "HealthyLineups Internal Pilot"},
        "description": description,
        "agent_type": agent_type,
        "model_providers": providers,
        "capabilities": list(candidate.likely_capabilities) or ["unknown_automation"],
        "permission_scopes": list(candidate.likely_permission_scopes) or ["workspace.observe"],
        "risk_level": candidate.risk_level_guess,
        "requires_human_approval": False,
        "metadata": meta,
        "discovery": {
            "candidate_id": candidate.candidate_id,
            "candidate_type": candidate.candidate_type,
            "detected_signals": candidate.detected_signals,
            "confidence": candidate.confidence,
            "notes": candidate.notes,
        },
    }


def validate_generated_manifest(data: dict[str, Any]) -> AgentManifest:
    """Ensure generated drafts satisfy ``AgentManifest``."""
    return AgentManifest.model_validate(data)


def write_manifest_draft(
    candidate: DiscoveredAgentCandidate,
    out_path: Path,
    *,
    overwrite: bool = False,
    discovered_at_iso: str | None = None,
) -> bool:
    """Write YAML manifest. Returns True when a new file was written or overwritten."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not overwrite:
        return False

    data = build_manifest_dict(candidate, discovered_at_iso=discovered_at_iso)
    validate_generated_manifest(data)
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    out_path.write_text(text, encoding="utf-8")
    return True
