"""Generate unsigned ReckLock Registry manifest drafts from ``ScannerFinding`` rows."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from agenttrust.constants import MANIFEST_REGISTRY_VERSION
from agenttrust.manifest import AgentManifest, AgentType
from agenttrust.scanner.models import FindingType, ScannerFinding

DEFAULT_EXPORT_DIRNAME = "recklock_manifest_exports"

EXPORTABLE_ACTIONS = frozenset({"register", "govern", "manual_review"})

_SLUG_SAFE = re.compile(r"[^a-z0-9\-]+")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slugify(source_path: str) -> str:
    s = source_path.replace("\\", "/").lower()
    s = s.replace("/", "-").replace(".", "-")
    s = _SLUG_SAFE.sub("-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        s = "scanned"
    return s[:56]


def _short_hash(source_path: str) -> str:
    return hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:8]


def compute_agent_id(source_path: str) -> str:
    """Return ``agt_<slug>_<shorthash>`` derived from a repo-relative path."""
    return f"agt_{_slugify(source_path)}_{_short_hash(source_path)}"


_FINDING_TO_AGENT_TYPE: dict[FindingType, AgentType] = {
    "ai_agent": "workflow_agent",
    "llm_tool": "assistant",
    "automation_agent": "workflow_agent",
    "outbound_agent": "other",
    "browser_agent": "workflow_agent",
    "scheduled_job": "workflow_agent",
    "ci_cd_workflow": "workflow_agent",
    "deployment_workflow": "workflow_agent",
    "database_writer": "workflow_agent",
    "payment_or_financial_workflow": "financial_agent",
    "secret_using_workflow": "workflow_agent",
    "shell_execution_workflow": "workflow_agent",
    "unknown": "other",
}


def _agent_type_for(finding_type: FindingType) -> AgentType:
    return _FINDING_TO_AGENT_TYPE.get(finding_type, "other")


def _infer_model_providers(finding: ScannerFinding) -> list[str]:
    providers: set[str] = set()
    blob = " ".join(s.name.lower() for s in finding.signals)
    if "openai" in blob:
        providers.add("openai")
    if "anthropic" in blob:
        providers.add("anthropic")
    if "google" in blob or "gemini" in blob or "generative" in blob:
        providers.add("google")
    if "ollama" in blob:
        providers.add("ollama")
    if "vertex" in blob:
        providers.add("google")
    if not providers:
        providers.add("unspecified")
    return sorted(providers)


def _description(finding: ScannerFinding, scanner_version: str) -> str:
    return (
        f"Auto-discovered by ReckLock Discover v{scanner_version} from `{finding.path}`. "
        f"This is an unsigned draft manifest — review and edit before signing or registering. "
        f"Detected as {finding.finding_type} with {finding.confidence} confidence at {finding.risk_level} risk."
    )


def build_manifest_dict(
    finding: ScannerFinding,
    *,
    scanner_version: str,
    developer_name: str = "Unknown",
) -> dict[str, Any]:
    """Build a YAML-serializable manifest mapping for one finding."""
    aid = compute_agent_id(finding.path)
    now = _utc_now()
    agent_type = _agent_type_for(finding.finding_type)
    providers = _infer_model_providers(finding)

    detected_signals = [
        {
            "name": s.name,
            "category": s.category,
            "line_number": s.line_number,
        }
        for s in finding.signals
    ]

    name = (finding.name or finding.path)[:120] or "Discovered Workflow"

    return {
        "agent_id": aid,
        "name": name,
        "version": "0.0.0-scanner",
        "developer": {"name": developer_name},
        "description": _description(finding, scanner_version),
        "agent_type": agent_type,
        "model_providers": providers,
        "capabilities": list(finding.likely_capabilities) or ["unknown_automation"],
        "permission_scopes": list(finding.likely_permission_scopes) or ["workspace.observe"],
        "risk_level": finding.risk_level,
        "requires_human_approval": False,
        "metadata": {
            "created_at": now,
            "updated_at": now,
            "registry_version": MANIFEST_REGISTRY_VERSION,
            "scanner_generated": True,
            "scanner_version": scanner_version,
            "source_path": finding.path,
            "detected_signals": detected_signals,
            "recommended_action": finding.recommended_action,
            "finding_type": finding.finding_type,
            "confidence": finding.confidence,
        },
    }


def validate_manifest_dict(data: dict[str, Any]) -> AgentManifest:
    """Validate a generated manifest dict against ``AgentManifest``."""
    return AgentManifest.model_validate(data)


def manifest_filename_for(finding: ScannerFinding) -> str:
    return f"{compute_agent_id(finding.path)}.yaml"


def write_manifest_for_finding(
    finding: ScannerFinding,
    out_dir: Path,
    *,
    scanner_version: str,
    overwrite: bool = False,
    developer_name: str = "Unknown",
) -> tuple[Path, bool]:
    """
    Write a single manifest YAML draft for *finding*.

    Returns (path, was_written). ``was_written`` is False when the file existed
    and ``overwrite`` was not set.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / manifest_filename_for(finding)
    if dest.exists() and not overwrite:
        return dest, False

    data = build_manifest_dict(finding, scanner_version=scanner_version, developer_name=developer_name)
    validate_manifest_dict(data)
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    dest.write_text(text, encoding="utf-8")
    return dest, True


def export_manifests(
    findings: list[ScannerFinding],
    out_dir: Path,
    *,
    scanner_version: str,
    overwrite: bool = False,
    developer_name: str = "Unknown",
    actions: frozenset[str] = EXPORTABLE_ACTIONS,
) -> list[tuple[Path, bool, str]]:
    """
    Export draft manifests for every finding whose recommended_action is exportable.

    Returns a list of ``(path, was_written, finding_id)`` tuples.
    """
    results: list[tuple[Path, bool, str]] = []
    for f in findings:
        if f.recommended_action not in actions:
            continue
        path, written = write_manifest_for_finding(
            f,
            out_dir,
            scanner_version=scanner_version,
            overwrite=overwrite,
            developer_name=developer_name,
        )
        results.append((path, written, f.finding_id))
    return results
