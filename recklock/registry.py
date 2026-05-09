"""Registry index generation from YAML manifests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from recklock.constants import (
    DEFAULT_AGENTS_DIR,
    DEFAULT_DISCOVERED_AGENTS_DIR,
    DEFAULT_INDEX_PATH,
    REGISTRY_INDEX_VERSION,
)
from recklock.crypto import verify_manifest_model
from recklock.manifest import AgentManifest, load_manifest


class IndexAgentEntry(BaseModel):
    """One agent summary row in the registry index."""

    agent_id: str
    name: str
    version: str
    developer: str = Field(..., description="developer.name")
    agent_type: str
    risk_level: str
    capabilities: list[str]
    permission_scopes: list[str]
    manifest_path: str
    signature_verified: bool


class RegistryIndex(BaseModel):
    """Written to registry/index.json."""

    registry_version: str
    generated_at: str
    agent_count: int
    agents: list[IndexAgentEntry]


def _repo_relative_manifest_path(manifest_path: Path, root: Path) -> str:
    try:
        return str(manifest_path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(manifest_path)


def scan_agents(agents_dir: str | Path) -> list[Path]:
    """Return sorted paths to *.yaml and *.yml under agents_dir."""
    base = Path(agents_dir)
    if not base.is_dir():
        return []
    paths: list[Path] = []
    for pattern in ("*.yaml", "*.yml"):
        paths.extend(sorted(base.glob(pattern)))
    return sorted(set(paths), key=lambda p: str(p).lower())


def validate_all_manifests(agents_dir: str | Path) -> list[tuple[Path, AgentManifest]]:
    """Load and validate every manifest under agents_dir."""
    results: list[tuple[Path, AgentManifest]] = []
    for path in scan_agents(agents_dir):
        m = load_manifest(path)
        results.append((path, m))
    return results


def validate_manifest_trees(
    *agents_dirs: str | Path,
    prefer_first_on_duplicate_id: bool = True,
) -> list[tuple[Path, AgentManifest]]:
    """
    Load manifests from multiple directories.

    When the same ``agent_id`` appears twice, the first directory wins
    (canonical ``registry/agents`` should be listed before ``registry/discovered``).
    """
    seen: set[str] = set()
    out: list[tuple[Path, AgentManifest]] = []
    for adir in agents_dirs:
        for path, m in validate_all_manifests(adir):
            if m.agent_id in seen:
                if prefer_first_on_duplicate_id:
                    continue
                raise ValueError(f"Duplicate agent_id {m.agent_id!r} in {path}")
            seen.add(m.agent_id)
            out.append((path, m))
    return out


def build_index(
    agents_dir: str | Path | None = None,
    index_path: str | Path | None = None,
    *,
    root: str | Path | None = None,
    discovered_dir: str | Path | None = None,
    include_discovered: bool = True,
) -> RegistryIndex:
    """
    Validate all YAML manifests under registry/agents and write registry/index.json.

    Paths default to registry/agents and registry/index.json relative to ``root``
    (defaults to current working directory).
    """
    cwd = Path(root or ".").resolve()
    adir = Path(agents_dir or DEFAULT_AGENTS_DIR)
    if not adir.is_absolute():
        adir = cwd / adir
    out = Path(index_path or DEFAULT_INDEX_PATH)
    if not out.is_absolute():
        out = cwd / out

    dirs: list[Path] = [adir]
    if include_discovered:
        disc = Path(discovered_dir or DEFAULT_DISCOVERED_AGENTS_DIR)
        if not disc.is_absolute():
            disc = cwd / disc
        if disc.is_dir():
            dirs.append(disc)

    validated = validate_manifest_trees(*dirs)
    agents: list[IndexAgentEntry] = []
    for manifest_path, m in validated:
        rel = _repo_relative_manifest_path(manifest_path, cwd)
        sig_ok, _ = verify_manifest_model(m)
        agents.append(
            IndexAgentEntry(
                agent_id=m.agent_id,
                name=m.name,
                version=m.version,
                developer=m.developer.name,
                agent_type=m.agent_type,
                risk_level=m.risk_level,
                capabilities=list(m.capabilities),
                permission_scopes=list(m.permission_scopes),
                manifest_path=rel.replace("\\", "/"),
                signature_verified=sig_ok,
            )
        )

    index = RegistryIndex(
        registry_version=REGISTRY_INDEX_VERSION,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        agent_count=len(agents),
        agents=sorted(agents, key=lambda a: a.agent_id),
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(index.model_dump(), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return index
