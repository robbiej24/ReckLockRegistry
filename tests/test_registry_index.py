"""Tests for registry index generation."""

import json
from pathlib import Path

from recklock.registry import build_index


def test_build_index_creates_index_with_one_agent(tmp_path: Path, example_manifest: Path) -> None:
    agents = tmp_path / "registry" / "agents"
    agents.mkdir(parents=True)
    dest = agents / "example-agent.yaml"
    dest.write_text(example_manifest.read_text(encoding="utf-8"), encoding="utf-8")
    index_path = tmp_path / "registry" / "index.json"

    idx = build_index(
        agents_dir=agents,
        index_path=index_path,
        root=tmp_path,
    )

    assert idx.agent_count == 1
    assert len(idx.agents) == 1
    assert idx.agents[0].agent_id == "agt_example-demo_a1b2c3d4"
    assert idx.agents[0].manifest_path == "registry/agents/example-agent.yaml"
    assert idx.agents[0].signature_verified is False

    data = json.loads(index_path.read_text(encoding="utf-8"))
    assert data["agent_count"] == 1
    assert len(data["agents"]) == 1
    assert data["agents"][0]["manifest_path"] == "registry/agents/example-agent.yaml"
    assert data["agents"][0]["signature_verified"] is False


def test_build_index_merges_discovered_manifests(tmp_path: Path, example_manifest: Path) -> None:
    agents = tmp_path / "registry" / "agents"
    disc = tmp_path / "registry" / "discovered"
    agents.mkdir(parents=True)
    disc.mkdir(parents=True)
    (agents / "example-agent.yaml").write_text(
        example_manifest.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (disc / "agt_disc-only_feedface00.yaml").write_text(
        """
agent_id: agt_disc-only_feedface00
name: Discovered Only
version: "0.0.0-discovered"
developer:
  name: HealthyLineups Internal Pilot
description: Auto-discovered during internal pilot.
agent_type: other
model_providers:
  - unspecified
capabilities:
  - script_execution
permission_scopes:
  - workspace.execute
risk_level: low
requires_human_approval: false
metadata:
  created_at: "2099-01-01T00:00:00Z"
  updated_at: "2099-01-01T00:00:00Z"
  registry_version: "0.1.0"
  observation_mode: true
  governance_status: observed_only
  source_path: tools/extra.py
  discovered_at: "2099-01-01T00:00:00Z"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    index_path = tmp_path / "registry" / "index.json"
    idx = build_index(agents_dir=agents, index_path=index_path, root=tmp_path)
    assert idx.agent_count == 2
    ids = {a.agent_id for a in idx.agents}
    assert "agt_example-demo_a1b2c3d4" in ids
    assert "agt_disc-only_feedface00" in ids
