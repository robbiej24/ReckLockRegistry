"""Manifest draft generation tests."""

from __future__ import annotations

from pathlib import Path

from agenttrust.discovery.manifest_generator import (
    build_manifest_dict,
    compute_agent_id,
    write_manifest_draft,
)
from agenttrust.discovery.models import DiscoveredAgentCandidate


def test_creates_valid_manifest_dict() -> None:
    c = DiscoveredAgentCandidate(
        candidate_id="cand_x",
        name="Test Bot",
        source_path="scripts/demo_bot.py",
        candidate_type="ai_agent",
        detected_signals=["imports or calls OpenAI API"],
        likely_capabilities=["llm_inference"],
        likely_permission_scopes=["ai.invoke"],
        risk_level_guess="medium",
        confidence="high",
    )
    doc = build_manifest_dict(c)
    assert doc["agent_id"] == compute_agent_id(c.source_path)
    assert doc["requires_human_approval"] is False
    meta = doc["metadata"]
    assert meta["observation_mode"] is True
    assert meta["governance_status"] == "observed_only"
    assert meta["source_path"] == "scripts/demo_bot.py"


def test_does_not_overwrite_without_flag(tmp_path: Path) -> None:
    c = DiscoveredAgentCandidate(
        candidate_id="cand_y",
        name="X",
        source_path="a/b.py",
        detected_signals=["imports or calls OpenAI API"],
    )
    dest = tmp_path / f"{compute_agent_id(c.source_path)}.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("existing", encoding="utf-8")
    assert write_manifest_draft(c, dest, overwrite=False) is False
    assert dest.read_text(encoding="utf-8") == "existing"


def test_overwrite_writes_manifest(tmp_path: Path) -> None:
    c = DiscoveredAgentCandidate(
        candidate_id="cand_z",
        name="Y",
        source_path="c/d.py",
        detected_signals=["imports or calls OpenAI API"],
    )
    dest = tmp_path / f"{compute_agent_id(c.source_path)}.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("existing", encoding="utf-8")
    assert write_manifest_draft(c, dest, overwrite=True) is True
    txt = dest.read_text(encoding="utf-8")
    assert "observation_mode" in txt
