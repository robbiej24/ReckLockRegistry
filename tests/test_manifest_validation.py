"""Tests for YAML manifest validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from recklock.manifest import load_manifest, validate_manifest


def test_valid_manifest_passes(example_manifest: Path) -> None:
    m = validate_manifest(example_manifest)
    assert m.agent_id == "agt_example-demo_a1b2c3d4"
    assert m.name == "Example Agent"
    assert m.developer.name == "Example Labs"
    assert m.metadata.registry_version == "0.1.0"


def test_load_manifest_equivalent(example_manifest: Path) -> None:
    assert load_manifest(example_manifest).agent_id == validate_manifest(example_manifest).agent_id


def test_invalid_manifest_fails_bad_agent_id(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
agent_id: INVALID-ID
name: X
version: "1"
developer:
  name: Dev
description: "d"
agent_type: assistant
model_providers: []
capabilities: []
permission_scopes: []
risk_level: low
requires_human_approval: true
metadata:
  created_at: "2026-01-01T00:00:00Z"
  updated_at: "2026-01-01T00:00:00Z"
  registry_version: "0.1.0"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        validate_manifest(bad)


def test_invalid_manifest_fails_missing_field(tmp_path: Path) -> None:
    bad = tmp_path / "incomplete.yaml"
    bad.write_text(
        """
agent_id: agt_x_abcd1234
name: X
version: "1"
developer:
  name: Dev
description: "d"
agent_type: assistant
model_providers: []
capabilities: []
permission_scopes: []
risk_level: low
requires_human_approval: true
metadata:
  created_at: "2026-01-01T00:00:00Z"
  updated_at: "2026-01-01T00:00:00Z"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        validate_manifest(bad)
