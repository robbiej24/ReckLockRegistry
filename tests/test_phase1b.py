"""Phase 1B: canonical JSON and JSON Schema export."""

import json
from pathlib import Path

from agenttrust.manifest import (
    AgentManifest,
    canonicalize_manifest,
    load_manifest,
    write_manifest_schema,
)


def test_canonicalization_is_deterministic(example_manifest: Path) -> None:
    m1 = load_manifest(example_manifest)
    m2 = load_manifest(example_manifest)
    assert canonicalize_manifest(m1) == canonicalize_manifest(m2)


def test_canonicalization_excludes_signature(tmp_path: Path) -> None:
    unsigned = tmp_path / "unsigned.yaml"
    signed = tmp_path / "signed.yaml"
    base = """
agent_id: agt_canon-test_abcd1234
name: Canon Test
version: "1.0.0"
developer:
  name: Dev
description: "test"
agent_type: assistant
model_providers:
  - openai
capabilities:
  - cap
permission_scopes:
  - scope.a
risk_level: low
requires_human_approval: false
metadata:
  created_at: "2026-01-01T00:00:00Z"
  updated_at: "2026-01-02T00:00:00Z"
  registry_version: "0.1.0"
"""
    unsigned.write_text(base, encoding="utf-8")
    signed.write_text(
        base
        + """
signature:
  signed_by_key_id: key1
  signature_base64: aaa
  signed_at: "2026-01-03T00:00:00Z"
""",
        encoding="utf-8",
    )
    u = load_manifest(unsigned)
    s = load_manifest(signed)
    assert "signature" not in json.loads(canonicalize_manifest(s))
    assert canonicalize_manifest(u) == canonicalize_manifest(s)


def test_export_schema_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "schemas" / "agent_manifest.schema.json"
    write_manifest_schema(out)
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data.get("title") == "AgentManifest"
    assert "properties" in data
    props = data["properties"]
    assert "signature" in props and "public_keys" in props
