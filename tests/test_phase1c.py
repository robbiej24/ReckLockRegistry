"""Phase 1C: Ed25519 signing and verification."""

import json
from pathlib import Path

from agenttrust.crypto import (
    generate_keypair,
    load_private_key,
    save_private_key,
    sign_manifest,
    verify_manifest,
    verify_manifest_model,
)
from agenttrust.manifest import load_manifest
from agenttrust.registry import build_index


def _manifest_yaml(agent_slug: str) -> str:
    return f"""
agent_id: agt_{agent_slug}_abcd1234
name: Sign Test
version: "1.0.0"
developer:
  name: Dev
description: "sign test"
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


def test_keygen_creates_usable_key(tmp_path: Path) -> None:
    sk1 = generate_keypair()
    key_path = tmp_path / "private.key"
    save_private_key(key_path, sk1)
    sk2 = load_private_key(key_path)
    assert sk1.encode() == sk2.encode()


def test_signed_manifest_verifies(tmp_path: Path) -> None:
    manifest = tmp_path / "m.yaml"
    manifest.write_text(_manifest_yaml("sign-one"), encoding="utf-8")
    key_path = tmp_path / "k.key"
    save_private_key(key_path, generate_keypair())

    sign_manifest(manifest, key_path, "default")
    ok, msg = verify_manifest(manifest)
    assert ok is True
    assert "verified" in msg.lower()


def test_tampered_manifest_fails_verification(tmp_path: Path) -> None:
    manifest = tmp_path / "m.yaml"
    manifest.write_text(_manifest_yaml("tamper"), encoding="utf-8")
    key_path = tmp_path / "k.key"
    save_private_key(key_path, generate_keypair())
    sign_manifest(manifest, key_path, "default")

    text = manifest.read_text(encoding="utf-8")
    manifest.write_text(text.replace("Sign Test", "Evil Test"), encoding="utf-8")

    ok, msg = verify_manifest(manifest)
    assert ok is False
    assert "verification failed" in msg.lower()


def test_unsigned_manifest_verification_fails_clearly(tmp_path: Path) -> None:
    manifest = tmp_path / "m.yaml"
    manifest.write_text(_manifest_yaml("nosig"), encoding="utf-8")
    m = load_manifest(manifest)
    ok, msg = verify_manifest_model(m)
    assert ok is False
    assert "no signature" in msg.lower()


def test_build_index_marks_signature_verified(tmp_path: Path) -> None:
    agents = tmp_path / "registry" / "agents"
    agents.mkdir(parents=True)

    unsigned_path = agents / "unsigned.yaml"
    unsigned_path.write_text(_manifest_yaml("unsigned-row"), encoding="utf-8")

    signed_work = tmp_path / "signed-work.yaml"
    signed_work.write_text(_manifest_yaml("signed-row"), encoding="utf-8")
    key_path = tmp_path / "k.key"
    save_private_key(key_path, generate_keypair())
    sign_manifest(signed_work, key_path, "pair-key")

    signed_dest = agents / "signed.yaml"
    signed_dest.write_text(signed_work.read_text(encoding="utf-8"), encoding="utf-8")

    index_path = tmp_path / "registry" / "index.json"
    idx = build_index(agents_dir=agents, index_path=index_path, root=tmp_path)

    rows = {a.manifest_path: a for a in idx.agents}
    assert rows["registry/agents/unsigned.yaml"].signature_verified is False
    assert rows["registry/agents/signed.yaml"].signature_verified is True

    data = json.loads(index_path.read_text(encoding="utf-8"))
    dumped = {a["manifest_path"]: a["signature_verified"] for a in data["agents"]}
    assert dumped["registry/agents/unsigned.yaml"] is False
    assert dumped["registry/agents/signed.yaml"] is True
