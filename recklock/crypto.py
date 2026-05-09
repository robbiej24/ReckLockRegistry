"""Ed25519 manifest signing and verification (PyNaCl)."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml
from nacl import signing
from nacl.exceptions import BadSignatureError
from pydantic import ValidationError

from recklock.manifest import (
    AgentManifest,
    ManifestSignature,
    PublicKeyEntry,
    canonicalize_manifest,
    load_manifest,
)


def generate_keypair() -> signing.SigningKey:
    """Generate a new Ed25519 signing key (32-byte seed)."""
    return signing.SigningKey.generate()


def save_private_key(path: str | Path, signing_key: signing.SigningKey) -> None:
    """Write the raw 32-byte signing seed to ``path`` (permissions 0o600 on POSIX)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(signing_key.encode())
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def load_private_key(path: str | Path) -> signing.SigningKey:
    """Load a signing key from a 32-byte seed file."""
    p = Path(path)
    seed = p.read_bytes()
    if len(seed) != 32:
        raise ValueError(f"private key file must contain exactly 32 bytes, got {len(seed)}")
    return signing.SigningKey(seed)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _merge_public_keys(
    manifest: AgentManifest,
    key_id: str,
    verify_key: signing.VerifyKey,
) -> list[PublicKeyEntry]:
    """Upsert ``key_id`` with Ed25519 material and return a stable sort order."""
    now = _utc_now_iso()
    pk_b64 = base64.standard_b64encode(bytes(verify_key)).decode("ascii")
    kept = [e for e in (manifest.public_keys or []) if e.key_id != key_id]
    kept.append(
        PublicKeyEntry(
            key_id=key_id,
            algorithm="Ed25519",
            public_key_base64=pk_b64,
            created_at=now,
            expires_at=None,
        )
    )
    kept.sort(key=lambda e: e.key_id)
    return kept


def _dump_manifest_yaml(path: Path, manifest: AgentManifest) -> None:
    data = manifest.model_dump(mode="json", exclude_none=True)
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=120,
    )
    path.write_text(text, encoding="utf-8")


def sign_manifest(
    manifest_path: str | Path,
    private_key_path: str | Path,
    key_id: str,
) -> AgentManifest:
    """
    Canonicalize manifest without signature, sign UTF-8 bytes, upsert ``public_keys``,
    write ``signature`` and save YAML.
    """
    mp = Path(manifest_path)
    sk = load_private_key(private_key_path)
    vk = sk.verify_key

    manifest = load_manifest(mp)
    merged_keys = _merge_public_keys(manifest, key_id, vk)
    payload = manifest.model_copy(update={"signature": None, "public_keys": merged_keys})

    canon = canonicalize_manifest(payload).encode("utf-8")
    signed_msg = sk.sign(canon)
    sig_b64 = base64.standard_b64encode(signed_msg.signature).decode("ascii")

    signed_manifest = payload.model_copy(
        update={
            "signature": ManifestSignature(
                signed_by_key_id=key_id,
                signature_base64=sig_b64,
                signed_at=_utc_now_iso(),
            ),
        }
    )
    _dump_manifest_yaml(mp, signed_manifest)
    return signed_manifest


def verify_manifest_model(manifest: AgentManifest) -> tuple[bool, str]:
    """
    Verify signature against canonical payload (signature excluded).

    Rules:
    - ``signature`` must be present.
    - ``signed_by_key_id`` must match a ``public_keys`` entry.
    - That entry's algorithm must be ``Ed25519``.
    - Signature bytes must validate over canonical JSON for the manifest without ``signature``.
    """
    if manifest.signature is None:
        return False, "verification failed: manifest has no signature block"

    if not manifest.public_keys:
        return False, "verification failed: manifest has no public_keys (cannot verify signature)"

    pk_entry = next(
        (p for p in manifest.public_keys if p.key_id == manifest.signature.signed_by_key_id),
        None,
    )
    if pk_entry is None:
        kid = manifest.signature.signed_by_key_id
        return False, (
            f"verification failed: no public_keys entry matches signed_by_key_id={kid!r}"
        )

    if pk_entry.algorithm != "Ed25519":
        return False, (
            "verification failed: public key algorithm must be Ed25519, "
            f"got {pk_entry.algorithm!r}"
        )

    try:
        vk_bytes = base64.standard_b64decode(pk_entry.public_key_base64)
        vk = signing.VerifyKey(vk_bytes)
    except Exception as exc:
        return False, f"verification failed: invalid Ed25519 public key data ({exc})"

    try:
        sig_bytes = base64.standard_b64decode(manifest.signature.signature_base64)
    except Exception as exc:
        return False, f"verification failed: invalid signature_base64 ({exc})"

    payload = manifest.model_copy(update={"signature": None})
    canon = canonicalize_manifest(payload).encode("utf-8")

    try:
        vk.verify(canon, sig_bytes)
    except BadSignatureError:
        return False, "verification failed: signature does not match canonical manifest payload"

    return True, "signature verified"


def verify_manifest(manifest_path: str | Path) -> tuple[bool, str]:
    """Load ``manifest_path`` and run :func:`verify_manifest_model`."""
    try:
        m = load_manifest(manifest_path)
    except (ValidationError, ValueError, OSError, yaml.YAMLError) as exc:
        return False, f"verification failed: cannot load manifest ({exc})"
    return verify_manifest_model(m)
