"""Manifest export tests."""

from __future__ import annotations

from pathlib import Path

import yaml

from agenttrust.manifest import AgentManifest
from agenttrust.scanner import scan_repository
from agenttrust.scanner.manifest_export import (
    EXPORTABLE_ACTIONS,
    build_manifest_dict,
    compute_agent_id,
    export_manifests,
    validate_manifest_dict,
)


SCANNER_VERSION = "0.1.0-test"


def _scan_one(tmp_path: Path) -> Path:
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\nkubectl apply -f infra.yaml\nexport AWS_SECRET_ACCESS_KEY=longverysecretvalue1234567890\n",
        encoding="utf-8",
    )
    return tmp_path


def test_build_manifest_dict_validates_against_schema(tmp_path: Path) -> None:
    repo = _scan_one(tmp_path)
    rpt = scan_repository(repo)
    finding = next(f for f in rpt.findings if f.path == "deploy.sh")
    data = build_manifest_dict(finding, scanner_version=SCANNER_VERSION)
    AgentManifest.model_validate(data)
    assert data["agent_id"].startswith("agt_")
    assert data["metadata"]["scanner_generated"] is True
    assert data["metadata"]["scanner_version"] == SCANNER_VERSION
    assert data["metadata"]["source_path"] == "deploy.sh"
    assert data["developer"]["name"] == "Unknown"
    assert data["requires_human_approval"] is False


def test_export_manifests_only_emits_eligible_findings(tmp_path: Path) -> None:
    (tmp_path / "summary.py").write_text(
        "# read-only summary script\nprint('hello')\n",
        encoding="utf-8",
    )
    (tmp_path / "ship.sh").write_text(
        "#!/bin/bash\nkubectl apply -f deploy.yaml\nexport STRIPE_SECRET_KEY=longsecretvalueABCDEFG1234567\n",
        encoding="utf-8",
    )
    rpt = scan_repository(tmp_path)
    out_dir = tmp_path / "exports"
    results = export_manifests(rpt.findings, out_dir, scanner_version=SCANNER_VERSION)

    eligible = [f for f in rpt.findings if f.recommended_action in EXPORTABLE_ACTIONS]
    assert len(results) == len(eligible)
    for path, written, _ in results:
        assert path.exists()
        assert path.suffix == ".yaml"
        assert written


def test_exported_manifest_redacts_signal_snippets(tmp_path: Path) -> None:
    (tmp_path / "ship.sh").write_text(
        "#!/bin/bash\nkubectl apply -f infra.yaml\nexport API_KEY=averysecretvalue1234567890ABCDEF\n",
        encoding="utf-8",
    )
    rpt = scan_repository(tmp_path)
    out_dir = tmp_path / "exports"
    export_manifests(rpt.findings, out_dir, scanner_version=SCANNER_VERSION)

    for fp in out_dir.glob("*.yaml"):
        text = fp.read_text(encoding="utf-8")
        assert "averysecretvalue1234567890" not in text


def test_validate_manifest_dict_detects_invalid_payload() -> None:
    bad = {"agent_id": "not-a-valid-id", "name": "x"}
    try:
        validate_manifest_dict(bad)
    except Exception:
        return
    raise AssertionError("expected validation error for invalid manifest dict")


def test_compute_agent_id_changes_with_path() -> None:
    a = compute_agent_id("a/b/c.py")
    b = compute_agent_id("a/b/d.py")
    assert a != b
