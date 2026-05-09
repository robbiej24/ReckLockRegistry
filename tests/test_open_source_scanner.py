"""End-to-end tests for the open-source ReckLock Discover."""

from __future__ import annotations

from pathlib import Path

import yaml

from recklock.scanner import scan_repository
from recklock.scanner.cli import import_scan_manifests, run_scan
from recklock.scanner.manifest_export import compute_agent_id


def test_scan_emits_report_for_simple_repo(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import openai\n"
        "from openai import OpenAI\n"
        "tool_calls = []\n"
        "client = OpenAI()\n",
        encoding="utf-8",
    )
    rpt = scan_repository(tmp_path)
    assert rpt.findings_count >= 1
    finding = rpt.findings[0]
    assert finding.path == "agent.py"
    assert finding.finding_type in {"ai_agent", "llm_tool"}
    assert finding.recommended_action in {"monitor", "register", "manual_review"}
    assert finding.likely_capabilities, "capabilities should be populated"
    assert finding.likely_permission_scopes, "scopes should be populated"


def test_scan_skips_default_excluded_directories(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.js").write_text(
        "require('openai'); require('@anthropic-ai/sdk');", encoding="utf-8"
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    (tmp_path / "tracked_agent.py").write_text("import openai\n", encoding="utf-8")
    rpt = scan_repository(tmp_path)
    assert rpt.findings_count == 1
    assert rpt.findings[0].path == "tracked_agent.py"


def test_scan_respects_user_exclude_patterns(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "agent.py").write_text("import openai\n", encoding="utf-8")
    (tmp_path / "vendor_libs").mkdir()
    (tmp_path / "vendor_libs" / "third_party.py").write_text("import openai\n", encoding="utf-8")

    rpt = scan_repository(tmp_path, exclude="vendor_libs")
    paths = {f.path for f in rpt.findings}
    assert "src/agent.py" in paths
    assert all("vendor_libs" not in p for p in paths)


def test_scan_respects_include_globs(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("import openai\n", encoding="utf-8")
    (tmp_path / "tool.ts").write_text("import OpenAI from 'openai'\n", encoding="utf-8")
    rpt = scan_repository(tmp_path, include="*.py")
    paths = [f.path for f in rpt.findings]
    assert paths == ["agent.py"]


def test_scan_min_confidence_filter(tmp_path: Path) -> None:
    (tmp_path / "weak.py").write_text("# nothing interesting\n", encoding="utf-8")
    (tmp_path / "strong.py").write_text(
        "import openai\nfrom anthropic import Anthropic\nimport langchain\nimport requests\n",
        encoding="utf-8",
    )
    rpt = scan_repository(tmp_path, min_confidence="medium")
    assert rpt.findings_count == 1
    assert rpt.findings[0].confidence in {"medium", "high"}


def test_scan_writes_json_and_markdown_reports(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("import openai\n", encoding="utf-8")
    out = tmp_path / "out"

    rpt, json_path, md_path, manifest_dir, manifest_results = run_scan(
        path=repo,
        output_dir=out,
        export_manifests_flag=False,
    )
    assert json_path.is_file()
    assert md_path.is_file()
    assert manifest_dir is None
    assert manifest_results == []

    payload = json_path.read_text(encoding="utf-8")
    assert "recklock-discover" in payload
    md = md_path.read_text(encoding="utf-8")
    assert md.startswith("# ReckLock Discover Report")
    assert "## All findings" in md


def test_scan_export_manifests_creates_valid_drafts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    deploy = repo / "deploy.sh"
    deploy.write_text(
        "#!/bin/bash\nkubectl apply -f manifest.yaml\nexport AWS_SECRET_ACCESS_KEY=verylongsecretvalue1234567890abcdef\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"

    rpt, _, _, manifest_dir, results = run_scan(
        path=repo,
        output_dir=out,
        export_manifests_flag=True,
    )
    assert manifest_dir is not None
    assert manifest_dir.is_dir()
    assert results, "expected manifest exports for deploy script"

    written = [p for p, ok, _ in results if ok]
    assert written
    text = written[0].read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert data["agent_id"].startswith("agt_")
    assert data["metadata"]["scanner_generated"] is True
    assert data["metadata"]["source_path"] == "deploy.sh"
    assert data["risk_level"] in {"high", "critical"}


def test_import_scan_manifests_copies_into_registry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ship.sh").write_text(
        "#!/bin/bash\nkubectl apply -f deploy.yaml\nexport API_KEY=topsecretvalue1234567890abcdef\n",
        encoding="utf-8",
    )

    out = tmp_path / "out"
    _, _, _, manifest_dir, _ = run_scan(
        path=repo,
        output_dir=out,
        export_manifests_flag=True,
    )
    assert manifest_dir is not None

    registry_root = tmp_path / "registry_root"
    (registry_root / "registry" / "agents").mkdir(parents=True)

    summary = import_scan_manifests(
        export_dir=manifest_dir,
        registry_root=registry_root,
        rebuild_index=True,
    )
    assert summary["validated"] >= 1
    assert summary["written"] >= 1
    discovered = registry_root / "registry" / "discovered"
    assert discovered.is_dir()
    assert any(discovered.glob("*.yaml"))
    assert summary["registry_agent_count"] >= 1

    redo = import_scan_manifests(
        export_dir=manifest_dir,
        registry_root=registry_root,
        rebuild_index=False,
    )
    assert redo["written"] == 0
    assert redo["skipped"], "should skip existing manifests when overwrite is False"

    redo_overwrite = import_scan_manifests(
        export_dir=manifest_dir,
        registry_root=registry_root,
        overwrite=True,
        rebuild_index=False,
    )
    assert redo_overwrite["written"] >= 1


def test_compute_agent_id_is_stable(tmp_path: Path) -> None:
    a = compute_agent_id("services/foo/bar.py")
    b = compute_agent_id("services/foo/bar.py")
    assert a == b
    assert a.startswith("agt_")
