"""CLI coverage for scan-repo registry opt-in behavior."""

from __future__ import annotations

from pathlib import Path

from recklock.scanner.cli import import_scan_manifests, registry_opt_in_prompt, run_scan


def _repo_with_registry_candidate(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "deploy.sh").write_text(
        "#!/bin/bash\nkubectl apply -f infra.yaml\nexport AWS_SECRET_ACCESS_KEY=longverysecretvalue1234567890\n",
        encoding="utf-8",
    )
    return repo


def test_registry_opt_in_prompt_uses_adoption_friendly_copy() -> None:
    assert registry_opt_in_prompt(6) == (
        "ReckLock Discover found 6 AI agents. Add them to your ReckLock Registry so you can display:\n\n"
        "- That you own them\n"
        "- What their capabilities are\n"
        "- Which risks they carry &\n"
        "- Allow other people who want to license your agents to contact you?"
    )


def test_scan_repo_add_to_registry_imports_discovered_manifests(tmp_path: Path) -> None:
    repo = _repo_with_registry_candidate(tmp_path)
    out_dir = tmp_path / "reports"
    registry_root = tmp_path / "registry-root"

    _, _, _, manifest_export_dir, manifest_results = run_scan(
        repo,
        output_dir=out_dir,
        export_manifests_flag=True,
    )
    assert manifest_export_dir is not None
    import_summary = import_scan_manifests(
        export_dir=manifest_export_dir,
        registry_root=registry_root,
        rebuild_index=True,
    )

    assert any(written for _, written, _ in manifest_results)
    assert list((out_dir / "recklock_manifest_exports").glob("*.yaml"))
    assert list((registry_root / "registry" / "discovered").glob("*.yaml"))
    assert (registry_root / "registry" / "index.json").exists()
    assert import_summary["written"] > 0


def test_scan_repo_skip_registry_leaves_registry_untouched(tmp_path: Path) -> None:
    repo = _repo_with_registry_candidate(tmp_path)
    out_dir = tmp_path / "reports"
    registry_root = tmp_path / "registry-root"

    _, _, _, manifest_export_dir, manifest_results = run_scan(
        repo,
        output_dir=out_dir,
        export_manifests_flag=False,
    )

    assert manifest_export_dir is None
    assert manifest_results == []
    assert not (registry_root / "registry" / "discovered").exists()
