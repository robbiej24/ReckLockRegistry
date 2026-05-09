"""CLI helpers for ReckLock Discover.

The actual ``typer`` commands live in ``recklock.cli`` so the scanner shares
the existing ``recklock-registry`` entrypoint. This module provides the thin glue
functions those commands call so they remain unit-testable.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from recklock.constants import DEFAULT_DISCOVERED_AGENTS_DIR
from recklock.manifest import AgentManifest
from recklock.scanner import SCANNER_VERSION
from recklock.scanner.manifest_export import (
    DEFAULT_EXPORT_DIRNAME,
    EXPORTABLE_ACTIONS,
    export_manifests,
)
from recklock.scanner.models import Confidence, ScannerReport
from recklock.scanner.report import (
    DEFAULT_JSON_FILENAME,
    DEFAULT_MARKDOWN_FILENAME,
    write_reports,
)
from recklock.scanner.scanner import scan_repository


def run_scan(
    path: Path,
    *,
    output_dir: Path | None = None,
    include: str | None = None,
    exclude: str | None = None,
    min_confidence: Confidence | None = None,
    export_manifests_flag: bool = False,
    manifest_export_dir: Path | None = None,
) -> tuple[ScannerReport, Path, Path, Path | None, list[tuple[Path, bool, str]]]:
    """
    Run a scan & write reports.

    Returns ``(report, json_path, md_path, manifest_dir or None, manifest_results)``.
    """
    report = scan_repository(
        path,
        include=include,
        exclude=exclude,
        min_confidence=min_confidence,
    )
    out_dir = (output_dir or Path.cwd()).resolve()
    json_path, md_path = write_reports(
        report,
        out_dir,
        json_filename=DEFAULT_JSON_FILENAME,
        markdown_filename=DEFAULT_MARKDOWN_FILENAME,
    )

    manifest_dir: Path | None = None
    manifest_results: list[tuple[Path, bool, str]] = []
    if export_manifests_flag:
        manifest_dir = (manifest_export_dir or (out_dir / DEFAULT_EXPORT_DIRNAME)).resolve()
        manifest_results = export_manifests(
            report.findings,
            manifest_dir,
            scanner_version=SCANNER_VERSION,
            actions=EXPORTABLE_ACTIONS,
        )
    return report, json_path, md_path, manifest_dir, manifest_results


def summarize_report_text(report: ScannerReport) -> str:
    """Compact human-readable summary printed to the terminal after a scan."""
    lines = [
        f"ReckLock Discover v{report.scanner_version}",
        f"  scanned_path:  {report.scanned_path}",
        f"  scanned_at:    {report.scanned_at}",
        f"  files_scanned: {report.files_scanned}",
        f"  files_matched: {report.files_matched}",
        f"  findings:      {report.findings_count}",
    ]
    if report.findings_by_risk:
        lines.append("  by risk:")
        for k in ("critical", "high", "medium", "low"):
            if report.findings_by_risk.get(k):
                lines.append(f"    {k:>8}: {report.findings_by_risk[k]}")
    if report.findings_by_action:
        lines.append("  by recommended action:")
        for k in ("govern", "register", "manual_review", "monitor"):
            if report.findings_by_action.get(k):
                lines.append(f"    {k:>14}: {report.findings_by_action[k]}")
    if report.recommended_governance_targets:
        lines.append(f"  govern first: {len(report.recommended_governance_targets)} candidate(s)")
    if report.recommended_registration_targets:
        lines.append(
            f"  register next: {len(report.recommended_registration_targets)} candidate(s)"
        )
    return "\n".join(lines)


def report_to_json(report: ScannerReport) -> str:
    """Pretty JSON used by ``--format json``."""
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def import_scan_manifests(
    export_dir: Path,
    *,
    registry_root: Path,
    discovered_dir: Path | None = None,
    overwrite: bool = False,
    rebuild_index: bool = True,
) -> dict[str, Any]:
    """
    Validate exported manifests in *export_dir* and copy them into ``registry/discovered``.

    Returns a summary dict with counts (validated, written, skipped, invalid)
    and (when ``rebuild_index`` is True) the new agent count from the rebuilt
    registry index.
    """
    src = Path(export_dir).resolve()
    if not src.is_dir():
        raise NotADirectoryError(f"Manifest export directory not found: {src}")

    root = Path(registry_root).resolve()
    dest_dir = (discovered_dir or (root / DEFAULT_DISCOVERED_AGENTS_DIR)).resolve()
    if not dest_dir.is_absolute():
        dest_dir = root / dest_dir
    dest_dir.mkdir(parents=True, exist_ok=True)

    validated = 0
    written = 0
    skipped: list[str] = []
    invalid: list[dict[str, str]] = []
    written_files: list[str] = []

    for src_path in sorted(src.glob("*.yaml")) + sorted(src.glob("*.yml")):
        try:
            raw = yaml.safe_load(src_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("manifest must be a YAML mapping")
            AgentManifest.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            invalid.append({"path": str(src_path), "error": str(exc)})
            continue
        validated += 1

        dest_path = dest_dir / src_path.name
        if dest_path.exists() and not overwrite:
            skipped.append(str(dest_path))
            continue
        shutil.copyfile(src_path, dest_path)
        written += 1
        written_files.append(str(dest_path))

    summary: dict[str, Any] = {
        "export_dir": str(src),
        "discovered_dir": str(dest_dir),
        "validated": validated,
        "written": written,
        "skipped": skipped,
        "invalid": invalid,
        "written_files": written_files,
    }

    if rebuild_index:
        from recklock.registry import build_index

        idx = build_index(root=root)
        summary["registry_agent_count"] = idx.agent_count

    return summary
