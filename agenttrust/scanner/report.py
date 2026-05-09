"""JSON & Markdown reporting for ReckLock Discover."""

from __future__ import annotations

import json
from pathlib import Path

from agenttrust.scanner.models import ScannerFinding, ScannerReport

DEFAULT_JSON_FILENAME = "recklock_discover_scan_report.json"
DEFAULT_MARKDOWN_FILENAME = "recklock_discover_scan_report.md"


def write_json_report(report: ScannerReport, out_path: Path) -> Path:
    """Write the report as pretty-printed JSON."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_path


def _md_header(report: ScannerReport) -> list[str]:
    lines = [
        "# ReckLock Discover Report",
        "",
        f"- Scanner version: `{report.scanner_version}`",
        f"- Scanned path: `{report.scanned_path}`",
        f"- Scanned at: `{report.scanned_at}`",
        f"- Files scanned: **{report.files_scanned}**",
        f"- Files with findings: **{report.files_matched}**",
        f"- Total findings: **{report.findings_count}**",
        "",
    ]
    return lines


def _md_summary_table(title: str, mapping: dict[str, int]) -> list[str]:
    if not mapping:
        return []
    lines = [f"## {title}", "", "| Bucket | Count |", "| --- | --- |"]
    for k in sorted(mapping):
        lines.append(f"| `{k}` | {mapping[k]} |")
    lines.append("")
    return lines


def _md_finding_block(f: ScannerFinding) -> list[str]:
    sig_lines: list[str] = []
    for s in f.signals:
        loc = f"line {s.line_number}" if s.line_number else "filename match"
        snip = s.redacted_snippet or ""
        snip_md = f" — `{snip}`" if snip else ""
        sig_lines.append(f"  - **{s.name}** ({s.category}, {loc}){snip_md}")

    return [
        f"### `{f.path}` — {f.name}",
        "",
        f"- finding_id: `{f.finding_id}`",
        f"- finding_type: `{f.finding_type}`",
        f"- risk_level: **{f.risk_level}**",
        f"- confidence: `{f.confidence}`",
        f"- recommended_action: **{f.recommended_action}**",
        f"- likely_capabilities: {', '.join(f'`{c}`' for c in f.likely_capabilities) or '—'}",
        f"- likely_permission_scopes: {', '.join(f'`{p}`' for p in f.likely_permission_scopes) or '—'}",
        f"- rationale: _{f.rationale}_",
        "- signals:",
        *sig_lines,
        "",
    ]


def _md_top_section(title: str, ids: list[str], findings: list[ScannerFinding], blurb: str) -> list[str]:
    if not ids:
        return [f"## {title}", "", f"_{blurb}_", "", "_None._", ""]
    by_id = {f.finding_id: f for f in findings}
    lines = [f"## {title}", "", f"_{blurb}_", ""]
    for fid in ids:
        f = by_id.get(fid)
        if not f:
            continue
        lines.append(
            f"- `{f.path}` — **{f.finding_type}** "
            f"({f.risk_level}, {f.confidence}) → action: `{f.recommended_action}`"
        )
    lines.append("")
    return lines


def render_markdown_report(report: ScannerReport) -> str:
    """Render a Markdown view of *report* suitable for GitHub display."""
    parts: list[str] = []
    parts.extend(_md_header(report))

    parts.extend(_md_summary_table("Findings by Type", report.findings_by_type))
    parts.extend(_md_summary_table("Findings by Risk", report.findings_by_risk))
    parts.extend(_md_summary_table("Findings by Recommended Action", report.findings_by_action))

    parts.extend(
        _md_top_section(
            "Top candidates to govern first",
            report.recommended_governance_targets,
            report.findings,
            "These are critical-risk findings the scanner recommends governing with strict approval & policy.",
        )
    )
    parts.extend(
        _md_top_section(
            "Top candidates to register with ReckLock Registry",
            report.recommended_registration_targets,
            report.findings,
            "These are high-risk findings the scanner recommends registering before governing.",
        )
    )

    parts.append("## All findings")
    parts.append("")
    if not report.findings:
        parts.append("_No automation, agents, or sensitive workflows were detected._")
        parts.append("")
    else:
        for f in report.findings:
            parts.extend(_md_finding_block(f))

    parts.append("---")
    parts.append("")
    parts.append(
        "_ReckLock Discover is a heuristic static analyzer. Findings are educated guesses, "
        "not absolute proof. Always review high-risk paths manually before acting._"
    )
    parts.append("")
    return "\n".join(parts)


def write_markdown_report(report: ScannerReport, out_path: Path) -> Path:
    """Write a Markdown view of *report*."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_markdown_report(report), encoding="utf-8")
    return out_path


def write_reports(
    report: ScannerReport,
    output_dir: Path,
    *,
    json_filename: str = DEFAULT_JSON_FILENAME,
    markdown_filename: str = DEFAULT_MARKDOWN_FILENAME,
) -> tuple[Path, Path]:
    """Write both JSON & Markdown reports into *output_dir*; return their paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_json_report(report, output_dir / json_filename)
    md_path = write_markdown_report(report, output_dir / markdown_filename)
    return json_path, md_path
