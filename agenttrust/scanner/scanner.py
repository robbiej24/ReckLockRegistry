"""Top-level repository walker for ReckLock Discover."""

from __future__ import annotations

import fnmatch
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from agenttrust.scanner.classifiers import classify_finding
from agenttrust.scanner.detectors import detect_signals_for_file
from agenttrust.scanner.models import (
    Confidence,
    ScannerFinding,
    ScannerReport,
    at_least_confidence,
)

DEFAULT_EXCLUDE_DIRS: tuple[str, ...] = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".ruff_cache",
    "coverage",
    "htmlcov",
    ".next",
    ".turbo",
    ".nuxt",
    ".idea",
    "vendor",
    "site-packages",
    ".eggs",
    "target",
)

SCAN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".sh",
        ".bash",
        ".zsh",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
    }
)

SPECIAL_FILENAMES: frozenset[str] = frozenset(
    {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
    }
)

MAX_FILE_BYTES = 1_048_576  # 1 MiB cap per file
MAX_FILES = 50_000


def _human_name_from_rel(rel: Path) -> str:
    stem = rel.stem.replace("_", " ").replace("-", " ").strip()
    if rel.name.lower() == "dockerfile":
        return f"Dockerfile ({rel.parent.as_posix() or '.'})"
    return stem.title() if stem else rel.as_posix()


def _finding_id_for_path(repo_root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(repo_root.resolve())
    digest = hashlib.sha256(str(rel).encode("utf-8")).hexdigest()[:12]
    return f"find_{digest}"


def _read_text_limited(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if not data:
        return ""
    if b"\x00" in data[: min(len(data), 8192)]:
        return None
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None


def _matches_any(patterns: tuple[str, ...] | None, candidate: str) -> bool:
    if not patterns:
        return False
    for pat in patterns:
        if fnmatch.fnmatch(candidate, pat) or fnmatch.fnmatch(os.path.basename(candidate), pat):
            return True
    return False


def _split_csv(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    parts = tuple(p.strip() for p in value.split(",") if p.strip())
    return parts or None


def _should_skip_dir(name: str, exclude_dirs: tuple[str, ...]) -> bool:
    if name in exclude_dirs:
        return True
    if name.endswith(".egg-info"):
        return True
    return False


def _is_scannable(rel_posix: str, lower_name: str) -> bool:
    if lower_name in SPECIAL_FILENAMES:
        return True
    if lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
        return True
    ext = os.path.splitext(lower_name)[1]
    if ext in SCAN_EXTENSIONS:
        return True
    if rel_posix.startswith(".github/workflows/") and lower_name.endswith((".yml", ".yaml")):
        return True
    return False


def _normalize_excludes(exclude: tuple[str, ...] | None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split user-supplied excludes into (dir-name set, glob list)."""
    if not exclude:
        return DEFAULT_EXCLUDE_DIRS, ()
    dir_names: list[str] = list(DEFAULT_EXCLUDE_DIRS)
    globs: list[str] = []
    for raw in exclude:
        e = raw.strip().rstrip("/")
        if not e:
            continue
        if any(ch in e for ch in "*?["):
            globs.append(e)
        else:
            dir_names.append(e)
    return tuple(dict.fromkeys(dir_names)), tuple(globs)


def scan_repository(
    repo_root: Path | str,
    *,
    include: tuple[str, ...] | str | None = None,
    exclude: tuple[str, ...] | str | None = None,
    min_confidence: Confidence | None = None,
) -> ScannerReport:
    """
    Walk *repo_root* and produce a deterministic ``ScannerReport``.

    The scanner reads files locally, runs heuristic detectors, redacts
    likely secrets in any quoted snippets, and never emits raw credentials.

    Parameters
    ----------
    repo_root:
        Filesystem path to scan.
    include:
        Optional glob list (tuple or comma-separated string). When set, only
        files whose path or basename matches at least one include glob are
        scanned. Filename-only matches (e.g. ``"*.py"``) work too.
    exclude:
        Optional list of additional directory names or globs to skip,
        merged with the default excludes (``node_modules``, ``.git``, etc.).
    min_confidence:
        Filter findings whose confidence is below this threshold.
    """
    if isinstance(include, str):
        include = _split_csv(include)
    if isinstance(exclude, str):
        exclude = _split_csv(exclude)

    root = Path(repo_root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    exclude_dirs, exclude_globs = _normalize_excludes(exclude)

    findings: list[ScannerFinding] = []
    files_scanned = 0
    files_matched = 0

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir_posix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")

        dirnames[:] = sorted(
            d
            for d in dirnames
            if not _should_skip_dir(d, exclude_dirs)
            and not _matches_any(exclude_globs, f"{rel_dir_posix}/{d}".lstrip("/"))
        )

        for fname in sorted(filenames):
            rel_path = (Path(rel_dir_posix) / fname).as_posix() if rel_dir_posix else fname
            lower = fname.lower()

            if not _is_scannable(rel_path, lower):
                continue
            if include and not (
                _matches_any(include, rel_path) or _matches_any(include, fname)
            ):
                continue
            if exclude_globs and _matches_any(exclude_globs, rel_path):
                continue

            files_scanned += 1
            if files_scanned > MAX_FILES:
                break

            full_path = Path(dirpath) / fname
            text = _read_text_limited(full_path)
            if text is None:
                continue

            signals = detect_signals_for_file(text, rel_path, lower)
            if not signals:
                continue

            files_matched += 1
            finding = classify_finding(
                finding_id=_finding_id_for_path(root, full_path),
                name=_human_name_from_rel(Path(rel_path)),
                path=rel_path,
                rel_posix=rel_path,
                lower_name=lower,
                signals=signals,
            )

            if min_confidence and not at_least_confidence(finding.confidence, min_confidence):
                continue

            findings.append(finding)

        if files_scanned > MAX_FILES:
            break

    findings.sort(key=lambda f: (f.path.lower(), f.finding_id))

    by_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    by_action: dict[str, int] = {}
    critical_findings: list[str] = []
    high_findings: list[str] = []
    governance_targets: list[str] = []
    registration_targets: list[str] = []
    for f in findings:
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
        by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1
        by_action[f.recommended_action] = by_action.get(f.recommended_action, 0) + 1
        if f.risk_level == "critical":
            critical_findings.append(f.finding_id)
        elif f.risk_level == "high":
            high_findings.append(f.finding_id)
        if f.recommended_action == "govern":
            governance_targets.append(f.finding_id)
        elif f.recommended_action == "register":
            registration_targets.append(f.finding_id)

    from agenttrust.scanner import SCANNER_VERSION

    report = ScannerReport(
        scanner_version=SCANNER_VERSION,
        scanned_path=str(root),
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        files_scanned=files_scanned,
        files_matched=files_matched,
        findings_count=len(findings),
        findings_by_type=dict(sorted(by_type.items())),
        findings_by_risk=dict(sorted(by_risk.items())),
        findings_by_action=dict(sorted(by_action.items())),
        critical_findings=critical_findings,
        high_findings=high_findings,
        recommended_governance_targets=governance_targets,
        recommended_registration_targets=registration_targets,
        findings=findings,
    )
    return report
