"""Repository scanner for candidate automation / agent paths."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from agenttrust.discovery.classifiers import classify_candidate
from agenttrust.discovery.models import DiscoveredAgentCandidate

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "coverage",
        "htmlcov",
        ".cursor",
        ".idea",
        "target",
        ".next",
        ".nuxt",
        "vendor",
        "site-packages",
        ".eggs",
        "*.egg-info",
    }
)

SCAN_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".sh", ".yml", ".yaml"})
SPECIAL_FILENAMES = frozenset(
    {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "cargo.toml",
        "makefile",
    }
)

MAX_FILE_BYTES = 512 * 1024

# --- Signal detection (readable labels for reports & classification) ---

_RE_IMPORT_OPENAI = re.compile(r"\b(import\s+openai|from\s+openai\b)", re.I)
_RE_IMPORT_ANTHROPIC = re.compile(r"\b(import\s+anthropic|from\s+anthropic\b)", re.I)
_RE_LANGCHAIN = re.compile(r"\blangchain\b|\blanggraph\b", re.I)
_RE_CREWAI = re.compile(r"\bcrewai\b", re.I)
_RE_AUTOGEN = re.compile(r"\b(autogen|pyautogen)\b", re.I)
_RE_GEMINI = re.compile(
    r"\b(google\.generativeai|google\.ai\.generativelanguage|generativeai)\b|\bgemini\b",
    re.I,
)
_RE_CURSOR = re.compile(r"\bcursor\b|\.cursor\b", re.I)
_RE_SLACK = re.compile(r"\bslack\b|slack_webhook|hooks\.slack\.com", re.I)
_RE_EMAIL = re.compile(r"\b(send_email|send_mail|smtplib|EmailMessage|MIMEText)\b", re.I)
_RE_SUBPROCESS = re.compile(r"\bsubprocess\b|os\.system\(|popen\(", re.I)
_RE_BOTO3 = re.compile(r"\bboto3\b|\bbotocore\b", re.I)
_RE_GITHUB_TOKEN = re.compile(r"GITHUB_TOKEN|GH_TOKEN|ACTIONS_RUNTIME_TOKEN", re.I)
_RE_DATABASE_URL = re.compile(r"DATABASE_URL|POSTGRES_|MYSQL_|SQLALCHEMY_DATABASE", re.I)
_RE_DB_WRITE = re.compile(
    r"\.(execute|commit)\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET|\.delete\(|session\.add\(",
    re.I,
)
_RE_STRIPE = re.compile(r"\bstripe\b|STRIPE_", re.I)
_RE_PAYMENT = re.compile(
    r"\b(payment|banking|kyc|wallet|pci\b|plaid|square\b|checkout\.Session)", re.I
)
_RE_DEPLOY = re.compile(
    r"\b(deploy|kubectl|helm\b|terraform\b|pulumi\b|aws\s+ecs|cloudformation)\b",
    re.I,
)
_RE_CRON = re.compile(
    r"(\bcron\b|schedule\b|crontab|APScheduler|celery\s+beat|\bon:\s*schedule\b)", re.I
)
_RE_GHA = re.compile(r"^(\s*)on:\s*$|\bactions/checkout\b|^\s*jobs:\s*$", re.I | re.M)
_RE_DOCKER = re.compile(r"\bFROM\s+\w|docker\s+build|docker-compose\b", re.I)
_RE_OPENAI_STRING = re.compile(r'openai\.|OpenAI\(|api\.openai\.com', re.I)
_RE_ANTHROPIC_STRING = re.compile(r'Anthropic\(|api\.anthropic\.com', re.I)


def _candidate_id_for_path(repo_root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(repo_root.resolve())
    digest = hashlib.sha256(str(rel).encode("utf-8")).hexdigest()[:12]
    return f"cand_{digest}"


def _read_text_limited(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _detect_signals(text: str, rel_posix: str, filename: str) -> list[str]:
    signals: list[str] = []
    lower_name = filename.lower()

    if rel_posix.startswith(".github/workflows/") and lower_name.endswith((".yml", ".yaml")):
        signals.append("GitHub Actions workflow")

    if _RE_IMPORT_OPENAI.search(text) or _RE_OPENAI_STRING.search(text):
        signals.append("imports or calls OpenAI API")
    if _RE_IMPORT_ANTHROPIC.search(text) or _RE_ANTHROPIC_STRING.search(text):
        signals.append("imports or calls Anthropic API")
    if _RE_LANGCHAIN.search(text):
        signals.append("uses LangChain")
    if _RE_CREWAI.search(text):
        signals.append("uses CrewAI")
    if _RE_AUTOGEN.search(text):
        signals.append("uses AutoGen")
    if _RE_GEMINI.search(text):
        signals.append("uses Google Gemini / Generative AI client")
    if _RE_CURSOR.search(text):
        signals.append("references Cursor IDE or agent automation")

    if _RE_EMAIL.search(text):
        signals.append("email send or SMTP usage")
    if _RE_SLACK.search(text):
        signals.append("Slack webhook or Slack API usage")
    if _RE_SUBPROCESS.search(text):
        signals.append("subprocess or shell invocation")
    if _RE_BOTO3.search(text):
        signals.append("uses boto3 (AWS)")
    if _RE_GITHUB_TOKEN.search(text):
        signals.append("references GitHub token env vars")
    if _RE_DATABASE_URL.search(text):
        signals.append("references database URL env vars")
    if _RE_DB_WRITE.search(text):
        signals.append("possible database write operations")
    if _RE_STRIPE.search(text):
        signals.append("references Stripe or STRIPE_ secrets")
    if _RE_PAYMENT.search(text):
        signals.append("financial / payment / wallet / KYC signals")
    if _RE_DEPLOY.search(text):
        signals.append("deployment or infrastructure tooling")
    if _RE_CRON.search(text):
        signals.append("cron-like schedule or background jobs")
    if _RE_DOCKER.search(text):
        signals.append("Docker build or compose usage")

    if lower_name == "dockerfile" or "docker-compose" in lower_name:
        signals.append("Docker deployment artifact")

    if lower_name in {"package.json", "pyproject.toml", "requirements.txt"}:
        deps_blob = text.lower()
        if any(k in deps_blob for k in ("openai", "anthropic", "langchain", "crewai", "autogen")):
            signals.append("dependency manifest lists AI SDKs")

    # YAML-specific CI
    if lower_name.endswith((".yml", ".yaml")) and _RE_GHA.search(text):
        if "GitHub Actions workflow" not in signals:
            signals.append("YAML resembles CI/CD workflow")

    # Dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _human_name_from_rel(rel: Path) -> str:
    stem = rel.stem.replace("_", " ").replace("-", " ")
    return stem.title() if stem else rel.as_posix()


def scan_repository(repo_root: Path | str) -> list[DiscoveredAgentCandidate]:
    """
    Walk *repo_root* and emit classified candidates for relevant files.

    This pass is heuristic and observation-only.
    """
    root = Path(repo_root).resolve()
    candidates: list[DiscoveredAgentCandidate] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIR_NAMES and not d.startswith(".pytest") and not d.startswith(".egg")
        ]
        for fname in filenames:
            path = Path(dirpath) / fname
            try:
                rel = path.resolve().relative_to(root)
            except ValueError:
                continue
            rel_posix = rel.as_posix()
            lower = fname.lower()

            ext = path.suffix.lower()
            is_special = lower in SPECIAL_FILENAMES or lower == "dockerfile"
            if ext not in SCAN_EXTENSIONS and not is_special:
                continue

            text = _read_text_limited(path)
            if text is None:
                continue

            signals = _detect_signals(text, rel_posix, lower)
            if not signals:
                continue

            cid = _candidate_id_for_path(root, path)
            name = _human_name_from_rel(rel)
            raw = DiscoveredAgentCandidate(
                candidate_id=cid,
                name=name,
                source_path=rel_posix,
                detected_signals=signals,
            )
            classified = classify_candidate(raw)
            notes_parts: list[str] = []
            if classified.confidence == "low":
                notes_parts.append("Low confidence — review manually.")
            if classified.candidate_type == "unknown":
                notes_parts.append("Unknown automation category — review manually.")
            classified.notes = "; ".join(notes_parts) if notes_parts else None
            candidates.append(classified)

    # Stable ordering for deterministic outputs
    candidates.sort(key=lambda c: (c.source_path.lower(), c.candidate_id))
    return candidates
