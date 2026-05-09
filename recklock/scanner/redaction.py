"""Redaction helpers — keep secrets out of scan reports."""

from __future__ import annotations

import math
import re

REDACTED = "[REDACTED]"

_SECRET_KEY_NAMES = (
    r"API_?KEY",
    r"SECRET(?:_KEY)?",
    r"ACCESS_?TOKEN",
    r"AUTH_?TOKEN",
    r"PRIVATE_?KEY",
    r"PASSWORD",
    r"PASSWD",
    r"PASSPHRASE",
    r"BEARER",
    r"CLIENT_?SECRET",
    r"OPENAI_?API_?KEY",
    r"ANTHROPIC_?API_?KEY",
    r"STRIPE_?(?:SECRET|API)_?KEY",
    r"AWS_?SECRET_?ACCESS_?KEY",
    r"AWS_?ACCESS_?KEY_?ID",
    r"GITHUB_?TOKEN",
    r"GH_?TOKEN",
    r"DATABASE_?URL",
    r"DB_?URL",
    r"MONGO_?URL",
    r"REDIS_?URL",
    r"SLACK_?(?:BOT_)?TOKEN",
    r"DISCORD_?TOKEN",
    r"TWILIO_?(?:AUTH_)?TOKEN",
    r"PLAID_?(?:SECRET|TOKEN)",
)

_SECRET_NAME_GROUP = "(" + "|".join(_SECRET_KEY_NAMES) + ")"

_RE_ENV_ASSIGN = re.compile(
    rf"(?P<key>\b{_SECRET_NAME_GROUP}\b)\s*[:=]\s*(?P<val>.+?)(?=$|\s*[#;])",
    re.IGNORECASE,
)

_RE_DICT_KV = re.compile(
    rf"""(?P<quote>['"])\s*(?P<key>{_SECRET_NAME_GROUP})\s*['"]\s*[:=]\s*['"]?(?P<val>[^'",\s\}}\]]+)['"]?""",
    re.IGNORECASE | re.VERBOSE,
)

_RE_BEARER = re.compile(r"(?i)\b(Bearer)\s+([A-Za-z0-9_\-\.\=\+/]{8,})")

_RE_AUTH_HEADER = re.compile(
    r"""(?ix)(Authorization\s*[:=]\s*['"]?)([A-Za-z0-9_\-\.\=\+/\s]{8,})"""
)

_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
    re.DOTALL,
)

_RE_AWS_AKID = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")

_RE_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")

_RE_GITHUB_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{20,}\b|\bghs_[A-Za-z0-9]{20,}\b")

_RE_LONG_HEX = re.compile(r"\b[a-fA-F0-9]{40,}\b")

_RE_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_high_entropy(value: str, *, min_len: int = 24, min_entropy: float = 3.5) -> bool:
    """Heuristic: long strings with high Shannon entropy are likely secrets."""
    cleaned = value.strip().strip("'\"")
    if len(cleaned) < min_len:
        return False
    return _shannon_entropy(cleaned) >= min_entropy


def redact_line(line: str) -> str:
    """
    Return a single line with likely secrets replaced by ``[REDACTED]``.

    Targets: env-style assignments, dict literals, bearer/auth headers,
    common provider key formats, and long high-entropy strings.
    """
    if not line:
        return line
    out = line

    out = _RE_PRIVATE_KEY.sub(REDACTED, out)
    out = _RE_GITHUB_TOKEN.sub(REDACTED, out)
    out = _RE_OPENAI_KEY.sub(REDACTED, out)
    out = _RE_AWS_AKID.sub(REDACTED, out)
    out = _RE_BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _RE_AUTH_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", out)

    def _env_repl(m: re.Match[str]) -> str:
        return f"{m.group('key')}={REDACTED}"

    out = _RE_ENV_ASSIGN.sub(_env_repl, out)

    def _kv_repl(m: re.Match[str]) -> str:
        q = m.group("quote")
        return f'{q}{m.group("key")}{q}: {q}{REDACTED}{q}'

    out = _RE_DICT_KV.sub(_kv_repl, out)

    def _entropy_token(m: re.Match[str]) -> str:
        token = m.group(0)
        return REDACTED if _looks_high_entropy(token) else token

    out = _RE_LONG_HEX.sub(_entropy_token, out)
    out = _RE_LONG_B64.sub(_entropy_token, out)

    return out.rstrip()


def redact_text(text: str) -> str:
    """Redact every line in *text*."""
    return "\n".join(redact_line(line) for line in text.splitlines())


def redact_snippet(line: str, *, max_len: int = 240) -> str:
    """Produce a short, redacted preview of a line for reports."""
    redacted = redact_line(line)
    if len(redacted) <= max_len:
        return redacted
    return redacted[: max_len - 3] + "..."
