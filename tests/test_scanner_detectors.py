"""Detector & redaction tests."""

from __future__ import annotations

from pathlib import Path

from agenttrust.scanner import scan_repository
from agenttrust.scanner.detectors import detect_signals_for_file
from agenttrust.scanner.redaction import redact_line, redact_snippet


def _signal_names(text: str, name: str = "x.py") -> list[str]:
    sigs = detect_signals_for_file(text, name, name)
    return [s.name for s in sigs]


def test_detects_openai_imports() -> None:
    names = _signal_names("import openai\nclient = openai.OpenAI()\n")
    assert "imports or calls OpenAI" in names


def test_detects_anthropic_imports() -> None:
    names = _signal_names(
        "from anthropic import Anthropic\nclient = Anthropic()\n"
    )
    assert "imports or calls Anthropic" in names


def test_detects_langchain() -> None:
    names = _signal_names("from langchain.chains import LLMChain\n")
    assert "uses LangChain / LangGraph" in names


def test_detects_github_actions_workflow_file() -> None:
    text = "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    sigs = detect_signals_for_file(
        text, ".github/workflows/ci.yml", "ci.yml"
    )
    names = [s.name for s in sigs]
    assert "GitHub Actions workflow file" in names


def test_detects_scheduled_workflow() -> None:
    text = (
        "name: nightly\n"
        "on:\n"
        "  schedule:\n"
        "    - cron: '0 0 * * *'\n"
        "jobs:\n"
        "  run:\n"
        "    runs-on: ubuntu-latest\n"
    )
    sigs = detect_signals_for_file(text, ".github/workflows/nightly.yml", "nightly.yml")
    names = [s.name for s in sigs]
    assert "GitHub Actions workflow file" in names
    assert "GitHub Actions schedule" in names


def test_detects_database_writes() -> None:
    names = _signal_names(
        "sql = 'INSERT INTO users (email) VALUES (%s)'\nconn.execute(sql)\nconn.commit()\n"
    )
    assert "database write operation" in names


def test_detects_payment_workflow() -> None:
    names = _signal_names(
        "import stripe\nstripe.api_key = os.environ['STRIPE_SECRET_KEY']\n"
        "stripe.Charge.create(amount=1000, currency='usd')\n"
    )
    assert any("Stripe" in n for n in names)


def test_detects_secrets_usage() -> None:
    names = _signal_names("import os\nopenai_key = os.environ['OPENAI_API_KEY']\n")
    assert "API key reference" in names


def test_detects_subprocess_shell_execution() -> None:
    names = _signal_names("import subprocess\nsubprocess.run(['rm', '-rf', '/tmp/foo'])\n")
    assert "subprocess invocation" in names


def test_detects_browser_automation() -> None:
    names = _signal_names(
        "from playwright.sync_api import sync_playwright\n"
        "with sync_playwright() as p:\n    browser = p.chromium.launch()\n"
    )
    assert "Playwright automation" in names


def test_detects_dependency_manifest_ai_sdks(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"dependencies": {"openai": "^4.0.0", "@anthropic-ai/sdk": "^0.20.0"}}\n',
        encoding="utf-8",
    )
    sigs = detect_signals_for_file(pkg.read_text(), "package.json", "package.json")
    names = [s.name for s in sigs]
    assert any("OpenAI SDK" in n for n in names)
    assert any("Anthropic SDK" in n for n in names)


def test_redact_line_handles_env_assignments() -> None:
    line = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDE"
    redacted = redact_line(line)
    assert "REDACTED" in redacted
    assert "sk-abcdefghijkl" not in redacted


def test_redact_line_handles_bearer_tokens() -> None:
    line = "Authorization: Bearer ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
    redacted = redact_line(line)
    assert "ghp_" not in redacted
    assert "REDACTED" in redacted


def test_redact_line_handles_private_keys() -> None:
    line = "key = '-----BEGIN PRIVATE KEY-----abcdefxyz12345-----END PRIVATE KEY-----'"
    redacted = redact_line(line)
    assert "BEGIN PRIVATE KEY" not in redacted
    assert "REDACTED" in redacted


def test_redact_line_keeps_normal_code_intact() -> None:
    line = "for i in range(10): print(i)"
    assert redact_line(line) == line


def test_redact_snippet_truncates_long_lines() -> None:
    long_line = "x = " + ("a" * 500)
    snippet = redact_snippet(long_line, max_len=80)
    assert len(snippet) <= 80
    assert snippet.endswith("...")


def test_scan_does_not_leak_secrets_in_signals(tmp_path: Path) -> None:
    p = tmp_path / "leaky.py"
    p.write_text(
        "API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDE'\n"
        "TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345'\n",
        encoding="utf-8",
    )
    rpt = scan_repository(tmp_path)
    blob = "\n".join(s.redacted_snippet or "" for f in rpt.findings for s in f.signals)
    assert "sk-abcdefghijkl" not in blob
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345" not in blob
    assert "REDACTED" in blob
