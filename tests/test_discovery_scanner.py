"""Discovery scanner & classifier tests."""

from __future__ import annotations

from pathlib import Path

from recklock.discovery.scanner import scan_repository


def test_detects_openai_usage(tmp_path: Path) -> None:
    p = tmp_path / "bot.py"
    p.write_text("import openai\nclient = openai.OpenAI()\n", encoding="utf-8")
    hits = scan_repository(tmp_path)
    assert hits
    assert any("openai" in s.lower() for h in hits for s in h.detected_signals)
    assert hits[0].candidate_type == "ai_agent"
    assert hits[0].risk_level_guess in {"low", "medium", "high"}


def test_detects_github_actions_workflow(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    hits = scan_repository(tmp_path)
    assert hits
    assert any("GitHub Actions" in s for h in hits for s in h.detected_signals)
    assert hits[0].candidate_type == "ci_cd_workflow"


def test_detects_deployment_script(tmp_path: Path) -> None:
    p = tmp_path / "deploy.sh"
    p.write_text("#!/bin/bash\nkubectl apply -f manifest.yaml\n", encoding="utf-8")
    hits = scan_repository(tmp_path)
    assert hits
    assert hits[0].candidate_type == "deployment_workflow"
    assert hits[0].risk_level_guess == "critical"


def test_detects_database_write_signal(tmp_path: Path) -> None:
    p = tmp_path / "write_row.py"
    p.write_text(
        'sql = "INSERT INTO users (email) VALUES (%s)"\nconn.execute(sql, ("a@b.com",))\nconn.commit()\n',
        encoding="utf-8",
    )
    hits = scan_repository(tmp_path)
    assert hits
    assert any("database write" in s.lower() for h in hits for s in h.detected_signals)
    assert "write_database" in hits[0].likely_capabilities


def test_assigns_financial_critical_risk(tmp_path: Path) -> None:
    p = tmp_path / "pay.py"
    p.write_text(
        "import stripe\nstripe.api_key = os.environ['STRIPE_SECRET']\n",
        encoding="utf-8",
    )
    hits = scan_repository(tmp_path)
    assert hits[0].risk_level_guess == "critical"
    assert "payments.initiate" in hits[0].likely_permission_scopes
