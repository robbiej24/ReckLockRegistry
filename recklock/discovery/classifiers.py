"""Deterministic heuristic classification for discovered automation paths."""

from __future__ import annotations

from recklock.discovery.models import CandidateType, ConfidenceLevel, DiscoveredAgentCandidate, RiskGuess


def _has_any(signal_subset: set[str], haystack: list[str]) -> bool:
    return any(s in haystack for s in signal_subset)


def classify_candidate(candidate: DiscoveredAgentCandidate) -> DiscoveredAgentCandidate:
    """
    Map detected signals to type, capabilities, scopes, and risk.

    Pure heuristics — no LLM calls.
    """
    sigs = candidate.detected_signals
    caps: set[str] = set()
    scopes: set[str] = set()
    ctype: CandidateType = candidate.candidate_type
    risk: RiskGuess = "low"

    ai_signals = {
        "imports or calls OpenAI API",
        "imports or calls Anthropic API",
        "uses LangChain",
        "uses CrewAI",
        "uses AutoGen",
        "uses Google Gemini / Generative AI client",
        "dependency manifest lists AI SDKs",
    }
    coding_signals = {"references Cursor IDE or agent automation"}
    outbound_signals = {"email send or SMTP usage", "Slack webhook or Slack API usage"}
    deploy_signals = {
        "deployment or infrastructure tooling",
        "Docker build or compose usage",
        "Docker deployment artifact",
    }
    ci_signals = {"GitHub Actions workflow", "YAML resembles CI/CD workflow"}
    schedule_signals = {"cron-like schedule or background jobs"}

    if _has_any(ci_signals, sigs):
        ctype = "ci_cd_workflow"
        caps.update({"run_ci", "repository_automation"})
        scopes.update({"ci.execute", "repository.write"})
        risk = _bump_risk(risk, "medium")

    if candidate.source_path.startswith(".github/workflows/"):
        ctype = "ci_cd_workflow"

    if _has_any(deploy_signals, sigs):
        ctype = "deployment_workflow"
        caps.update({"deploy_code", "infrastructure_mutate"})
        scopes.update({"production.deploy", "infrastructure.write"})
        risk = _bump_risk(risk, "critical")

    if _has_any(schedule_signals, sigs) and ctype not in {"ci_cd_workflow", "deployment_workflow"}:
        ctype = "scheduled_job"
        caps.update({"scheduled_execution"})
        scopes.update({"scheduler.trigger"})
        risk = _bump_risk(risk, "medium")

    if _has_any(ai_signals, sigs):
        ctype = "ai_agent"
        caps.update({"llm_inference"})
        scopes.update({"ai.invoke"})
        risk = _bump_risk(risk, "medium")

    if _has_any(coding_signals, sigs):
        ctype = "coding_agent"
        caps.update({"code_assist", "repository_edit"})
        scopes.update({"workspace.write", "ai.invoke"})
        risk = _bump_risk(risk, "medium")

    if _has_any(outbound_signals, sigs):
        if ctype == "unknown":
            ctype = "outbound_agent"
        caps.update({"external_communication"})
        scopes.update({"email.send", "chat.post"})
        risk = _bump_risk(risk, "high")

    if "possible database write operations" in sigs:
        caps.update({"write_database"})
        scopes.update({"database.write"})
        risk = _bump_risk(risk, "high")

    if "references Stripe or STRIPE_ secrets" in sigs or "financial / payment / wallet / KYC signals" in sigs:
        caps.update({"initiate_payment", "financial_data_access"})
        scopes.update({"payments.initiate", "finance.read"})
        risk = _bump_risk(risk, "critical")

    if "subprocess or shell invocation" in sigs:
        caps.update({"execute_shell"})
        scopes.update({"process.exec"})
        risk = _bump_risk(risk, "high")

    if "uses boto3 (AWS)" in sigs or "deployment or infrastructure tooling" in sigs:
        caps.update({"cloud_api"})
        scopes.update({"cloud.write"})
        risk = _bump_risk(risk, "high")

    if "references GitHub token env vars" in sigs:
        scopes.update({"repository.secrets"})
        risk = _bump_risk(risk, "medium")

    if "references database URL env vars" in sigs:
        scopes.update({"database.connect"})
        risk = _bump_risk(risk, "medium")

    # Generic script bucket when still unclear but has automation signals
    if ctype == "unknown" and sigs:
        ctype = "script"
        caps.add("script_execution")
        scopes.add("workspace.execute")
        risk = _bump_risk(risk, "low")

    confidence = _confidence(len(sigs), ctype)

    candidate.candidate_type = ctype
    candidate.likely_capabilities = sorted(caps)
    candidate.likely_permission_scopes = sorted(scopes)
    candidate.risk_level_guess = risk
    candidate.confidence = confidence
    return candidate


def _bump_risk(current: RiskGuess, minimum: RiskGuess) -> RiskGuess:
    order = ("low", "medium", "high", "critical")
    return order[max(order.index(current), order.index(minimum))]


def _confidence(signal_count: int, ctype: CandidateType) -> ConfidenceLevel:
    if ctype == "unknown":
        return "low"
    if signal_count >= 4:
        return "high"
    if signal_count >= 2:
        return "medium"
    return "low"
