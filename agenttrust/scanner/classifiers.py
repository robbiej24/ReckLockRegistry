"""Deterministic classification: turn signals into finding type, risk, & action."""

from __future__ import annotations

from agenttrust.scanner.detectors import (
    CAT_BROWSER,
    CAT_CI_CD,
    CAT_DATABASE,
    CAT_DEPLOY,
    CAT_LLM,
    CAT_OUTBOUND,
    CAT_PAYMENTS,
    CAT_SCHEDULE,
    CAT_SECRETS,
    CAT_SHELL,
)
from agenttrust.scanner.models import (
    Confidence,
    FindingType,
    RecommendedAction,
    RiskLevel,
    ScannerFinding,
    ScannerSignal,
    bump_risk,
)

PRODUCTION_INDICATOR_NAMES = {
    "deploy / production keywords",
    "Vercel deploy",
    "Netlify deploy",
    "Railway deploy",
    "Fly.io flyctl",
    "Terraform invocation",
    "Pulumi invocation",
    "kubectl invocation",
    "Helm invocation",
    "aws CLI invocation",
    "gcloud invocation",
    "azure CLI invocation",
    "Docker build / compose",
}


def _categories(signals: list[ScannerSignal]) -> set[str]:
    return {s.category for s in signals}


def _names(signals: list[ScannerSignal]) -> set[str]:
    return {s.name for s in signals}


def _classify_finding_type(
    signals: list[ScannerSignal], rel_posix: str, lower_name: str
) -> FindingType:
    cats = _categories(signals)
    names = _names(signals)

    if rel_posix.startswith(".github/workflows/") and lower_name.endswith((".yml", ".yaml")):
        if any(s.category == CAT_DEPLOY for s in signals) or any(
            n in PRODUCTION_INDICATOR_NAMES for n in names
        ):
            return "deployment_workflow"
        if CAT_SCHEDULE in cats or "GitHub Actions schedule" in names:
            return "scheduled_job"
        return "ci_cd_workflow"

    if "Dockerfile present" in names or "docker-compose file" in names:
        return "deployment_workflow"

    if CAT_DEPLOY in cats and (CAT_SECRETS in cats or CAT_SHELL in cats):
        return "deployment_workflow"

    if CAT_PAYMENTS in cats:
        return "payment_or_financial_workflow"

    if CAT_LLM in cats:
        if "tool calling / function calling" in names or "agent framework reference" in names or any(
            n in names for n in (
                "uses LangChain / LangGraph",
                "uses CrewAI",
                "uses AutoGen",
                "uses Semantic Kernel",
            )
        ):
            return "ai_agent"
        return "llm_tool"

    if CAT_BROWSER in cats and any(
        n in names
        for n in (
            "Playwright automation",
            "Selenium automation",
            "Puppeteer automation",
            "browser-use library",
        )
    ):
        return "browser_agent"

    if CAT_OUTBOUND in cats:
        return "outbound_agent"

    if CAT_DATABASE in cats and "database write operation" in names:
        return "database_writer"

    if CAT_DEPLOY in cats:
        return "deployment_workflow"

    if CAT_SCHEDULE in cats:
        return "scheduled_job"

    if CAT_SHELL in cats:
        return "shell_execution_workflow"

    if CAT_SECRETS in cats:
        return "secret_using_workflow"

    if CAT_BROWSER in cats:
        return "automation_agent"

    return "unknown"


def _capabilities_and_scopes(
    signals: list[ScannerSignal], finding_type: FindingType
) -> tuple[list[str], list[str]]:
    cats = _categories(signals)
    names = _names(signals)
    caps: set[str] = set()
    scopes: set[str] = set()

    if CAT_LLM in cats:
        caps.add("llm_inference")
        scopes.add("ai.invoke")
    if "tool calling / function calling" in names or "agent framework reference" in names:
        caps.add("agent_tool_calls")
        scopes.add("tools.invoke")

    if CAT_OUTBOUND in cats:
        caps.add("external_communication")
        scopes.update({"email.send", "chat.post"})

    if CAT_BROWSER in cats:
        caps.add("http_outbound")
        scopes.add("network.outbound")
        if finding_type == "browser_agent":
            caps.add("browser_automation")
            scopes.add("browser.control")

    if CAT_DEPLOY in cats:
        caps.update({"deploy_code", "infrastructure_mutate"})
        scopes.update({"production.deploy", "infrastructure.write"})

    if CAT_DATABASE in cats:
        if "database write operation" in names:
            caps.add("write_database")
            scopes.add("database.write")
        else:
            caps.add("read_database")
            scopes.add("database.read")
        if "references DATABASE_URL" in names:
            scopes.add("database.connect")

    if CAT_PAYMENTS in cats:
        caps.update({"initiate_payment", "financial_data_access"})
        scopes.update({"payments.initiate", "finance.read"})

    if CAT_SECRETS in cats:
        scopes.add("secrets.read")

    if CAT_SCHEDULE in cats:
        caps.add("scheduled_execution")
        scopes.add("scheduler.trigger")

    if CAT_SHELL in cats:
        caps.add("execute_shell")
        scopes.add("process.exec")

    if CAT_CI_CD in cats:
        caps.add("ci_pipeline")
        scopes.update({"ci.execute", "repository.write"})

    if not caps:
        caps.add("script_execution")
    if not scopes:
        scopes.add("workspace.execute")

    return sorted(caps), sorted(scopes)


def _risk_level(
    signals: list[ScannerSignal], finding_type: FindingType
) -> RiskLevel:
    cats = _categories(signals)
    names = _names(signals)

    risk: RiskLevel = "low"

    if CAT_BROWSER in cats:
        risk = bump_risk(risk, "medium")
    if CAT_LLM in cats:
        risk = bump_risk(risk, "medium")
    if CAT_SCHEDULE in cats:
        risk = bump_risk(risk, "medium")
    if CAT_CI_CD in cats:
        risk = bump_risk(risk, "medium")
    if CAT_SECRETS in cats:
        risk = bump_risk(risk, "medium")
    if "references DATABASE_URL" in names:
        risk = bump_risk(risk, "medium")

    if CAT_OUTBOUND in cats:
        risk = bump_risk(risk, "high")
    if CAT_SHELL in cats:
        risk = bump_risk(risk, "high")
    if "database write operation" in names:
        risk = bump_risk(risk, "high")
    if CAT_DEPLOY in cats:
        risk = bump_risk(risk, "high")
    if "tool calling / function calling" in names and CAT_LLM in cats:
        risk = bump_risk(risk, "high")

    if CAT_PAYMENTS in cats:
        money_verbs = {
            "money movement verb",
            "Stripe SDK / API",
            "Plaid SDK / API",
            "Dwolla SDK / API",
            "PayPal SDK / API",
        }
        if names & money_verbs or "database write operation" in names:
            risk = bump_risk(risk, "critical")
        else:
            risk = bump_risk(risk, "high")

    deploy_with_secrets = (CAT_DEPLOY in cats) and (CAT_SECRETS in cats)
    db_write_with_prod = "database write operation" in names and (
        CAT_DEPLOY in cats or any(n in PRODUCTION_INDICATOR_NAMES for n in names)
    )
    shell_with_secrets_and_deploy = (
        CAT_SHELL in cats and CAT_SECRETS in cats and CAT_DEPLOY in cats
    )
    if deploy_with_secrets or db_write_with_prod or shell_with_secrets_and_deploy:
        risk = bump_risk(risk, "critical")

    return risk


def _confidence(signals: list[ScannerSignal], finding_type: FindingType) -> Confidence:
    if finding_type == "unknown":
        return "low"
    distinct_categories = len(_categories(signals))
    if len(signals) >= 4 or distinct_categories >= 3:
        return "high"
    if len(signals) >= 2 or distinct_categories >= 2:
        return "medium"
    return "low"


def _recommended_action(
    risk: RiskLevel, confidence: Confidence, finding_type: FindingType
) -> RecommendedAction:
    if confidence == "low" and risk in {"high", "critical"}:
        return "manual_review"
    if risk == "critical":
        return "govern"
    if risk == "high":
        return "register"
    if risk == "medium":
        return "register" if confidence == "high" else "monitor"
    return "monitor"


def _rationale(
    signals: list[ScannerSignal],
    finding_type: FindingType,
    risk: RiskLevel,
    confidence: Confidence,
    action: RecommendedAction,
) -> str:
    sig_summary = ", ".join(sorted({s.name for s in signals})[:8])
    return (
        f"Classified as {finding_type} ({confidence} confidence) at risk={risk}. "
        f"Recommended action: {action}. "
        f"Top signals: {sig_summary or 'none'}."
    )


def classify_finding(
    *,
    finding_id: str,
    name: str,
    path: str,
    rel_posix: str,
    lower_name: str,
    signals: list[ScannerSignal],
) -> ScannerFinding:
    """Build a fully populated ScannerFinding from raw signals."""
    finding_type = _classify_finding_type(signals, rel_posix, lower_name)
    capabilities, scopes = _capabilities_and_scopes(signals, finding_type)
    risk = _risk_level(signals, finding_type)
    confidence = _confidence(signals, finding_type)
    action = _recommended_action(risk, confidence, finding_type)
    line_numbers = sorted({s.line_number for s in signals if s.line_number is not None})
    rationale = _rationale(signals, finding_type, risk, confidence, action)
    return ScannerFinding(
        finding_id=finding_id,
        name=name,
        path=path,
        line_numbers=line_numbers,
        finding_type=finding_type,
        confidence=confidence,
        risk_level=risk,
        signals=signals,
        likely_capabilities=capabilities,
        likely_permission_scopes=scopes,
        recommended_action=action,
        rationale=rationale,
    )
