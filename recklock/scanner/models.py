"""Data models for ReckLock Discover findings & reports."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FindingType = Literal[
    "ai_agent",
    "llm_tool",
    "automation_agent",
    "outbound_agent",
    "browser_agent",
    "scheduled_job",
    "ci_cd_workflow",
    "deployment_workflow",
    "database_writer",
    "payment_or_financial_workflow",
    "secret_using_workflow",
    "shell_execution_workflow",
    "unknown",
]

Confidence = Literal["low", "medium", "high"]
RiskLevel = Literal["low", "medium", "high", "critical"]
RecommendedAction = Literal["monitor", "register", "govern", "manual_review"]


class ScannerSignal(BaseModel):
    """One detected signal inside a file."""

    name: str = Field(..., description="Human-readable signal label.")
    category: str = Field(
        ..., description="Coarse category, e.g. 'llm_ai', 'outbound', 'browser', 'deploy'."
    )
    line_number: int | None = Field(
        default=None, description="1-based line number, when known."
    )
    redacted_snippet: str | None = Field(
        default=None,
        description="Matched line with secrets redacted. Never contains raw credentials.",
    )


class ScannerFinding(BaseModel):
    """One scanner finding for a single file."""

    finding_id: str
    name: str
    path: str
    line_numbers: list[int] = Field(default_factory=list)
    finding_type: FindingType = "unknown"
    confidence: Confidence = "low"
    risk_level: RiskLevel = "low"
    signals: list[ScannerSignal] = Field(default_factory=list)
    likely_capabilities: list[str] = Field(default_factory=list)
    likely_permission_scopes: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction = "monitor"
    rationale: str = ""


class ScannerReport(BaseModel):
    """Aggregate scan report (also emitted as JSON)."""

    scanner: str = "recklock-discover"
    scanner_version: str
    scanned_path: str
    scanned_at: str
    files_scanned: int
    files_matched: int
    findings_count: int
    findings_by_type: dict[str, int] = Field(default_factory=dict)
    findings_by_risk: dict[str, int] = Field(default_factory=dict)
    findings_by_action: dict[str, int] = Field(default_factory=dict)
    critical_findings: list[str] = Field(default_factory=list)
    high_findings: list[str] = Field(default_factory=list)
    recommended_governance_targets: list[str] = Field(default_factory=list)
    recommended_registration_targets: list[str] = Field(default_factory=list)
    findings: list[ScannerFinding] = Field(default_factory=list)


CONFIDENCE_ORDER: tuple[Confidence, ...] = ("low", "medium", "high")
RISK_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


def at_least_confidence(confidence: Confidence, minimum: Confidence) -> bool:
    """Return True if *confidence* meets or exceeds *minimum*."""
    return CONFIDENCE_ORDER.index(confidence) >= CONFIDENCE_ORDER.index(minimum)


def bump_risk(current: RiskLevel, minimum: RiskLevel) -> RiskLevel:
    """Take the higher of two risk levels."""
    return RISK_ORDER[max(RISK_ORDER.index(current), RISK_ORDER.index(minimum))]
