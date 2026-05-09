"""Shared discovery models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CandidateType = Literal[
    "ai_agent",
    "coding_agent",
    "outbound_agent",
    "automation_agent",
    "deployment_workflow",
    "scheduled_job",
    "ci_cd_workflow",
    "script",
    "unknown",
]

RiskGuess = Literal["low", "medium", "high", "critical"]
ConfidenceLevel = Literal["low", "medium", "high"]


class DiscoveredAgentCandidate(BaseModel):
    """One heuristic scan hit."""

    candidate_id: str
    name: str
    source_path: str
    candidate_type: CandidateType = "unknown"
    detected_signals: list[str] = Field(default_factory=list)
    likely_capabilities: list[str] = Field(default_factory=list)
    likely_permission_scopes: list[str] = Field(default_factory=list)
    risk_level_guess: RiskGuess = "low"
    confidence: ConfidenceLevel = "low"
    notes: str | None = None
