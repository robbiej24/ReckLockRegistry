"""Phase 4A — internal agent discovery, passive telemetry, and evidence reports."""

from recklock.discovery.models import DiscoveredAgentCandidate
from recklock.discovery.scanner import scan_repository

__all__ = ["DiscoveredAgentCandidate", "scan_repository"]
