"""ReckLock Discover — open-source static agent discovery for any repository."""

from recklock.scanner.models import (
    Confidence,
    FindingType,
    RecommendedAction,
    RiskLevel,
    ScannerFinding,
    ScannerReport,
    ScannerSignal,
)
from recklock.scanner.scanner import scan_repository

__all__ = [
    "Confidence",
    "FindingType",
    "RecommendedAction",
    "RiskLevel",
    "ScannerFinding",
    "ScannerReport",
    "ScannerSignal",
    "scan_repository",
]

SCANNER_VERSION = "0.1.0"
