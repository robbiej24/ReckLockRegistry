"""Pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Local test pepper only — never the retired in-repo default.
os.environ.setdefault("RECKLOCK_SECRET_KEY", "local-recklock-registry-test-pepper")


@pytest.fixture
def example_manifest() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "registry" / "agents" / "example-agent.yaml"
