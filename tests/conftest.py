"""Pytest fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def example_manifest() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "registry" / "agents" / "example-agent.yaml"
