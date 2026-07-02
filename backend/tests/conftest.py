"""Shared pytest fixtures.

Tests run fully offline: NVD is served from fixtures and vLLM is assumed
unreachable, so the deterministic extractor is exercised. This makes the suite
hermetic and reproducible.
"""
from __future__ import annotations

import os

import pytest

# Force offline behaviour before any app module reads settings.
os.environ["CVE2BF_OFFLINE_MODE"] = "true"
# Point vLLM at an unroutable port so is_reachable() is False and the
# deterministic fallback is used.
os.environ["CVE2BF_VLLM_BASE_URL"] = "http://127.0.0.1:1/v1"
os.environ["CVE2BF_VLLM_FALLBACK_ENABLED"] = "true"

from app.config import Settings, get_settings  # noqa: E402
from app.rule_engine.cwe2bf import load_mapper  # noqa: E402
from app.rule_engine.taxonomy import load_taxonomy  # noqa: E402


@pytest.fixture(scope="session")
def settings() -> Settings:
    return get_settings()


@pytest.fixture(scope="session")
def taxonomy(settings):
    return load_taxonomy(settings.taxonomy_path)


@pytest.fixture(scope="session")
def mapper(settings):
    return load_mapper(settings.cwe2bf_path)
