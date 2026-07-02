"""FastAPI dependency providers.

Centralises construction of shared, expensive-to-build objects (the
orchestrator and its rule-engine components) so routes stay thin and the same
cached instances are reused across requests.
"""
from __future__ import annotations

from functools import lru_cache

from app.config import get_settings
from app.services.orchestrator import Orchestrator, build_orchestrator


@lru_cache
def get_orchestrator() -> Orchestrator:
    """Return a process-wide cached :class:`Orchestrator`."""
    return build_orchestrator(get_settings())
