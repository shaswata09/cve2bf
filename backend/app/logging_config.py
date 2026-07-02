"""Structured-ish logging configuration for the application.

Keeps logging setup in one place so both the API server and CLI/batch entry
points log consistently.
"""
from __future__ import annotations

import logging


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging once, idempotently."""
    root = logging.getLogger()
    if root.handlers:  # already configured (e.g. under uvicorn)
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level)
