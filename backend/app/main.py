"""FastAPI application factory and entrypoint.

Run locally with::

    uvicorn app.main:app --reload --port 9000

The app serves the JSON API under the configured prefix and, when present,
mounts the static frontend at ``/`` so the whole platform is one process.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import get_settings
from app.logging_config import configure_logging

#: Location of the static frontend relative to the repository root.
_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    configure_logging()
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Deterministic CVE -> Bugs Framework (BF) chain generation.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix=settings.api_prefix)

    if _FRONTEND_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
        logging.getLogger(__name__).info("Serving frontend from %s", _FRONTEND_DIR)

    return app


app = create_app()
