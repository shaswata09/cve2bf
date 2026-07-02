"""Centralised, environment-driven application configuration.

All tunables live here so nothing downstream reads ``os.environ`` directly.
Values can be overridden with environment variables or a local ``.env`` file
(see ``.env.example``).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Absolute path to the ``app`` package, used to locate bundled data files.
APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"


class Settings(BaseSettings):
    """Runtime configuration.

    Attributes are populated (in priority order) from constructor arguments,
    environment variables, then the ``.env`` file.
    """

    model_config = SettingsConfigDict(env_file=".env", env_prefix="CVE2BF_", extra="ignore")

    # --- HTTP server -------------------------------------------------------
    app_name: str = "CVE2BF Platform"
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    # --- NVD data source ---------------------------------------------------
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_timeout_seconds: float = 15.0
    #: When True, never hit the network; serve only bundled fixtures. Useful for
    #: air-gapped or offline environments and for deterministic tests.
    offline_mode: bool = False

    # --- vLLM inference server --------------------------------------------
    #: OpenAI-compatible base URL exposed by ``vllm serve``.
    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_model: str = "meta-llama/Llama-3.1-8B-Instruct"
    vllm_api_key: str = "EMPTY"
    vllm_timeout_seconds: float = 30.0
    #: If vLLM is unreachable, fall back to the deterministic rule-based
    #: extractor so the platform stays functional without a GPU.
    vllm_fallback_enabled: bool = True

    # --- Data files --------------------------------------------------------
    taxonomy_path: Path = DATA_DIR / "bf_taxonomy.json"
    cwe2bf_path: Path = DATA_DIR / "cwe2bf.json"


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance (one per process)."""
    return Settings()
