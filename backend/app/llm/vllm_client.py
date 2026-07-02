"""Thin client for a vLLM OpenAI-compatible inference server.

The platform talks to whatever model is served by ``vllm serve ... --port 8000``
via its ``/v1/chat/completions`` endpoint. Constrained decoding is requested
through the vLLM ``guided_json`` extra body parameter, so the model output is
guaranteed to conform to the schema built by :mod:`app.llm.schema_builder`.

The client is deliberately small and dependency-light (``httpx`` only) and
exposes a :meth:`VLLMClient.is_reachable` probe so the orchestrator can decide
whether to fall back to deterministic extraction.
"""
from __future__ import annotations

import json
import logging

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class VLLMError(RuntimeError):
    """Raised when the vLLM server returns an error or is unreachable."""


class VLLMClient:
    """Minimal chat-completions client with structured-output support."""

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.vllm_base_url.rstrip("/")
        self._model = settings.vllm_model
        self._api_key = settings.vllm_api_key
        self._timeout = settings.vllm_timeout_seconds

    def is_reachable(self) -> bool:
        """Return True if the vLLM server responds to a models list request."""
        try:
            resp = httpx.get(
                f"{self._base_url}/models",
                headers=self._headers(),
                timeout=min(self._timeout, 5.0),
            )
            if resp.status_code != 200:
                return False

            try:
                data = resp.json().get("data", [])
                ids = {m["id"] for m in data}
                if self._model not in ids:
                    resolved = False
                    for m in data:
                        if m.get("root") == self._model:
                            logger.info("Resolved configured model '%s' to served ID '%s'", self._model, m["id"])
                            self._model = m["id"]
                            resolved = True
                            break
                    if not resolved and len(data) == 1:
                        logger.info("Using the single served model '%s' (configured: '%s')", data[0]["id"], self._model)
                        self._model = data[0]["id"]
            except Exception as e:
                logger.warning("Failed to parse models payload for resolution: %s", e)

            return True
        except httpx.HTTPError:
            return False

    def extract_json(self, system_prompt: str, user_prompt: str, json_schema: dict) -> dict:
        """Call the model and return a schema-conforming JSON object.

        Parameters
        ----------
        system_prompt, user_prompt:
            The instruction and the CVE context.
        json_schema:
            The JSON Schema enforced via vLLM ``guided_json``.

        Raises
        ------
        VLLMError
            If the request fails or the response cannot be parsed.
        """
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,  # deterministic decoding
            "max_tokens": 1024,
            # vLLM structured-output: constrain generation to the schema.
            "extra_body": {"guided_json": json_schema},
        }
        try:
            resp = httpx.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:  # network / status error
            raise VLLMError(f"vLLM request failed: {exc}") from exc

        try:
            message = resp.json()["choices"][0]["message"]
            content = message.get("content") or message.get("reasoning") or message.get("reasoning_content")
            if content is None:
                raise KeyError("No content or reasoning fields found in message")
            return json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise VLLMError(f"Could not parse vLLM response: {exc}") from exc

    # -- internal -----------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
