"""Step 3 of the pipeline: constrained slot-filling extraction.

Given a chosen chain skeleton and the CVE text, produce the concrete per-slot
values (operation, bug cause, operands, attributes). Two backends:

* :class:`VLLMExtractor` — calls the vLLM server with an enum-constrained JSON
  schema (the primary, low-non-determinism path);
* :class:`DeterministicExtractor` — a rule-based fallback using keyword
  heuristics over the CVE description, guaranteeing a valid result even when no
  model is available.

Both return the same structure, so the orchestrator is agnostic to which ran.
The extractor's output is always subsequently checked by the validator, so a
poor extraction is rejected rather than trusted blindly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from app.config import Settings
from app.llm.schema_builder import build_extraction_schema
from app.llm.vllm_client import VLLMClient, VLLMError
from app.models.bf import Operand
from app.rule_engine.backward_tree import ChainSkeleton
from app.rule_engine.chain_builder import SlotValues
from app.rule_engine.taxonomy import Taxonomy

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a NIST Bugs Framework (BF) analyst. Given a CVE description and a "
    "fixed chain of BF weakness classes, fill in the operation, bug cause, "
    "operands and attributes for each weakness. You MUST choose only values "
    "offered by the provided JSON schema enums. Respond with JSON only."
)


@dataclass
class ExtractionOutput:
    """Slot values plus provenance about which backend produced them."""

    slot_values: list[SlotValues]
    source: str  # "vllm" | "deterministic"
    model: str | None = None


class DeterministicExtractor:
    """Rule-based fallback extractor.

    Uses light keyword heuristics over the CVE description to pick plausible
    operations and attributes, always defaulting to the first allowed enum
    value so the output is guaranteed valid against the taxonomy.
    """

    def __init__(self, taxonomy: Taxonomy) -> None:
        self._tax = taxonomy

    def extract(self, skeleton: ChainSkeleton, cve_text: str) -> ExtractionOutput:
        text = cve_text.lower()
        slots: list[SlotValues] = []
        for slot in skeleton.slots:
            cls = self._tax.get_class(slot.bf_class)
            operation = self._pick_operation(slot.allowed_operations, text)
            bug_cause = slot.allowed_bug_causes[0] if slot.entry_cause_kind == "bug" else None
            operands = [Operand(name=self._guess_operand(text), attributes=self._default_operand_attrs(cls))]
            op_attrs = self._default_operation_attrs(cls)
            slots.append(SlotValues(operation, bug_cause, operands, op_attrs))
        return ExtractionOutput(slots, source="deterministic")

    def _pick_operation(self, allowed: tuple[str, ...], text: str) -> str:
        """Prefer an operation whose name appears in the description."""
        for op in allowed:
            token = op.split()[0].lower()
            if token in text:
                return op
        # Keyword nudges for common patterns.
        if "read" in text and "Read" in allowed:
            return "Read"
        if "write" in text and "Write" in allowed:
            return "Write"
        return allowed[0]

    def _guess_operand(self, text: str) -> str:
        for token in ("memcpy", "strcpy", "malloc", "buffer", "pointer", "payload"):
            if token in text:
                return token
        return "operand"

    def _default_operand_attrs(self, cls) -> dict[str, str]:
        return {name: values[0] for name, values in cls.operand_attributes.items()}

    def _default_operation_attrs(self, cls) -> dict[str, str]:
        return {name: values[0] for name, values in cls.operation_attributes.items()}


class VLLMExtractor:
    """Primary extractor backed by a vLLM server with guided decoding."""

    def __init__(self, taxonomy: Taxonomy, client: VLLMClient, model: str) -> None:
        self._tax = taxonomy
        self._client = client
        self._model = model

    def extract(self, skeleton: ChainSkeleton, cve_text: str) -> ExtractionOutput:
        schema = build_extraction_schema(skeleton, self._tax)
        user_prompt = self._render_prompt(skeleton, cve_text)
        raw = self._client.extract_json(_SYSTEM_PROMPT, user_prompt, schema)
        slots = self._parse(skeleton, raw)
        return ExtractionOutput(slots, source="vllm", model=self._model)

    def _render_prompt(self, skeleton: ChainSkeleton, cve_text: str) -> str:
        chain = " -> ".join(skeleton.class_sequence)
        return (
            f"CVE description:\n{cve_text}\n\n"
            f"BF weakness class chain (fixed): {chain}\n"
            f"Terminal final error: {skeleton.final_error}\n"
            f"Fill each weakness's slots using only the schema enums."
        )

    def _parse(self, skeleton: ChainSkeleton, raw: dict) -> list[SlotValues]:
        """Convert the model's JSON into :class:`SlotValues`, filling gaps safely."""
        items = raw.get("weaknesses", [])
        slots: list[SlotValues] = []
        for idx, slot in enumerate(skeleton.slots):
            cls = self._tax.get_class(slot.bf_class)
            item = items[idx] if idx < len(items) else {}
            operation = item.get("operation") or slot.allowed_operations[0]
            bug_cause = item.get("bug_cause") if slot.entry_cause_kind == "bug" else None
            operands = [
                Operand(name=o.get("name", "operand"), attributes=o.get("attributes", {}))
                for o in item.get("operands", [])
            ] or [Operand(name="operand", attributes={})]
            op_attrs = item.get("operation_attributes", {})
            slots.append(SlotValues(operation, bug_cause, operands, op_attrs))
        return slots


def build_extractor(settings: Settings, taxonomy: Taxonomy) -> tuple[object, bool]:
    """Return ``(extractor, using_vllm)`` based on availability and config.

    Prefers vLLM; falls back to the deterministic extractor when the server is
    unreachable and fallback is enabled. Raises if neither is available.
    """
    client = VLLMClient(settings)
    if client.is_reachable():
        return VLLMExtractor(taxonomy, client, settings.vllm_model), True
    if settings.vllm_fallback_enabled:
        logger.warning("vLLM unreachable; using deterministic fallback extractor.")
        return DeterministicExtractor(taxonomy), False
    raise VLLMError("vLLM is unreachable and fallback is disabled.")
