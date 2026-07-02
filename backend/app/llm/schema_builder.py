"""Builds the enum-constrained JSON schema handed to the LLM (part of step 3).

The extractor never asks the model for a free-form chain. Instead, for the
chosen skeleton it emits a JSON schema in which every field the model may fill
is constrained to an ``enum`` drawn from the taxonomy. Passed to vLLM as
``guided_json`` (structured/grammar-constrained decoding), the model *cannot*
emit an out-of-vocabulary token. This pushes most of the extraction step into
deterministic decoding; the model only resolves genuine ambiguity.
"""
from __future__ import annotations

from app.rule_engine.backward_tree import ChainSkeleton
from app.rule_engine.taxonomy import Taxonomy


def build_extraction_schema(skeleton: ChainSkeleton, taxonomy: Taxonomy) -> dict:
    """Return a JSON Schema constraining the model's output for ``skeleton``.

    The schema requires a ``weaknesses`` array of exactly ``len(skeleton.slots)``
    objects; each object has an ``operation`` (enum of that class's operations),
    an optional ``bug_cause`` (only meaningful for the initial weakness), an
    ``operands`` array, and ``operation_attributes``.
    """
    weakness_schemas: list[dict] = []
    for slot in skeleton.slots:
        cls = taxonomy.get_class(slot.bf_class)
        properties: dict = {
            "operation": {
                "type": "string",
                "enum": list(slot.allowed_operations),
                "description": f"Operation for BF class {slot.bf_class} ({cls.name}).",
            },
            "operands": {
                "type": "array",
                "items": _operand_schema(cls),
                "description": "Operands of the operation, e.g. the call site and pointer.",
            },
            "operation_attributes": _operation_attributes_schema(cls),
        }
        required = ["operation"]
        if slot.entry_cause_kind == "bug":
            properties["bug_cause"] = {
                "type": "string",
                "enum": list(slot.allowed_bug_causes),
                "description": "The bug (improper operation) label for the initial weakness.",
            }
            required.append("bug_cause")
        weakness_schemas.append(
            {"type": "object", "properties": properties, "required": required}
        )

    return {
        "type": "object",
        "properties": {
            "weaknesses": {
                "type": "array",
                "minItems": len(weakness_schemas),
                "maxItems": len(weakness_schemas),
                "items": weakness_schemas,  # tuple-style: positional item schemas
            }
        },
        "required": ["weaknesses"],
    }


def _operand_schema(cls) -> dict:
    """Schema for a single operand, with attribute enums from the class."""
    attr_props = {
        name: {"type": "string", "enum": list(values)}
        for name, values in cls.operand_attributes.items()
    }
    return {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Operand expression from the code."},
            "attributes": {"type": "object", "properties": attr_props},
        },
        "required": ["name"],
    }


def _operation_attributes_schema(cls) -> dict:
    """Schema for operation attributes, with enums from the class."""
    props = {
        name: {"type": "string", "enum": list(values)}
        for name, values in cls.operation_attributes.items()
    }
    return {"type": "object", "properties": props}
