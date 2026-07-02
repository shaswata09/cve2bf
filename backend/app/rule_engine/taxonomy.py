"""Typed, cached, read-only access to the BF taxonomy knowledge base.

The taxonomy JSON is the deterministic rule base. Every other rule-engine
component queries *this* module rather than reading the file, so there is a
single, well-tested place where the taxonomy is interpreted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.config import get_settings


@dataclass(frozen=True)
class BFClass:
    """An immutable view of one BF class and its legal vocabulary."""

    code: str
    name: str
    cluster: str
    phase: str
    operations: tuple[str, ...]
    bug_causes: tuple[str, ...]
    fault_causes: tuple[str, ...]
    errors: tuple[str, ...]
    final_errors: tuple[str, ...]
    operand_attributes: dict[str, tuple[str, ...]]
    operation_attributes: dict[str, tuple[str, ...]]

    def is_valid_operation(self, operation: str) -> bool:
        return operation in self.operations

    def is_valid_cause(self, kind: str, value: str) -> bool:
        pool = self.bug_causes if kind == "bug" else self.fault_causes
        return value in pool

    def is_valid_consequence(self, kind: str, value: str) -> bool:
        pool = self.errors if kind == "error" else self.final_errors
        return value in pool


class Taxonomy:
    """In-memory index over the BF taxonomy file.

    Parameters
    ----------
    raw:
        The parsed JSON document (see ``data/bf_taxonomy.json``).
    """

    def __init__(self, raw: dict) -> None:
        self._raw = raw
        self.version: str = raw["version"]
        self._classes: dict[str, BFClass] = {}
        for code, spec in raw["classes"].items():
            self._classes[code] = BFClass(
                code=code,
                name=spec["name"],
                cluster=spec["cluster"],
                phase=spec["phase"],
                operations=tuple(spec["operations"]),
                bug_causes=tuple(spec["causes"]["bug"]),
                fault_causes=tuple(spec["causes"]["fault"]),
                errors=tuple(spec["consequences"]["error"]),
                final_errors=tuple(spec["consequences"]["final_error"]),
                operand_attributes={
                    k: tuple(v) for k, v in spec.get("operand_attributes", {}).items()
                },
                operation_attributes={
                    k: tuple(v) for k, v in spec.get("operation_attributes", {}).items()
                },
            )
        self._failure_classes: dict[str, dict] = raw["failure_classes"]
        self._final_error_to_failure: dict[str, list[str]] = raw["final_error_to_failure"]

    # -- class lookups ------------------------------------------------------
    def classes(self) -> list[str]:
        """Return all BF class codes."""
        return list(self._classes)

    def has_class(self, code: str) -> bool:
        return code in self._classes

    def get_class(self, code: str) -> BFClass:
        """Return the :class:`BFClass` for ``code`` or raise ``KeyError``."""
        return self._classes[code]

    # -- failure lookups ----------------------------------------------------
    def failure_classes(self) -> dict[str, dict]:
        return dict(self._failure_classes)

    def failures_for_final_error(self, final_error: str) -> list[str]:
        """Return the failure-class codes a given final error can enable."""
        return list(self._final_error_to_failure.get(final_error, []))

    def failure_impact(self, failure_class: str) -> str:
        return self._failure_classes.get(failure_class, {}).get("impact", "")

    # -- propagation --------------------------------------------------------
    def classes_accepting_fault(self, fault_value: str) -> list[str]:
        """Return every class that can consume ``fault_value`` as a fault cause.

        This underpins backward chaining: given an error emitted by one
        weakness, which classes could take it as their fault?
        """
        return [c.code for c in self._classes.values() if fault_value in c.fault_causes]


@lru_cache
def load_taxonomy(path: Path | None = None) -> Taxonomy:
    """Load and cache the taxonomy from ``path`` (defaults to settings)."""
    resolved = path or get_settings().taxonomy_path
    raw = json.loads(Path(resolved).read_text(encoding="utf-8"))
    return Taxonomy(raw)
