"""Step 1 of the pipeline: deterministic CWE -> BF class narrowing.

Given the CWE ids attached to a CVE by NVD, this module returns the candidate
BF classes and typical final errors via a pure table lookup. No model is
involved. When a CVE carries no recognised CWE, a conservative default is used.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.config import get_settings


@dataclass
class NarrowingResult:
    """Outcome of CWE narrowing for a single CVE."""

    #: Candidate BF class codes, de-duplicated, order-preserved.
    candidate_classes: list[str] = field(default_factory=list)
    #: Typical final-error labels associated with the matched CWEs.
    candidate_final_errors: list[str] = field(default_factory=list)
    #: The CWE ids that were actually recognised in the table.
    matched_cwes: list[str] = field(default_factory=list)
    #: True when the default fallback mapping was used.
    used_default: bool = False


class CWE2BFMapper:
    """Table-driven CWE -> BF class mapper."""

    def __init__(self, raw: dict) -> None:
        self._mappings: dict[str, dict] = raw["mappings"]
        self._default: dict = raw["default"]

    def narrow(self, cwe_ids: list[str]) -> NarrowingResult:
        """Return candidate BF classes for the given CWE ids.

        Parameters
        ----------
        cwe_ids:
            CWE identifiers such as ``["CWE-125"]``. Unknown or empty inputs
            trigger the default mapping.
        """
        classes: list[str] = []
        final_errors: list[str] = []
        matched: list[str] = []

        for cwe in cwe_ids:
            entry = self._mappings.get(cwe.strip().upper())
            if entry is None:
                continue
            matched.append(cwe)
            _extend_unique(classes, entry["bf_classes"])
            _extend_unique(final_errors, entry["typical_final_errors"])

        if not matched:
            _extend_unique(classes, self._default["bf_classes"])
            _extend_unique(final_errors, self._default["typical_final_errors"])
            return NarrowingResult(classes, final_errors, matched, used_default=True)

        return NarrowingResult(classes, final_errors, matched, used_default=False)


def _extend_unique(target: list[str], items: list[str]) -> None:
    """Append items from ``items`` not already present in ``target``."""
    for item in items:
        if item not in target:
            target.append(item)


@lru_cache
def load_mapper(path: Path | None = None) -> CWE2BFMapper:
    """Load and cache the CWE2BF mapper."""
    resolved = path or get_settings().cwe2bf_path
    raw = json.loads(Path(resolved).read_text(encoding="utf-8"))
    return CWE2BFMapper(raw)
