"""Tests for CWE -> BF class narrowing."""
from __future__ import annotations


def test_known_cwe_maps_to_memory_classes(mapper):
    result = mapper.narrow(["CWE-125"])
    assert not result.used_default
    assert result.matched_cwes == ["CWE-125"]
    assert "MUS" in result.candidate_classes
    assert "Buffer Over-Read" in result.candidate_final_errors


def test_unknown_cwe_uses_default(mapper):
    result = mapper.narrow(["CWE-99999"])
    assert result.used_default
    assert result.candidate_classes  # non-empty conservative default


def test_empty_cwe_uses_default(mapper):
    result = mapper.narrow([])
    assert result.used_default


def test_multiple_cwes_dedupe(mapper):
    result = mapper.narrow(["CWE-125", "CWE-787"])
    # Classes should be de-duplicated across the two mappings.
    assert len(result.candidate_classes) == len(set(result.candidate_classes))
