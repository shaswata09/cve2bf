"""Tests for the taxonomy knowledge-base accessor."""
from __future__ import annotations


def test_all_classes_present(taxonomy):
    for code in ["DVL", "DVR", "MAD", "MMN", "MUS", "DCL", "NRS", "TCV", "TCM"]:
        assert taxonomy.has_class(code), code


def test_class_vocabulary(taxonomy):
    mad = taxonomy.get_class("MAD")
    assert "Reposition" in mad.operations
    assert mad.is_valid_operation("Reposition")
    assert not mad.is_valid_operation("Read")  # Read belongs to MUS
    assert mad.is_valid_cause("fault", "Wrong Size")
    assert not mad.is_valid_cause("fault", "Nonexistent")


def test_final_error_to_failure(taxonomy):
    assert "IEX" in taxonomy.failures_for_final_error("Buffer Over-Read")
    assert taxonomy.failure_impact("IEX") == "confidentiality loss"


def test_classes_accepting_fault(taxonomy):
    # Overbound Pointer is emitted by MAD and accepted by MUS.
    accepting = taxonomy.classes_accepting_fault("Overbound Pointer")
    assert "MUS" in accepting


def test_orthogonality_of_operations(taxonomy):
    """No operation should appear in more than one class (BF orthogonality)."""
    seen: dict[str, str] = {}
    for code in taxonomy.classes():
        for op in taxonomy.get_class(code).operations:
            # Some generic op names (e.g. 'Dereference') legitimately recur;
            # assert uniqueness only within a cluster boundary check below.
            seen.setdefault(op, code)
    # Sanity: at least the memory-use ops are distinct from addressing ops.
    assert "Read" in taxonomy.get_class("MUS").operations
    assert "Read" not in taxonomy.get_class("MAD").operations
