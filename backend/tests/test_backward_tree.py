"""Tests for the backward state tree."""
from __future__ import annotations

from app.rule_engine.backward_tree import BackwardStateTree


def test_heartbleed_chain_is_admissible(taxonomy):
    """The DVR -> MAD -> MUS chain must be discoverable for a Buffer Over-Read."""
    tree = BackwardStateTree(taxonomy)
    skeletons = tree.build(["DVR", "MAD", "MUS"], ["Buffer Over-Read"])
    sequences = [s.class_sequence for s in skeletons]
    assert ["DVR", "MAD", "MUS"] in sequences


def test_terminal_is_final_error(taxonomy):
    tree = BackwardStateTree(taxonomy)
    skeletons = tree.build(["MUS"], ["Buffer Over-Read"])
    assert skeletons
    for sk in skeletons:
        assert sk.slots[-1].exit_consequence_kind == "final_error"
        assert sk.slots[0].entry_cause_kind == "bug"


def test_propagation_labels_link_slots(taxonomy):
    """Each non-terminal slot's exit error equals the next slot's entry fault."""
    tree = BackwardStateTree(taxonomy)
    skeletons = tree.build(["DVR", "MAD", "MUS"], ["Buffer Over-Read"])
    target = next(s for s in skeletons if s.class_sequence == ["DVR", "MAD", "MUS"])
    for i in range(len(target.slots) - 1):
        assert target.slots[i].exit_consequence_value == target.slots[i + 1].entry_cause_value


def test_scoring_prefers_input_rooted(taxonomy):
    tree = BackwardStateTree(taxonomy)
    skeletons = tree.build(["DVR", "MAD", "MUS"], ["Buffer Over-Read"])
    # The best-scoring skeleton should begin at an input-check class.
    assert taxonomy.get_class(skeletons[0].class_sequence[0]).cluster == "_INP"


def test_empty_when_no_final_error(taxonomy):
    tree = BackwardStateTree(taxonomy)
    skeletons = tree.build(["DVR"], ["Nonexistent Final Error"])
    assert skeletons == []
