"""Tests for chain assembly and description generation."""
from __future__ import annotations

from app.llm.extractor import DeterministicExtractor
from app.rule_engine.backward_tree import BackwardStateTree
from app.rule_engine.chain_builder import ChainBuilder
from app.rule_engine.validator import ChainValidator


def test_built_chain_validates(taxonomy):
    """A chain assembled from a skeleton + deterministic slots must validate."""
    tree = BackwardStateTree(taxonomy)
    skeleton = next(
        s
        for s in tree.build(["DVR", "MAD", "MUS"], ["Buffer Over-Read"])
        if s.class_sequence == ["DVR", "MAD", "MUS"]
    )
    slots = DeterministicExtractor(taxonomy).extract(skeleton, "heap buffer over-read via memcpy").slot_values
    chain = ChainBuilder(taxonomy).build("CVE-2014-0160", skeleton, slots)

    assert chain.class_sequence == ["DVR", "MAD", "MUS"]
    assert chain.generated_description
    assert ChainValidator(taxonomy).validate(chain).valid


def test_slot_count_mismatch_raises(taxonomy):
    tree = BackwardStateTree(taxonomy)
    skeleton = tree.build(["MUS"], ["Buffer Over-Read"])[0]
    try:
        ChainBuilder(taxonomy).build("CVE-X", skeleton, [])
    except ValueError:
        return
    raise AssertionError("Expected ValueError for slot/skeleton length mismatch.")
