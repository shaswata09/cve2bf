"""Tests for the BF chain validator (the hard gate)."""
from __future__ import annotations

from app.models.bf import (
    BFChain,
    Cause,
    CauseKind,
    Consequence,
    ConsequenceKind,
    Failure,
    Weakness,
)
from app.rule_engine.validator import ChainValidator


def _heartbleed_chain() -> BFChain:
    """A hand-built, valid Heartbleed chain: DVR -> MAD -> MUS -> IEX."""
    return BFChain(
        cve_id="CVE-2014-0160",
        weaknesses=[
            Weakness(
                bf_class="DVR",
                operation="Verify",
                cause=Cause(kind=CauseKind.BUG, value="Missing Code"),
                consequence=Consequence(kind=ConsequenceKind.ERROR, value="Inconsistent Value"),
            ),
            Weakness(
                bf_class="MAD",
                operation="Reposition",
                cause=Cause(kind=CauseKind.FAULT, value="Inconsistent Value"),
                consequence=Consequence(kind=ConsequenceKind.ERROR, value="Overbound Pointer"),
            ),
            Weakness(
                bf_class="MUS",
                operation="Read",
                cause=Cause(kind=CauseKind.FAULT, value="Overbound Pointer"),
                consequence=Consequence(kind=ConsequenceKind.FINAL_ERROR, value="Buffer Over-Read"),
            ),
        ],
        failure=Failure(failure_class="IEX", impact="confidentiality loss"),
    )


def test_valid_chain_passes(taxonomy):
    result = ChainValidator(taxonomy).validate(_heartbleed_chain())
    assert result.valid, result.errors


def test_broken_propagation_rejected(taxonomy):
    chain = _heartbleed_chain()
    # Corrupt the link between MAD and MUS.
    chain.weaknesses[2].cause.value = "Wild Pointer"
    result = ChainValidator(taxonomy).validate(chain)
    assert not result.valid
    assert any("propagation" in e for e in result.errors)


def test_illegal_operation_rejected(taxonomy):
    chain = _heartbleed_chain()
    chain.weaknesses[1].operation = "Read"  # Read is not a MAD operation
    result = ChainValidator(taxonomy).validate(chain)
    assert not result.valid


def test_initial_must_be_bug(taxonomy):
    chain = _heartbleed_chain()
    chain.weaknesses[0].cause.kind = CauseKind.FAULT
    result = ChainValidator(taxonomy).validate(chain)
    assert not result.valid
    assert any("bug-rooted" in e for e in result.errors)


def test_illegal_failure_rejected(taxonomy):
    chain = _heartbleed_chain()
    chain.failure.failure_class = "ACE"  # not enabled by Buffer Over-Read
    result = ChainValidator(taxonomy).validate(chain)
    assert not result.valid
    assert any("failure" in e for e in result.errors)


def test_terminal_must_be_final_error(taxonomy):
    chain = _heartbleed_chain()
    chain.weaknesses[-1].consequence.kind = ConsequenceKind.ERROR
    result = ChainValidator(taxonomy).validate(chain)
    assert not result.valid
