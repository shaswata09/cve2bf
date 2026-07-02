"""Steps 5-6 of the pipeline: chain assembly and description generation.

The chain builder takes a :class:`ChainSkeleton` (from the backward state tree)
and the per-slot values chosen during extraction, then assembles a concrete
:class:`BFChain`. Propagation labels come straight from the skeleton, so the
error->fault links are correct by construction. It also renders a deterministic
natural-language description of the chain for display in the UI.
"""
from __future__ import annotations

from app.models.bf import (
    BFChain,
    Cause,
    CauseKind,
    Consequence,
    ConsequenceKind,
    Failure,
    Operand,
    Weakness,
)
from app.rule_engine.backward_tree import ChainSkeleton
from app.rule_engine.taxonomy import Taxonomy


class SlotValues:
    """The concrete values chosen for one weakness slot during extraction.

    Only the fields the extractor is responsible for; the class, propagation
    labels and consequence kind are already fixed by the skeleton.
    """

    def __init__(
        self,
        operation: str,
        bug_cause: str | None,
        operands: list[Operand] | None = None,
        operation_attributes: dict[str, str] | None = None,
    ) -> None:
        self.operation = operation
        #: Only used for the initial (bug-rooted) weakness.
        self.bug_cause = bug_cause
        self.operands = operands or []
        self.operation_attributes = operation_attributes or {}


class ChainBuilder:
    """Assembles and narrates BF chains."""

    def __init__(self, taxonomy: Taxonomy) -> None:
        self._tax = taxonomy

    def build(
        self,
        cve_id: str,
        skeleton: ChainSkeleton,
        slot_values: list[SlotValues],
    ) -> BFChain:
        """Assemble a :class:`BFChain`.

        Parameters
        ----------
        cve_id:
            The CVE identifier the chain describes.
        skeleton:
            The admissible skeleton chosen by the pipeline.
        slot_values:
            One :class:`SlotValues` per skeleton slot, in order.
        """
        if len(slot_values) != len(skeleton.slots):
            raise ValueError("slot_values length must match skeleton slots length.")

        weaknesses: list[Weakness] = []
        for slot, values in zip(skeleton.slots, slot_values):
            if slot.entry_cause_kind == "bug":
                cause = Cause(kind=CauseKind.BUG, value=values.bug_cause or slot.allowed_bug_causes[0])
            else:
                cause = Cause(kind=CauseKind.FAULT, value=slot.entry_cause_value or "")

            consequence = Consequence(
                kind=ConsequenceKind(slot.exit_consequence_kind),
                value=slot.exit_consequence_value,
            )
            weaknesses.append(
                Weakness(
                    bf_class=slot.bf_class,
                    operation=values.operation,
                    cause=cause,
                    consequence=consequence,
                    operands=values.operands,
                    operation_attributes=values.operation_attributes,
                )
            )

        failure = Failure(
            failure_class=skeleton.failure_class,
            impact=self._tax.failure_impact(skeleton.failure_class),
        )
        chain = BFChain(cve_id=cve_id, weaknesses=weaknesses, failure=failure)
        chain.generated_description = self._describe(chain)
        return chain

    # -- description --------------------------------------------------------
    def _describe(self, chain: BFChain) -> str:
        """Render a deterministic natural-language narrative of the chain."""
        parts: list[str] = []
        for idx, w in enumerate(chain.weaknesses):
            cls = self._tax.get_class(w.bf_class)
            operand = w.operands[0].name if w.operands else "the operand"
            if idx == 0:
                lead = f"A {w.cause.value.lower()} bug in the {cls.name} ({w.bf_class}) operation"
            else:
                lead = f"The {w.cause.value.lower()} propagates to the {cls.name} ({w.bf_class}) operation"
            clause = (
                f"{lead} '{w.operation}' over {operand}"
                f" results in {w.consequence.value.lower()}"
            )
            if idx < len(chain.weaknesses) - 1:
                clause += ", which propagates as the next cause"
            parts.append(clause)

        narrative = "; ".join(parts)
        narrative += (
            f". This final error enables a {chain.failure.failure_class} "
            f"({chain.failure.impact}) security failure."
        )
        return narrative.capitalize() if not narrative[0].isupper() else narrative
