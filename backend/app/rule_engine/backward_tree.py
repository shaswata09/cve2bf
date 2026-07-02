"""Step 2 of the pipeline: the Backward State Tree.

Given the candidate BF classes and typical final errors from CWE narrowing, this
module enumerates every *admissible chain skeleton* by walking the taxonomy's
propagation relation **backward** from the failure:

* a terminal class emits a *final error* that enables a *failure*;
* it is entered through a *fault*; a predecessor class is any class whose
  *error* equals that fault; and so on back to an initial (bug-rooted) weakness.

The result is a bounded lattice of skeletons. A skeleton fixes the class
sequence and the propagation labels that connect the weaknesses; the concrete
operation, operands and attributes are filled later (LLM slot-filling), and the
whole thing is validated by the parser. Because the taxonomy is small and the
depth is bounded, this search is fast and fully deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.rule_engine.taxonomy import Taxonomy

#: Chains longer than this are not considered. Real BF vulnerability chains are
#: almost always 1-4 weaknesses long.
DEFAULT_MAX_DEPTH = 4


@dataclass(frozen=True)
class WeaknessSlot:
    """One node in a chain skeleton, with the enums the LLM may choose from.

    ``entry_cause_kind`` is ``"bug"`` for the initial weakness and ``"fault"``
    for propagated ones. ``entry_cause_value`` is the propagated fault label
    (``None`` for a bug — the specific bug label is chosen during slot-filling).
    ``exit_consequence_kind``/``exit_consequence_value`` describe how this
    weakness connects to the next one (or to the failure, if terminal).
    """

    bf_class: str
    entry_cause_kind: str
    entry_cause_value: str | None
    exit_consequence_kind: str  # "error" | "final_error"
    exit_consequence_value: str
    allowed_operations: tuple[str, ...]
    allowed_bug_causes: tuple[str, ...]


@dataclass
class ChainSkeleton:
    """An admissible class sequence terminating in a failure."""

    slots: list[WeaknessSlot] = field(default_factory=list)
    final_error: str = ""
    failure_class: str = ""
    #: Higher is better. Chains whose classes all came from CWE narrowing and
    #: that begin at an input-check class score higher.
    score: float = 0.0

    @property
    def class_sequence(self) -> list[str]:
        return [s.bf_class for s in self.slots]


class BackwardStateTree:
    """Enumerates :class:`ChainSkeleton` objects for a CVE."""

    def __init__(self, taxonomy: Taxonomy, max_depth: int = DEFAULT_MAX_DEPTH) -> None:
        self._tax = taxonomy
        self._max_depth = max_depth

    def build(
        self,
        candidate_classes: list[str],
        candidate_final_errors: list[str],
    ) -> list[ChainSkeleton]:
        """Return admissible chain skeletons, best-scoring first.

        Parameters
        ----------
        candidate_classes:
            BF classes suggested by CWE narrowing. Used only for *scoring*, so
            that a genuinely novel chain outside the suggestions is still found.
        candidate_final_errors:
            Typical final errors from CWE narrowing. Restricts the terminal
            weakness; if empty, all final errors are considered.
        """
        candidate_set = set(candidate_classes)
        skeletons: list[ChainSkeleton] = []

        for terminal_class in self._tax.classes():
            cls = self._tax.get_class(terminal_class)
            for fe in cls.final_errors:
                if candidate_final_errors and fe not in candidate_final_errors:
                    continue
                for failure in self._tax.failures_for_final_error(fe):
                    # Depth-first backward expansion from this terminal weakness.
                    partial = [
                        WeaknessSlot(
                            bf_class=terminal_class,
                            entry_cause_kind="fault",  # provisional; fixed if head
                            entry_cause_value=None,
                            exit_consequence_kind="final_error",
                            exit_consequence_value=fe,
                            allowed_operations=cls.operations,
                            allowed_bug_causes=cls.bug_causes,
                        )
                    ]
                    self._expand(partial, fe, failure, candidate_set, skeletons)

        # Deduplicate by (class_sequence, final_error, failure) and sort.
        unique: dict[tuple, ChainSkeleton] = {}
        for sk in skeletons:
            key = (tuple(sk.class_sequence), sk.final_error, sk.failure_class)
            if key not in unique or sk.score > unique[key].score:
                unique[key] = sk
        return sorted(unique.values(), key=lambda s: s.score, reverse=True)

    # -- internal -----------------------------------------------------------
    def _expand(
        self,
        partial: list[WeaknessSlot],
        final_error: str,
        failure: str,
        candidate_set: set[str],
        out: list[ChainSkeleton],
    ) -> None:
        """Recursively prepend predecessor weaknesses to ``partial``.

        ``partial`` is ordered terminal-first during construction and reversed
        into chain order when emitted.
        """
        head = partial[0]
        head_cls = self._tax.get_class(head.bf_class)

        # Emit the chain as-is: the head becomes a bug-rooted initial weakness.
        out.append(self._finalise(partial, final_error, failure, candidate_set))

        if len(partial) >= self._max_depth:
            return

        # A predecessor is any class whose *error* is a fault the head accepts.
        for fault in head_cls.fault_causes:
            for pred_code in self._tax.classes():
                if pred_code in {s.bf_class for s in partial}:
                    continue  # avoid cycles
                pred = self._tax.get_class(pred_code)
                if fault not in pred.errors:
                    continue
                # Rebuild the head so it is entered via this fault.
                new_head = WeaknessSlot(
                    bf_class=head.bf_class,
                    entry_cause_kind="fault",
                    entry_cause_value=fault,
                    exit_consequence_kind=head.exit_consequence_kind,
                    exit_consequence_value=head.exit_consequence_value,
                    allowed_operations=head.allowed_operations,
                    allowed_bug_causes=head.allowed_bug_causes,
                )
                pred_slot = WeaknessSlot(
                    bf_class=pred_code,
                    entry_cause_kind="fault",
                    entry_cause_value=None,
                    exit_consequence_kind="error",
                    exit_consequence_value=fault,
                    allowed_operations=pred.operations,
                    allowed_bug_causes=pred.bug_causes,
                )
                self._expand(
                    [pred_slot, new_head] + partial[1:],
                    final_error,
                    failure,
                    candidate_set,
                    out,
                )

    def _finalise(
        self,
        partial: list[WeaknessSlot],
        final_error: str,
        failure: str,
        candidate_set: set[str],
    ) -> ChainSkeleton:
        """Turn a terminal-first partial into a scored, chain-ordered skeleton."""
        ordered = list(partial)
        # The first weakness is bug-rooted.
        ordered[0] = WeaknessSlot(
            bf_class=ordered[0].bf_class,
            entry_cause_kind="bug",
            entry_cause_value=None,
            exit_consequence_kind=ordered[0].exit_consequence_kind,
            exit_consequence_value=ordered[0].exit_consequence_value,
            allowed_operations=ordered[0].allowed_operations,
            allowed_bug_causes=ordered[0].allowed_bug_causes,
        )
        skeleton = ChainSkeleton(
            slots=ordered,
            final_error=final_error,
            failure_class=failure,
        )
        skeleton.score = self._score(skeleton, candidate_set)
        return skeleton

    def _score(self, skeleton: ChainSkeleton, candidate_set: set[str]) -> float:
        """Score a skeleton: prefer CWE-consistent, input-rooted, plausible chains."""
        classes = skeleton.class_sequence
        score = 0.0
        # Reward classes that came from CWE narrowing.
        if candidate_set:
            overlap = sum(1 for c in classes if c in candidate_set)
            score += 2.0 * overlap / len(classes)
        # Reward chains that begin at an input-check class (typical root cause).
        if self._tax.get_class(classes[0]).cluster == "_INP":
            score += 1.0
        # Mild preference for the canonical 2-3 weakness length.
        if 2 <= len(classes) <= 3:
            score += 0.5
        return score
