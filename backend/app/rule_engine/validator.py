"""Step 4 of the pipeline: the BF chain validator (the hard gate).

The full BF formal language is defined by an LL(1) attribute context-free
grammar in NIST SP 800-231. This module implements the equivalent structural
and causal checks that grammar enforces:

* every operation, cause and consequence is legal for its class;
* the initial weakness is bug-rooted and later ones are fault-rooted;
* each weakness's error consequence equals the next weakness's fault cause
  (strict propagation);
* the terminal weakness ends in a final error, and that final error legally
  enables the declared failure;
* any supplied attributes are drawn from the class's attribute vocabulary.

A chain either passes all checks or is rejected with precise, human-readable
reasons. This makes acceptance deterministic and auditable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models.bf import BFChain
from app.rule_engine.taxonomy import Taxonomy


@dataclass
class ValidationResult:
    """Outcome of validating a chain."""

    valid: bool
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # allow ``if result:``
        return self.valid


class ChainValidator:
    """Validates a :class:`BFChain` against the taxonomy."""

    def __init__(self, taxonomy: Taxonomy) -> None:
        self._tax = taxonomy

    def validate(self, chain: BFChain) -> ValidationResult:
        """Return a :class:`ValidationResult` for ``chain``."""
        errors: list[str] = []

        if not chain.weaknesses:
            return ValidationResult(False, ["Chain has no weaknesses."])

        for idx, weakness in enumerate(chain.weaknesses):
            prefix = f"weakness[{idx}] ({weakness.bf_class})"

            if not self._tax.has_class(weakness.bf_class):
                errors.append(f"{prefix}: unknown BF class.")
                continue
            cls = self._tax.get_class(weakness.bf_class)

            # Operation legality.
            if not cls.is_valid_operation(weakness.operation):
                errors.append(
                    f"{prefix}: operation '{weakness.operation}' is not valid for this class."
                )

            # Cause legality + bug/fault positioning.
            self._check_cause(idx, weakness, cls, prefix, errors)

            # Consequence legality.
            self._check_consequence(idx, weakness, cls, prefix, errors, len(chain.weaknesses))

            # Attribute legality.
            self._check_attributes(weakness, cls, prefix, errors)

        # Strict propagation between adjacent weaknesses.
        self._check_propagation(chain, errors)

        # Failure legality.
        self._check_failure(chain, errors)

        return ValidationResult(not errors, errors)

    # -- individual checks --------------------------------------------------
    def _check_cause(self, idx, weakness, cls, prefix, errors) -> None:
        cause = weakness.cause
        if idx == 0 and cause.kind.value != "bug":
            errors.append(f"{prefix}: initial weakness must be bug-rooted, got '{cause.kind.value}'.")
        if idx > 0 and cause.kind.value != "fault":
            errors.append(f"{prefix}: propagated weakness must be fault-rooted, got '{cause.kind.value}'.")
        if not cls.is_valid_cause(cause.kind.value, cause.value):
            errors.append(
                f"{prefix}: {cause.kind.value} cause '{cause.value}' is not valid for this class."
            )

    def _check_consequence(self, idx, weakness, cls, prefix, errors, n) -> None:
        cons = weakness.consequence
        is_terminal = idx == n - 1
        if is_terminal and cons.kind.value != "final_error":
            errors.append(f"{prefix}: terminal weakness must end in a final_error.")
        if not is_terminal and cons.kind.value != "error":
            errors.append(f"{prefix}: non-terminal weakness must end in an error.")
        if not cls.is_valid_consequence(cons.kind.value, cons.value):
            errors.append(
                f"{prefix}: {cons.kind.value} consequence '{cons.value}' is not valid for this class."
            )

    def _check_attributes(self, weakness, cls, prefix, errors) -> None:
        for attr, value in weakness.operation_attributes.items():
            allowed = cls.operation_attributes.get(attr)
            if allowed is None:
                errors.append(f"{prefix}: unknown operation attribute '{attr}'.")
            elif value not in allowed:
                errors.append(f"{prefix}: operation attribute '{attr}'='{value}' not allowed.")
        for operand in weakness.operands:
            for attr, value in operand.attributes.items():
                allowed = cls.operand_attributes.get(attr)
                if allowed is None:
                    errors.append(f"{prefix}: unknown operand attribute '{attr}'.")
                elif value not in allowed:
                    errors.append(f"{prefix}: operand attribute '{attr}'='{value}' not allowed.")

    def _check_propagation(self, chain, errors) -> None:
        for i in range(len(chain.weaknesses) - 1):
            emitted = chain.weaknesses[i].consequence
            received = chain.weaknesses[i + 1].cause
            if emitted.value != received.value:
                errors.append(
                    f"propagation[{i}->{i + 1}]: error '{emitted.value}' does not match "
                    f"next fault '{received.value}'."
                )

    def _check_failure(self, chain, errors) -> None:
        terminal = chain.weaknesses[-1].consequence
        allowed = self._tax.failures_for_final_error(terminal.value)
        if chain.failure.failure_class not in allowed:
            errors.append(
                f"failure: '{chain.failure.failure_class}' cannot be enabled by "
                f"final error '{terminal.value}' (allowed: {allowed or 'none'})."
            )
