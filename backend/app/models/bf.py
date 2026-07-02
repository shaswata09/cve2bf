"""Core Bugs Framework (BF) domain models.

These Pydantic models are the single source of truth for the *shape* of a BF
specification inside the platform. They mirror the concepts defined in
NIST SP 800-231:

* A **weakness** is a ``(cause, operation) -> consequence`` triple, where the
  cause is either a *bug* (an improper operation) or a *fault* (an improper
  operand), and the consequence is an *error* or a *final error*.
* A **vulnerability** is a *chain* of weaknesses that begins with a bug and
  ends with a final error that enables a *failure*.

The models here are intentionally free of business logic; validation against
the taxonomy lives in :mod:`app.rule_engine.validator`.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CauseKind(str, Enum):
    """Whether a weakness is rooted in a bug or a fault.

    A *bug* is an improper operation (must be fixed to resolve the
    vulnerability). A *fault* is an improper operand (fixing it only mitigates).
    The first weakness in a chain is always a bug; propagated weaknesses are
    faults.
    """

    BUG = "bug"
    FAULT = "fault"


class ConsequenceKind(str, Enum):
    """Whether a weakness consequence is an intermediate error or a final one."""

    ERROR = "error"
    FINAL_ERROR = "final_error"


class Cause(BaseModel):
    """The cause half of a BF weakness triple."""

    kind: CauseKind = Field(..., description="bug or fault")
    #: For a bug this is a code-defect label (e.g. 'Missing Code'); for a fault
    #: it is the improper-operand label propagated from the previous weakness
    #: (e.g. 'Wrong Size').
    value: str = Field(..., description="The cause label, drawn from the taxonomy.")


class Consequence(BaseModel):
    """The consequence half of a BF weakness triple."""

    kind: ConsequenceKind = Field(..., description="error or final_error")
    #: The error label (e.g. 'Overbound Pointer') or final-error label
    #: (e.g. 'Buffer Over-Read').
    value: str = Field(..., description="The consequence label, drawn from the taxonomy.")


class Operand(BaseModel):
    """An operand of a BF operation, with optional attribute annotations."""

    name: str = Field(..., description="Operand expression, e.g. 'memcpy(bp, pl, payload)'.")
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Operand attribute name -> value, e.g. {'Address State': 'Heap'}.",
    )


class Weakness(BaseModel):
    """A single BF weakness: ``(cause, operation) -> consequence``.

    ``bf_class`` selects the taxonomic class (e.g. ``MAD``) which constrains the
    legal ``operation``, ``cause`` and ``consequence`` values.
    """

    bf_class: str = Field(..., description="BF class code, e.g. 'DVR', 'MAD', 'MUS'.")
    operation: str = Field(..., description="Operation within the class, e.g. 'Reposition'.")
    cause: Cause
    consequence: Consequence
    operands: list[Operand] = Field(default_factory=list)
    operation_attributes: dict[str, str] = Field(default_factory=dict)


class Failure(BaseModel):
    """The terminal security failure enabled by the chain's final error."""

    failure_class: str = Field(..., description="Failure class code, e.g. 'IEX'.")
    impact: str = Field(..., description="e.g. 'confidentiality loss'.")


class BFChain(BaseModel):
    """A full BF vulnerability specification for one CVE.

    ``weaknesses`` are ordered from the initial bug to the final error; each
    weakness's error consequence propagates to become the fault cause of the
    next weakness.
    """

    cve_id: str
    weaknesses: list[Weakness]
    failure: Failure
    #: Human-readable, deterministically generated narrative of the chain.
    generated_description: str = ""

    @property
    def class_sequence(self) -> list[str]:
        """Return the ordered list of BF class codes, e.g. ``['DVR','MAD','MUS']``."""
        return [w.bf_class for w in self.weaknesses]
