"""Request/response schemas for the HTTP API.

These wrap the pure BF domain models (:mod:`app.models.bf`) with the
transport-level concerns: what the client sends, and what it receives back
including CVE metadata and pipeline provenance.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.bf import BFChain


class CVEMetadata(BaseModel):
    """The subset of NVD data the pipeline consumes and echoes to the UI."""

    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    #: True when the record came from the offline fixture rather than live NVD.
    from_fixture: bool = False


class AnalyzeRequest(BaseModel):
    """Payload for ``POST /api/v1/analyze``."""

    cve_id: str = Field(..., examples=["CVE-2014-0160"])

    @field_validator("cve_id")
    @classmethod
    def _normalise(cls, value: str) -> str:
        value = value.strip().upper()
        if not value.startswith("CVE-"):
            raise ValueError("cve_id must be of the form 'CVE-YYYY-NNNN'.")
        return value


class PipelineStepTrace(BaseModel):
    """Provenance for one pipeline step, recorded for auditability."""

    step: str
    status: str  # "ok" | "fallback" | "rejected" | "skipped"
    detail: str = ""


class ExtractionMeta(BaseModel):
    """Where the weakness slot values came from."""

    #: "vllm" when the language model produced the slots, "deterministic" when
    #: the rule-based fallback did.
    source: str
    model: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """Response for ``POST /api/v1/analyze``."""

    cve: CVEMetadata
    chain: Optional[BFChain] = None
    #: True when a valid chain was produced; False routes the UI to human review.
    valid: bool
    #: Present when ``valid`` is False.
    review_reason: Optional[str] = None
    extraction: Optional[ExtractionMeta] = None
    trace: list[PipelineStepTrace] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """Response for ``GET /api/v1/health``."""

    status: str
    taxonomy_version: str
    vllm_reachable: bool
