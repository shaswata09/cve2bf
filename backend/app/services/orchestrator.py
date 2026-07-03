"""The pipeline orchestrator: runs steps 1-6 for a single CVE.

The orchestrator holds *no* BF knowledge itself. It wires together the NVD
client, the CWE2BF mapper, the backward state tree, the extractor, the
validator and the chain builder, running them in order and recording a
provenance trace. It tries admissible skeletons best-first and returns the
first chain that passes validation; if none pass, it returns a review flag
rather than an unvalidated guess.
"""
from __future__ import annotations

import logging

from app.config import Settings, get_settings
from app.llm.extractor import build_extractor
from app.models.api_schemas import (
    AnalyzeResponse,
    CVEMetadata,
    ExtractionMeta,
    PipelineStepTrace,
)
from app.rule_engine.backward_tree import BackwardStateTree
from app.rule_engine.chain_builder import ChainBuilder
from app.rule_engine.cwe2bf import CWE2BFMapper, load_mapper
from app.rule_engine.taxonomy import Taxonomy, load_taxonomy
from app.rule_engine.validator import ChainValidator
from app.services.nvd_client import CVENotFoundError, NVDClient, NVDError

logger = logging.getLogger(__name__)

#: Cap on how many admissible skeletons to attempt before giving up.
MAX_SKELETON_ATTEMPTS = 8


class Orchestrator:
    """Coordinates the deterministic pipeline plus the constrained LLM step."""

    def __init__(
        self,
        settings: Settings,
        nvd: NVDClient,
        mapper: CWE2BFMapper,
        taxonomy: Taxonomy,
    ) -> None:
        self._settings = settings
        self._nvd = nvd
        self._mapper = mapper
        self._tax = taxonomy
        self._tree = BackwardStateTree(taxonomy)
        self._validator = ChainValidator(taxonomy)
        self._builder = ChainBuilder(taxonomy)

    def analyze(self, cve_id: str) -> AnalyzeResponse:
        """Run the full pipeline for ``cve_id`` and return the response."""
        trace: list[PipelineStepTrace] = []

        # Step 0: fetch the CVE.
        try:
            cve = self._nvd.fetch(cve_id)
        except CVENotFoundError as exc:
            return self._not_found(cve_id, str(exc), trace)
        except NVDError as exc:
            return self._fetch_failed(cve_id, str(exc), trace)
        trace.append(
            PipelineStepTrace(
                step="fetch_cve",
                status="fallback" if cve.from_fixture else "ok",
                detail=f"CWEs={cve.cwe_ids or 'none'}, fixture={cve.from_fixture}",
            )
        )

        # Step 1: CWE -> BF narrowing.
        narrowing = self._mapper.narrow(cve.cwe_ids)
        trace.append(
            PipelineStepTrace(
                step="cwe_narrowing",
                status="fallback" if narrowing.used_default else "ok",
                detail=f"classes={narrowing.candidate_classes}",
            )
        )

        # Step 2: backward state tree.
        skeletons = self._tree.build(
            narrowing.candidate_classes, narrowing.candidate_final_errors
        )
        if not skeletons:
            return self._review(cve, "No admissible BF chain could be derived.", trace)
        trace.append(
            PipelineStepTrace(
                step="backward_tree",
                status="ok",
                detail=f"{len(skeletons)} admissible skeleton(s)",
            )
        )

        # Build the extraction backend once (vLLM or deterministic fallback).
        extractor, using_vllm = build_extractor(self._settings, self._tax)
        extraction_meta: ExtractionMeta | None = None

        # Steps 3-5: try skeletons best-first until one validates.
        failed_attempts_log = []
        for attempt, skeleton in enumerate(skeletons[:MAX_SKELETON_ATTEMPTS]):
            output = extractor.extract(skeleton, cve.description)
            extraction_meta = ExtractionMeta(source=output.source, model=output.model)
            chain = self._builder.build(cve.cve_id, skeleton, output.slot_values)
            result = self._validator.validate(chain)
            if result.valid:
                trace.append(
                    PipelineStepTrace(
                        step="extract_validate",
                        status="ok",
                        detail=(
                            f"attempt={attempt}, chain={'->'.join(chain.class_sequence)}, "
                            f"source={output.source}, using_vllm={using_vllm}"
                        ),
                    )
                )
                return AnalyzeResponse(
                    cve=cve,
                    chain=chain,
                    valid=True,
                    extraction=extraction_meta,
                    trace=trace,
                )
            
            failed_attempts_log.append({
                "chain": " -> ".join(skeleton.class_sequence),
                "errors": "; ".join(result.errors[:3])
            })
            
            trace.append(
                PipelineStepTrace(
                    step="extract_validate",
                    status="rejected",
                    detail=f"attempt={attempt}: {'; '.join(result.errors[:3])}",
                )
            )

        analyst_eval = None
        if hasattr(extractor, "evaluate_failure"):
            eval_data = extractor.evaluate_failure(cve.description, failed_attempts_log)
            from app.models.api_schemas import AnalystEvaluation
            analyst_eval = AnalystEvaluation(
                justification=eval_data.get("justification", ""),
                suggested_chain=eval_data.get("suggested_chain", [])
            )

        return self._review(
            cve,
            "No candidate chain passed validation; manual review required.",
            trace,
            extraction_meta,
            analyst_eval,
        )

    # -- response helpers ---------------------------------------------------
    def _review(self, cve, reason, trace, extraction=None, analyst_evaluation=None) -> AnalyzeResponse:
        return AnalyzeResponse(
            cve=cve, chain=None, valid=False, review_reason=reason,
            extraction=extraction, trace=trace,
            analyst_evaluation=analyst_evaluation,
        )

    def _not_found(self, cve_id, detail, trace) -> AnalyzeResponse:
        trace.append(PipelineStepTrace(step="fetch_cve", status="rejected", detail=detail))
        return AnalyzeResponse(
            cve=CVEMetadata(cve_id=cve_id), chain=None, valid=False,
            review_reason=f"CVE not found: {detail}", trace=trace,
        )

    def _fetch_failed(self, cve_id, detail, trace) -> AnalyzeResponse:
        trace.append(PipelineStepTrace(step="fetch_cve", status="rejected", detail=detail))
        return AnalyzeResponse(
            cve=CVEMetadata(cve_id=cve_id), chain=None, valid=False,
            review_reason=f"Could not fetch CVE: {detail}", trace=trace,
        )


def build_orchestrator(settings: Settings | None = None) -> Orchestrator:
    """Factory assembling an :class:`Orchestrator` with default components."""
    settings = settings or get_settings()
    return Orchestrator(
        settings=settings,
        nvd=NVDClient(settings),
        mapper=load_mapper(settings.cwe2bf_path),
        taxonomy=load_taxonomy(settings.taxonomy_path),
    )
