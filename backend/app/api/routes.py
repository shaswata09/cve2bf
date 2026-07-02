"""HTTP routes for the CVE2BF platform.

Endpoints
---------
``POST {prefix}/analyze``   Run the pipeline for a CVE id and return a BF chain.
``GET  {prefix}/health``    Liveness plus vLLM reachability and taxonomy version.
``GET  {prefix}/taxonomy``  Return the taxonomy (for populating UI dropdowns).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_orchestrator
from app.config import get_settings
from app.llm.vllm_client import VLLMClient
from app.models.api_schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from app.rule_engine.taxonomy import load_taxonomy
from app.services.orchestrator import Orchestrator

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze a CVE into a BF chain")
def analyze(
    request: AnalyzeRequest,
    orchestrator: Orchestrator = Depends(get_orchestrator),
) -> AnalyzeResponse:
    """Fetch ``request.cve_id`` and return its validated BF chain (or a review flag)."""
    return orchestrator.analyze(request.cve_id)


@router.get("/health", response_model=HealthResponse, summary="Service health")
def health() -> HealthResponse:
    """Report liveness, taxonomy version and whether vLLM is reachable."""
    settings = get_settings()
    taxonomy = load_taxonomy(settings.taxonomy_path)
    vllm_reachable = VLLMClient(settings).is_reachable()
    return HealthResponse(
        status="ok",
        taxonomy_version=taxonomy.version,
        vllm_reachable=vllm_reachable,
    )


@router.get("/taxonomy", summary="Return the BF taxonomy")
def taxonomy() -> dict:
    """Return the raw taxonomy document for UI dropdowns and reference."""
    settings = get_settings()
    tax = load_taxonomy(settings.taxonomy_path)
    return {
        "version": tax.version,
        "classes": {
            code: {
                "name": tax.get_class(code).name,
                "cluster": tax.get_class(code).cluster,
                "operations": list(tax.get_class(code).operations),
            }
            for code in tax.classes()
        },
        "failure_classes": tax.failure_classes(),
    }
