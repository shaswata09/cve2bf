"""End-to-end tests for the orchestrator and HTTP API (offline)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.orchestrator import build_orchestrator


def test_orchestrator_heartbleed_end_to_end(settings):
    result = build_orchestrator(settings).analyze("CVE-2014-0160")
    assert result.valid, result.review_reason
    assert result.chain is not None
    assert result.chain.class_sequence == ["DVR", "MAD", "MUS"]
    assert result.chain.failure.failure_class == "IEX"
    # Offline test uses the deterministic fallback.
    assert result.extraction.source == "deterministic"
    # Every step recorded a trace entry.
    steps = {t.step for t in result.trace}
    assert {"fetch_cve", "cwe_narrowing", "backward_tree", "extract_validate"} <= steps


def test_orchestrator_unknown_cve_offline():
    # Not in fixtures and offline -> not found, routed to review.
    result = build_orchestrator().analyze("CVE-1999-0001")
    assert not result.valid
    assert result.review_reason


def test_api_analyze_endpoint():
    client = TestClient(app)
    resp = client.post("/api/v1/analyze", json={"cve_id": "CVE-2014-0160"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert [w["bf_class"] for w in body["chain"]["weaknesses"]] == ["DVR", "MAD", "MUS"]


def test_api_health_endpoint():
    client = TestClient(app)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_rejects_bad_cve_id():
    client = TestClient(app)
    resp = client.post("/api/v1/analyze", json={"cve_id": "not-a-cve"})
    assert resp.status_code == 422  # pydantic validation error


def test_api_taxonomy_endpoint():
    client = TestClient(app)
    resp = client.get("/api/v1/taxonomy")
    assert resp.status_code == 200
    assert "MAD" in resp.json()["classes"]
