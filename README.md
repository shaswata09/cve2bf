# CVE2BF Platform

Deterministic **CVE → Bugs Framework (BF) chain** generation. Enter a CVE id in
the UI (or call the API); the platform fetches the CVE from NVD and produces a
formally-validated BF weakness chain — the `(cause, operation) → consequence`
triples that lead to the security failure — reproducing the NIST *BF Tool*
workflow.

The design keeps the non-deterministic part (reading CVE prose) as small as
possible and pushes everything else into a deterministic rule engine grounded in
NIST SP 800-231.

---

## How it works

The pipeline runs six steps; only step 3 uses a language model, and even that is
constrained to enumerated choices and re-checked by a deterministic gate:

| Step | Component | Deterministic? |
|------|-----------|----------------|
| 0 Fetch CVE | `services/nvd_client.py` | yes (NVD REST) |
| 1 CWE → BF narrowing | `rule_engine/cwe2bf.py` | yes (table lookup) |
| 2 Backward state tree | `rule_engine/backward_tree.py` | yes (graph search) |
| 3 Constrained slot-filling | `llm/extractor.py` + `llm/vllm_client.py` | **LLM**, enum-constrained |
| 4 Validate chain | `rule_engine/validator.py` | yes (LL(1)-style grammar) |
| 5–6 Assemble + describe | `rule_engine/chain_builder.py` | yes |

The **taxonomy** (`app/data/bf_taxonomy.json`) and **CWE→BF map**
(`app/data/cwe2bf.json`) are the knowledge base. The LLM proposes; the validator
disposes. If no candidate chain passes validation, the response is flagged for
human review rather than returning an unvalidated guess.

```
frontend/  ── static BF Tool UI (calls the API)
backend/
  app/
    api/         HTTP routes + dependencies
    models/      Pydantic domain + API schemas
    services/    NVD client, orchestrator (state machine)
    rule_engine/ taxonomy, cwe2bf, backward tree, validator, chain builder
    llm/         vLLM client, schema builder, extractor (+ deterministic fallback)
    data/        BF taxonomy + CWE→BF mapping (JSON knowledge base)
  tests/         28 unit + end-to-end tests
```

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the API + UI (one process). Open http://localhost:9000
uvicorn app.main:app --reload --port 9000
```

Enter `CVE-2014-0160` (Heartbleed) and click **Generate BF Chain**. It works out
of the box using the bundled offline fixture and the deterministic extractor.

## Connecting your vLLM server

Serve any instruct model with vLLM's OpenAI-compatible API:

```bash
vllm serve meta-llama/Llama-3.1-8B-Instruct --port 8000
```

Then point the platform at it:

```bash
export CVE2BF_VLLM_BASE_URL=http://localhost:8000/v1
export CVE2BF_VLLM_MODEL=meta-llama/Llama-3.1-8B-Instruct
```

Extraction uses vLLM **structured output** (`guided_json`) so the model can only
emit values from the taxonomy enums. If the server is unreachable, the platform
automatically falls back to the deterministic extractor (set
`CVE2BF_VLLM_FALLBACK_ENABLED=false` to require vLLM instead). Structured output
requires a recent vLLM (0.6+) with the outlines/xgrammar backend.

See `backend/.env.example` for all settings (env prefix `CVE2BF_`).

## API

```
POST /api/v1/analyze   {"cve_id": "CVE-2014-0160"}  → BF chain + provenance trace
GET  /api/v1/health                                 → status, taxonomy version, vLLM reachable
GET  /api/v1/taxonomy                               → taxonomy for UI dropdowns
```

Interactive docs at `http://localhost:9000/docs`.

## Batch / dataset generation

```bash
python -m app.cli --cve CVE-2014-0160 --cve CVE-2021-3711 --out results.jsonl
python -m app.cli --file cves.txt --out results.jsonl
```

## Tests

```bash
cd backend && pytest
```

The suite is hermetic (offline NVD fixtures, vLLM assumed down) and covers the
taxonomy, narrowing, backward tree, validator, chain builder, orchestrator and
the HTTP API.

## Docker

```bash
docker compose up --build      # serves on :9000
```

Point `CVE2BF_VLLM_BASE_URL` at your vLLM host (GPU required for the model; the
app container itself is CPU-only and will use the deterministic fallback if the
model is absent).

## Notes on determinism

Given the same CVE text, taxonomy version and model, the output is reproducible.
For a CVE the backward tree admits several valid propagation labelings (e.g. a
DVR error of *Wrong Value* vs *Inconsistent Value*); the LLM step disambiguates
using the CVE description, and the deterministic fallback picks the
highest-scoring admissible chain. Either way the result is validated before it
is returned.

## Reference

Bojanova I. (2024). *Bugs Framework (BF): Formalizing Cybersecurity Weaknesses
and Vulnerabilities.* NIST SP 800-231.
