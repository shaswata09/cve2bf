/**
 * BF Tool frontend controller.
 *
 * Responsibilities:
 *   - read a CVE id from the input,
 *   - POST it to the analyze endpoint,
 *   - render the returned BF chain into the weakness panels, the chain
 *     sidebar, the failure list, the generated description and the trace.
 *
 * The UI is a thin view over the API: all BF logic lives on the backend.
 */

"use strict";

const API_PREFIX = "/api/v1";

// --- element handles --------------------------------------------------
const el = (id) => document.getElementById(id);
const cveInput = el("cve-input");
const analyzeBtn = el("analyze-btn");
const statusEl = el("status");

/** Set the status line with a severity class. */
function setStatus(message, kind = "") {
  statusEl.textContent = message;
  statusEl.className = `status ${kind}`;
}

/** Escape text for safe insertion into the DOM. */
function esc(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

/** Run analysis for the current CVE id. */
async function analyze() {
  const cveId = cveInput.value.trim().toUpperCase();
  if (!cveId) {
    setStatus("Enter a CVE id.", "err");
    return;
  }

  analyzeBtn.disabled = true;
  setStatus("Analyzing\u2026");
  clearOutputs();

  try {
    const resp = await fetch(`${API_PREFIX}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: cveId }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.detail || `Request failed (${resp.status})`);
    }
    const data = await resp.json();
    renderResponse(data);
  } catch (err) {
    setStatus(err.message, "err");
  } finally {
    analyzeBtn.disabled = false;
  }
}

/** Clear all output regions before a new run. */
function clearOutputs() {
  el("weaknesses").innerHTML = "";
  el("bf-chain").innerHTML = "";
  el("bf-failure").innerHTML = "";
  el("generated-desc").textContent = "\u2014";
  el("trace-table").querySelector("tbody").innerHTML = "";
  el("extraction-meta").textContent = "";
  ["cvss", "severity", "vendor", "cwe", "desc"].forEach((k) => {
    el(`meta-${k}`).textContent = "\u2014";
  });
}

/** Render the full analyze response. */
function renderResponse(data) {
  renderCveMeta(data.cve);
  renderTrace(data.trace, data.extraction);

  if (!data.valid || !data.chain) {
    setStatus(data.review_reason || "No valid chain \u2014 manual review required.", "warn");
    return;
  }

  const chain = data.chain;
  renderChainSidebar(chain);
  renderWeaknesses(chain);
  el("generated-desc").textContent = chain.generated_description || "\u2014";

  const src = data.extraction ? data.extraction.source : "unknown";
  setStatus(`Chain generated (${chain.weaknesses.length} weaknesses, extraction: ${src}).`, "ok");
}

/** Populate the CVE metadata fields. */
function renderCveMeta(cve) {
  el("meta-cvss").textContent = cve.cvss_score != null ? cve.cvss_score : "\u2014";
  el("meta-severity").textContent = cve.cvss_severity || "\u2014";
  el("meta-vendor").textContent =
    cve.vendor_project || cve.product ? `${cve.vendor_project || ""}:${cve.product || ""}` : "\u2014";
  el("meta-cwe").textContent = (cve.cwe_ids || []).join(", ") || "\u2014";
  el("meta-desc").textContent = cve.description || "\u2014";
}

/** Render the left-hand BF chain and failure lists. */
function renderChainSidebar(chain) {
  const chainList = el("bf-chain");
  chain.weaknesses.forEach((w) => {
    const li = document.createElement("li");
    li.className = "active";
    li.textContent = w.bf_class;
    chainList.appendChild(li);
  });

  const failureList = el("bf-failure");
  const li = document.createElement("li");
  li.className = "active";
  li.textContent = `${chain.failure.failure_class} (${chain.failure.impact})`;
  failureList.appendChild(li);
}

/** Render one panel per weakness using the template. */
function renderWeaknesses(chain) {
  const host = el("weaknesses");
  const template = el("weakness-template");
  const n = chain.weaknesses.length;

  chain.weaknesses.forEach((w, idx) => {
    const node = template.content.cloneNode(true);
    node.querySelector(".weakness-title").textContent = `BF Weakness ${idx + 1}`;
    node.querySelector(".class-value").textContent = w.bf_class;

    const causeLabel = w.cause.kind === "bug" ? "Bug" : "Fault";
    node.querySelector(".cause-label").textContent = causeLabel;
    node.querySelector(".cause-value").textContent = w.cause.value;
    node.querySelector(".cause-value").classList.add("highlight");

    node.querySelector(".op-value").textContent = w.operation;
    node.querySelector(".op-value").classList.add("highlight");

    const consLabel = idx === n - 1 ? "Final Error" : "Error";
    node.querySelector(".cons-label").textContent = consLabel;
    node.querySelector(".cons-value").textContent = w.consequence.value;
    node.querySelector(".cons-value").classList.add("highlight");

    renderOperands(node.querySelector(".operands"), w.operands);
    renderAttrs(node.querySelector(".attrs"), w.operation_attributes);
    host.appendChild(node);
  });
}

/** Render operands and their attributes into a container. */
function renderOperands(container, operands) {
  if (!operands || operands.length === 0) return;
  const heading = document.createElement("h4");
  heading.textContent = "Operands";
  container.appendChild(heading);
  operands.forEach((op) => {
    const name = document.createElement("div");
    name.className = "operand-name";
    name.textContent = op.name;
    container.appendChild(name);
    Object.entries(op.attributes || {}).forEach(([k, v]) => {
      container.appendChild(kvRow(k, v));
    });
  });
}

/** Render operation attributes. */
function renderAttrs(container, attrs) {
  const entries = Object.entries(attrs || {});
  if (entries.length === 0) return;
  const heading = document.createElement("h4");
  heading.textContent = "Operation Attributes";
  container.appendChild(heading);
  entries.forEach(([k, v]) => container.appendChild(kvRow(k, v)));
}

/** Build a key/value row element. */
function kvRow(key, value) {
  const row = document.createElement("div");
  row.className = "kv";
  row.innerHTML = `<span class="k">${esc(key)}</span><span class="v">${esc(value)}</span>`;
  return row;
}

/** Render the pipeline trace table and extraction provenance. */
function renderTrace(trace, extraction) {
  const tbody = el("trace-table").querySelector("tbody");
  (trace || []).forEach((t) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(t.step)}</td><td>${esc(t.status)}</td><td>${esc(t.detail)}</td>`;
    tbody.appendChild(tr);
  });
  if (extraction) {
    el("extraction-meta").textContent =
      `Extraction source: ${extraction.source}` + (extraction.model ? ` (model: ${extraction.model})` : "");
  }
}

// --- wire up ----------------------------------------------------------
analyzeBtn.addEventListener("click", analyze);
cveInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyze();
});
