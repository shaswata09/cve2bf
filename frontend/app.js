/**
 * BF Tool frontend controller with explainable pipeline visualization.
 */

"use strict";

const API_PREFIX = "/api/v1";

// --- Taxonomic lookup dictionaries for explanations -----------------
const BF_CLASSES = {
  "DVL": { name: "Data Validation", desc: "Checking input data properties such as range, type, or format." },
  "DVR": { name: "Data Verification", desc: "Verifying data attributes against policies or expected constraints." },
  "MAD": { name: "Memory Addressing", desc: "Calculating, reassigning, or dereferencing memory pointers and positions." },
  "MMN": { name: "Memory Management", desc: "Allocation, reallocation, or deallocation of memory segments." },
  "MUS": { name: "Memory Use", desc: "Reading from or writing to initialized memory objects." },
  "DCL": { name: "Declaration", desc: "Declaring or defining data types, objects, or structures." },
  "NRS": { name: "Name Resolution", desc: "Binding variables or symbols to their actual data objects." },
  "TCV": { name: "Type Conversion", desc: "Casting or converting data from one type representation to another." },
  "TCM": { name: "Type Computation", desc: "Evaluating expressions or calculating numerical values." }
};

const FAILURE_CLASSES = {
  "IEX": { name: "Information Exposure", impact: "Confidentiality Loss" },
  "ACE": { name: "Arbitrary Code Execution", impact: "Integrity & Control Loss" },
  "DOS": { name: "Denial of Service", impact: "Availability Loss" },
  "TPR": { name: "Tampering", impact: "Integrity & Data Loss" }
};

// --- DOM element handles ---------------------------------------------
const el = (id) => document.getElementById(id);
const cveInput = el("cve-input");
const analyzeBtn = el("analyze-btn");
const statusEl = el("status");

let activeStep = 0;
let lastResponseData = null;

/** Set the status line with a severity class. */
function setStatus(message, kind = "idle") {
  statusEl.textContent = message;
  statusEl.className = `status-indicator ${kind}`;
  // Refresh indicator icon
  let iconName = "info";
  if (kind === "running") iconName = "loader";
  if (kind === "success") iconName = "check-circle";
  if (kind === "warning") iconName = "alert-triangle";
  if (kind === "error") iconName = "x-circle";
  
  statusEl.innerHTML = `<i data-lucide="${iconName}" class="alert-icon"></i> <span>${message}</span>`;
  lucide.createIcons();
}

/** Escape text for safe insertion into the DOM. */
function esc(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

/** Copy JSON to clipboard */
async function copyJson() {
  const jsonText = el("json-spec").textContent;
  if (!jsonText || jsonText === "\u2014") return;
  try {
    await navigator.clipboard.writeText(jsonText);
    const copyBtn = el("copy-json-btn");
    copyBtn.innerHTML = `<i data-lucide="check" class="btn-icon-sm"></i> <span>Copied!</span>`;
    lucide.createIcons();
    setTimeout(() => {
      copyBtn.innerHTML = `<i data-lucide="copy" class="btn-icon-sm"></i> <span>Copy</span>`;
      lucide.createIcons();
    }, 2000);
  } catch (err) {
    console.error("Failed to copy JSON: ", err);
  }
}

/** Wire up step navigation tabs click handler */
function initStepNavigation() {
  document.querySelectorAll(".step-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const stepIdx = parseInt(btn.getAttribute("data-step"));
      setActiveStep(stepIdx);
    });
  });
}

/** Change active step tab */
function setActiveStep(stepIdx) {
  activeStep = stepIdx;
  
  // Update step sidebar buttons
  document.querySelectorAll(".step-item").forEach((btn) => {
    const idx = parseInt(btn.getAttribute("data-step"));
    if (idx === stepIdx) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Update panels visibility
  document.querySelectorAll(".step-panel").forEach((panel, idx) => {
    if (idx === stepIdx) {
      panel.classList.add("active");
    } else {
      panel.classList.remove("active");
    }
  });
  
  lucide.createIcons();
}

/** Clear all output regions before a new run. */
function clearOutputs() {
  lastResponseData = null;
  el("meta-cvss").textContent = "\u2014";
  el("meta-severity").textContent = "\u2014";
  el("meta-severity").className = "meta-val badge";
  el("meta-vendor").textContent = "\u2014";
  el("meta-cwe").innerHTML = "&mdash;";
  el("meta-desc").textContent = "\u2014";
  el("offline-banner").classList.add("hidden");
  
  el("narrowing-cwe-list").innerHTML = "";
  el("narrowing-bf-grid").innerHTML = "";
  el("narrowing-fallback-info").classList.add("hidden");
  
  el("skeletons-count").textContent = "0";
  el("skeletons-list").innerHTML = "";
  
  el("attempts-list").innerHTML = "";
  el("chain-flow-graph").innerHTML = "";
  el("generated-desc").textContent = "\u2014";
  el("json-spec").textContent = "\u2014";
  
  // Set all status dots back to pending
  document.querySelectorAll(".step-status-dot").forEach((dot) => {
    dot.className = "step-status-dot pending";
  });
  
  // Reset CVSS Gauge
  updateCvssCircle(0);
}

/** Update the CVSS SVG Circle progress bar */
function updateCvssCircle(score) {
  const circle = el("cvss-circle-progress");
  if (!circle) return;
  const val = Math.max(0, Math.min(10, score));
  // Circle perimeter = 2 * pi * r (r=50) = 314.159
  const offset = 314.159 - (val / 10 * 314.159);
  circle.style.strokeDashoffset = offset;
  
  // Color code CVSS
  if (val >= 9.0) {
    circle.style.stroke = "var(--color-error)";
  } else if (val >= 7.0) {
    circle.style.stroke = "#fb923c"; // Orange
  } else if (val >= 4.0) {
    circle.style.stroke = "var(--color-warning)";
  } else {
    circle.style.stroke = "var(--color-success)";
  }
}

/** Run analysis for the current CVE id. */
async function analyze() {
  const cveId = cveInput.value.trim().toUpperCase();
  if (!cveId) {
    setStatus("Enter a CVE ID.", "error");
    return;
  }

  analyzeBtn.disabled = true;
  setStatus("Analyzing pipeline...", "running");
  clearOutputs();
  setActiveStep(0);

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
    lastResponseData = data;
    renderResponse(data);
  } catch (err) {
    setStatus(err.message, "error");
  } finally {
    analyzeBtn.disabled = false;
  }
}

/** Render the full analyze response and explain each step. */
function renderResponse(data) {
  // Update step status dots based on trace
  updateSidebarStatus(data.trace, data.valid);

  // Render Step 1: Ingest
  renderIngest(data.cve);

  // Render Step 2: Narrowing
  renderNarrowing(data.trace);

  // Render Step 3: Skeletons
  renderSkeletons(data.trace);

  // Render Step 4: LLM Solve & Verify
  renderSolveAttempts(data.trace);

  // Render Step 5: Final Spec
  renderFinalSpecification(data);

  if (data.valid && data.chain) {
    const src = data.extraction ? data.extraction.source : "unknown";
    setStatus(`BF Chain generated successfully (${data.chain.weaknesses.length} weaknesses, extraction: ${src}).`, "success");
    // Switch to step 5 on success
    setActiveStep(4);
  } else {
    setStatus(data.review_reason || "Validation failed - human review required.", "warning");
    // Switch to step 4 to show validation failures
    setActiveStep(3);
  }
}

/** Map trace details to sidebar dot statuses */
function updateSidebarStatus(trace, valid) {
  const dots = document.querySelectorAll(".step-status-dot");
  
  // Step 1: Ingest (fetch_cve)
  const fetchTrace = (trace || []).find(t => t.step === "fetch_cve");
  if (fetchTrace) {
    dots[0].className = `step-status-dot ${fetchTrace.status === "rejected" ? "err" : "ok"}`;
  }
  
  // Step 2: Narrow (cwe_narrowing)
  const narrowTrace = (trace || []).find(t => t.step === "cwe_narrowing");
  if (narrowTrace) {
    dots[1].className = `step-status-dot ${narrowTrace.status === "fallback" ? "warn" : narrowTrace.status === "rejected" ? "err" : "ok"}`;
  }

  // Step 3: Skeletons (backward_tree)
  const treeTrace = (trace || []).find(t => t.step === "backward_tree");
  if (treeTrace) {
    dots[2].className = `step-status-dot ${treeTrace.status === "rejected" ? "err" : "ok"}`;
  }

  // Step 4: Solve & Verify (extract_validate)
  const attempts = (trace || []).filter(t => t.step === "extract_validate");
  if (attempts.length > 0) {
    const hasSuccess = attempts.some(t => t.status === "ok");
    dots[3].className = `step-status-dot ${hasSuccess ? "ok" : "err"}`;
  }

  // Step 5: Output
  dots[4].className = `step-status-dot ${valid ? "ok" : "warn"}`;
}

/** Step 1: Populate Ingest Panel */
function renderIngest(cve) {
  const score = cve.cvss_score != null ? cve.cvss_score : 0;
  el("meta-cvss").textContent = cve.cvss_score != null ? score.toFixed(1) : "\u2014";
  
  const sev = cve.cvss_severity || "UNKNOWN";
  const sevEl = el("meta-severity");
  sevEl.textContent = sev;
  sevEl.className = `meta-val badge ${sev.toLowerCase()}`;
  
  el("meta-vendor").textContent =
    cve.vendor_project || cve.product ? `${cve.vendor_project || ""}:${cve.product || ""}` : "\u2014";
  
  const cweContainer = el("meta-cwe");
  cweContainer.innerHTML = "";
  if (cve.cwe_ids && cve.cwe_ids.length > 0) {
    cve.cwe_ids.forEach(cwe => {
      const span = document.createElement("span");
      span.className = "tag highlight";
      span.textContent = cwe;
      cweContainer.appendChild(span);
    });
  } else {
    cweContainer.textContent = "\u2014";
  }

  el("meta-desc").textContent = cve.description || "\u2014";
  
  if (cve.from_fixture) {
    el("offline-banner").classList.remove("hidden");
  } else {
    el("offline-banner").classList.add("hidden");
  }

  updateCvssCircle(score);
}

/** Step 2: Populate Narrowing Panel */
function renderNarrowing(trace) {
  const narrowTrace = (trace || []).find(t => t.step === "cwe_narrowing");
  if (!narrowTrace) return;
  
  // Show fallback info warning if trace status is fallback
  if (narrowTrace.status === "fallback") {
    el("narrowing-fallback-info").classList.remove("hidden");
  } else {
    el("narrowing-fallback-info").classList.add("hidden");
  }

  // Parse mapped CWEs and candidate classes from detail string
  // Detail format: classes=['DVR', 'MAD', 'MUS']
  const cweListEl = el("narrowing-cwe-list");
  cweListEl.innerHTML = "";
  
  // Fetch CWE list from fetch_cve details or ingest
  const fetchTrace = (trace || []).find(t => t.step === "fetch_cve");
  let cwes = [];
  if (fetchTrace && fetchTrace.detail) {
    const cweMatches = fetchTrace.detail.match(/CWEs=\[?(.*?)\]?,/);
    if (cweMatches && cweMatches[1]) {
      cwes = cweMatches[1].replace(/['"\s]/g, "").split(",").filter(Boolean);
    }
  }
  
  if (cwes.length === 0) {
    cwes = ["Unknown CWE"];
  }
  
  cwes.forEach(cwe => {
    const cweTag = document.createElement("div");
    cweTag.className = "tag highlight";
    cweTag.textContent = cwe;
    cweListEl.appendChild(cweTag);
  });

  // Extract classes
  const classesMatch = narrowTrace.detail.match(/classes=\[?(.*?)\]?$/);
  let classes = [];
  if (classesMatch && classesMatch[1]) {
    classes = classesMatch[1].replace(/['"\s]/g, "").split(",").filter(Boolean);
  }

  const bfGridEl = el("narrowing-bf-grid");
  bfGridEl.innerHTML = "";
  
  classes.forEach(cls => {
    const classInfo = BF_CLASSES[cls] || { name: "Unknown BF Class", desc: "Bugs Framework class taxonomy segment." };
    const card = document.createElement("div");
    card.className = "bf-class-card";
    card.innerHTML = `
      <div class="flex-row justify-between align-center">
        <span class="bf-class-name">${esc(classInfo.name)}</span>
        <span class="bf-class-badge">${esc(cls)}</span>
      </div>
      <span class="bf-class-desc">${esc(classInfo.desc)}</span>
    `;
    bfGridEl.appendChild(card);
  });
}

/** Step 3: Populate Skeletons Panel */
function renderSkeletons(trace) {
  const treeTrace = (trace || []).find(t => t.step === "backward_tree");
  if (!treeTrace) return;
  
  const detail = treeTrace.detail || "";
  const countMatch = detail.match(/^(\d+)/);
  const skeletonCount = countMatch ? parseInt(countMatch[1]) : 0;
  
  el("skeletons-count").textContent = skeletonCount;
  
  // Extract tested skeletons from validation trace attempts
  const attempts = (trace || []).filter(t => t.step === "extract_validate");
  const listEl = el("skeletons-list");
  listEl.innerHTML = "";
  
  const renderedPaths = new Set();
  
  attempts.forEach(att => {
    // Detail format: attempt=0, chain=MUS->DVR, source=vllm, using_vllm=True
    // or attempt=0: weakness[0]...
    const chainMatch = att.detail.match(/chain=([A-Za-z0-9->]+)/);
    if (chainMatch && chainMatch[1]) {
      const path = chainMatch[1];
      if (renderedPaths.has(path)) return;
      renderedPaths.add(path);
      
      const pathItem = document.createElement("div");
      pathItem.className = "skeleton-item";
      
      const pathContainer = document.createElement("div");
      pathContainer.className = "skeleton-path";
      
      const nodes = path.split("->");
      nodes.forEach((node, nodeIdx) => {
        const clsSpan = document.createElement("span");
        clsSpan.className = "sk-class";
        clsSpan.textContent = node;
        clsSpan.title = (BF_CLASSES[node] || {}).name || "";
        pathContainer.appendChild(clsSpan);
        
        if (nodeIdx < nodes.length - 1) {
          const arrow = document.createElement("span");
          arrow.className = "sk-arrow";
          arrow.textContent = "\u2192";
          pathContainer.appendChild(arrow);
        }
      });
      
      pathItem.appendChild(pathContainer);
      
      // Mapped terminal final error info
      const finalErrorSpan = document.createElement("span");
      finalErrorSpan.className = "sk-final";
      finalErrorSpan.textContent = "Final Spec";
      pathItem.appendChild(finalErrorSpan);
      
      listEl.appendChild(pathItem);
    }
  });
  
  if (listEl.children.length === 0) {
    const emptyItem = document.createElement("div");
    emptyItem.className = "text-muted text-sm text-center py-4";
    emptyItem.textContent = "No validated paths traced yet.";
    listEl.appendChild(emptyItem);
  }
}

/** Step 4: Populate attempts log and validation sequence details */
function renderSolveAttempts(trace) {
  const attempts = (trace || []).filter(t => t.step === "extract_validate");
  const container = el("attempts-list");
  container.innerHTML = "";
  
  attempts.forEach((att, idx) => {
    const item = document.createElement("div");
    item.className = `attempt-item ${att.status === "ok" ? "ok" : "rejected"}`;
    
    // Parse chain if available in detail
    const chainMatch = att.detail.match(/chain=([A-Za-z0-9->]+)/);
    const pathString = chainMatch ? `Chain: ${chainMatch[1]}` : `Attempt ${idx + 1}`;
    
    const statusText = att.status === "ok" ? "Validated" : "Rejected";
    const statusClass = att.status === "ok" ? "ok" : "rejected";
    
    // Format details - split validation errors by semicolon to render neatly
    let detailsHtml = "";
    if (att.status === "ok") {
      detailsHtml = `<div class="attempt-details">${esc(att.detail)}</div>`;
    } else {
      // Split the list of errors
      // Detail looks like: attempt=0: weakness[0] (DVR)... ; weakness[1] (MAD)...
      const errorsPart = att.detail.includes(":") ? att.detail.substring(att.detail.indexOf(":") + 1).trim() : att.detail;
      const errorItems = errorsPart.split(";").map(err => err.trim()).filter(Boolean);
      
      detailsHtml = `<div class="attempt-details error"><ul>`;
      errorItems.forEach(err => {
        detailsHtml += `<li>${esc(err)}</li>`;
      });
      detailsHtml += `</ul></div>`;
    }
    
    item.innerHTML = `
      <div class="attempt-header">
        <span class="attempt-title">${esc(pathString)}</span>
        <span class="attempt-badge ${statusClass}">${statusText}</span>
      </div>
      ${detailsHtml}
    `;
    container.appendChild(item);
  });
  
  if (attempts.length === 0) {
    const emptyMsg = document.createElement("p");
    emptyMsg.className = "text-muted text-sm";
    emptyMsg.textContent = "No attempts recorded.";
    container.appendChild(emptyMsg);
  }
}

/** Step 5: Render final visual weakness flow diagram and output raw code */
function renderFinalSpecification(data) {
  const graphContainer = el("chain-flow-graph");
  graphContainer.innerHTML = "";
  
  // Render AI analyst report card if present
  const analystCard = el("analyst-report-card");
  if (data.analyst_evaluation && data.analyst_evaluation.justification) {
    analystCard.classList.remove("hidden");
    el("analyst-justification").textContent = data.analyst_evaluation.justification;
  } else {
    analystCard.classList.add("hidden");
  }
  
  if (!data.valid || !data.chain) {
    // Clear narrative/JSON
    el("generated-desc").textContent = "\u2014";
    el("json-spec").textContent = "\u2014";
    
    const suggested = data.analyst_evaluation ? data.analyst_evaluation.suggested_chain : [];
    if (suggested && suggested.length > 0) {
      const n = suggested.length;
      suggested.forEach((cls, idx) => {
        const card = document.createElement("div");
        card.className = "weakness-card suggested";
        const classInfo = BF_CLASSES[cls] || { name: cls, desc: "Bugs Framework class." };
        card.innerHTML = `
          <div class="weakness-card-header">
            <h4>Weakness ${idx + 1} (Suggested)</h4>
            <span class="weakness-class-tag">${esc(cls)}</span>
          </div>
          <div class="weakness-card-body">
            <div class="row-slot">
              <span class="slot-lbl">Class Description</span>
              <span class="slot-val highlight" style="font-size: 11px;">${esc(classInfo.name)}: ${esc(classInfo.desc)}</span>
            </div>
            <div class="row-slot">
              <span class="slot-lbl">Constraint Status</span>
              <span class="slot-val" style="color: var(--color-warning); font-size: 10px;">Failed formal verification (AI analyst predicted)</span>
            </div>
          </div>
        `;
        graphContainer.appendChild(card);
        
        if (idx < n - 1) {
          const arrow = document.createElement("div");
          arrow.className = "connector-arrow suggested";
          arrow.innerHTML = `
            <span class="arrow-label">Propagates</span>
            <div class="arrow-line"></div>
            <span class="arrow-badge">Transition Predicted</span>
          `;
          graphContainer.appendChild(arrow);
        } else {
          // Terminal Failure connector
          const arrow = document.createElement("div");
          arrow.className = "connector-arrow suggested";
          arrow.innerHTML = `
            <span class="arrow-label">Enables</span>
            <div class="arrow-line"></div>
          `;
          graphContainer.appendChild(arrow);
          
          // FAILURE CARD
          const failClass = (data.cve && data.cve.cwe_ids && data.cve.cwe_ids.includes("CWE-125")) ? "IEX" : "DOS";
          const failInfo = FAILURE_CLASSES[failClass] || { name: "Security Failure", impact: "Vulnerability impact" };
          
          const failCard = document.createElement("div");
          failCard.className = "failure-card suggested";
          failCard.style.borderColor = "rgba(251, 191, 36, 0.25)";
          failCard.style.background = "rgba(251, 191, 36, 0.02)";
          failCard.innerHTML = `
            <div class="failure-card-header" style="background: rgba(251, 191, 36, 0.05); border-color: rgba(251, 191, 36, 0.1);">
              <h4 style="color: var(--color-warning);">Failure (Suggested)</h4>
              <span class="failure-class-tag" style="background: rgba(251, 191, 36, 0.1); color: var(--color-warning); border-color: rgba(251, 191, 36, 0.2);">${esc(failClass)}</span>
            </div>
            <div class="weakness-card-body">
              <div class="row-slot">
                <span class="slot-lbl">Class</span>
                <span class="slot-val" style="color: var(--color-warning); font-weight: 600;">${esc(failInfo.name)}</span>
              </div>
              <div class="row-slot">
                <span class="slot-lbl">Impact</span>
                <span class="slot-val">${esc(failInfo.impact)}</span>
              </div>
            </div>
          `;
          graphContainer.appendChild(failCard);
        }
      });
    } else {
      // Show Review Required State
      graphContainer.innerHTML = `
        <div class="flex-col gap-12 align-center justify-center py-4" style="width: 100%; text-align: center;">
          <i data-lucide="alert-octagon" style="color: var(--color-warning); width: 48px; height: 48px;"></i>
          <h3 style="color: var(--color-warning);">Human Review Required</h3>
          <p class="text-sm text-muted">${esc(data.review_reason || "No candidate weakness chain passed validation rules.")}</p>
        </div>
      `;
    }
    return;
  }
  
  const chain = data.chain;
  const n = chain.weaknesses.length;
  
  chain.weaknesses.forEach((w, idx) => {
    // RENDER WEAKNESS CARD
    const card = document.createElement("div");
    card.className = "weakness-card";
    
    // Header
    const classInfo = BF_CLASSES[w.bf_class] || { name: w.bf_class };
    card.innerHTML = `
      <div class="weakness-card-header">
        <h4>Weakness ${idx + 1}</h4>
        <span class="weakness-class-tag" title="${esc(classInfo.desc)}">${esc(w.bf_class)}</span>
      </div>
    `;
    
    // Body
    const body = document.createElement("div");
    body.className = "weakness-card-body";
    
    // Cause/Fault
    const causeLabel = w.cause.kind === "bug" ? "Bug/Fault" : "Fault Cause";
    const causeBadge = w.cause.kind === "bug" ? "bug" : "fault";
    body.innerHTML += `
      <div class="row-slot">
        <span class="slot-lbl">${causeLabel}</span>
        <span class="slot-val highlight">${esc(w.cause.value)}</span>
      </div>
    `;
    
    // Operation
    body.innerHTML += `
      <div class="row-slot">
        <span class="slot-lbl">Operation</span>
        <span class="slot-val">${esc(w.operation)}</span>
      </div>
    `;
    
    // Consequence
    const consLabel = idx === n - 1 ? "Final Error" : "Error Consequence";
    body.innerHTML += `
      <div class="row-slot">
        <span class="slot-lbl">${consLabel}</span>
        <span class="slot-val highlight">${esc(w.consequence.value)}</span>
      </div>
    `;
    
    // Operands
    if (w.operands && w.operands.length > 0) {
      let opsText = w.operands.map(op => {
        let opDesc = op.name;
        if (op.attributes && Object.keys(op.attributes).length > 0) {
          opDesc += ` (${Object.entries(op.attributes).map(([k,v]) => `${k}:${v}`).join(", ")})`;
        }
        return opDesc;
      }).join(", ");
      
      body.innerHTML += `
        <div class="row-slot">
          <span class="slot-lbl">Operands</span>
          <span class="slot-val" style="font-family: monospace; font-size: 10px;">${esc(opsText)}</span>
        </div>
      `;
    }
    
    card.appendChild(body);
    graphContainer.appendChild(card);
    
    // CONNECTORS
    if (idx < n - 1) {
      // Weakness to Weakness connector shows consequence propagating as cause
      const nextWeakness = chain.weaknesses[idx + 1];
      const arrow = document.createElement("div");
      arrow.className = "connector-arrow";
      arrow.innerHTML = `
        <span class="arrow-label">Propagates</span>
        <div class="arrow-line"></div>
        <span class="arrow-badge" title="Propagated fault trigger">${esc(nextWeakness.cause.value)}</span>
      `;
      graphContainer.appendChild(arrow);
    } else {
      // Terminal Failure connector
      const arrow = document.createElement("div");
      arrow.className = "connector-arrow";
      arrow.innerHTML = `
        <span class="arrow-label">Enables</span>
        <div class="arrow-line" style="background: var(--color-error);"></div>
      `;
      // Fix arrow styling color for terminal failure
      arrow.querySelector(".arrow-line").style.setProperty("--color-accent", "var(--color-error)");
      graphContainer.appendChild(arrow);
      
      // FAILURE CARD
      const failCard = document.createElement("div");
      failCard.className = "failure-card";
      
      const failInfo = FAILURE_CLASSES[chain.failure.failure_class] || { name: chain.failure.failure_class };
      failCard.innerHTML = `
        <div class="failure-card-header">
          <h4>Failure</h4>
          <span class="failure-class-tag">${esc(chain.failure.failure_class)}</span>
        </div>
        <div class="weakness-card-body">
          <div class="row-slot">
            <span class="slot-lbl">Class</span>
            <span class="slot-val" style="color: var(--color-error); font-weight: 600;">${esc(failInfo.name)}</span>
          </div>
          <div class="row-slot">
            <span class="slot-lbl">Impact</span>
            <span class="slot-val">${esc(chain.failure.impact)}</span>
          </div>
        </div>
      `;
      graphContainer.appendChild(failCard);
    }
  });
  
  // Update texts
  el("generated-desc").textContent = chain.generated_description || "\u2014";
  el("json-spec").textContent = JSON.stringify(data.chain, null, 2);
}

// --- Wire up listeners ------------------------------------------------
analyzeBtn.addEventListener("click", analyze);
cveInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyze();
});
el("copy-json-btn").addEventListener("click", copyJson);

// --- Initialization --------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  initStepNavigation();
  lucide.createIcons();
});
