(function () {
  const I18N = window.ScanForgeI18n || { messages: {}, labels: {} };

  function formatTemplate(template, params) {
    return String(template).replace(/\{(\w+)\}/g, function (_match, key) {
      return Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : `{${key}}`;
    });
  }

  function t(text, params = {}) {
    return formatTemplate(I18N.messages?.[text] || text, params);
  }

  function valueLabel(group, value) {
    const labels = I18N.labels?.[group] || {};
    const key = String(value ?? "");
    return labels[key] || key;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function normalizeProjectKey(filename) {
    const normalized = String(filename || "").trim().toLowerCase();
    const suffixes = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar", ".gz", ".bz2", ".xz"];
    for (const suffix of suffixes) {
      if (normalized.endsWith(suffix) && normalized.length > suffix.length) {
        return normalized.slice(0, -suffix.length);
      }
    }
    return normalized;
  }

  function enabledChecks(job) {
    const checks = [];
    if (job.options?.run_functionality) checks.push("functionality");
    if (job.options?.run_security) checks.push("security");
    if (job.options?.run_style) checks.push("style");
    if (job.options?.run_quality) checks.push("quality");
    if (job.options?.run_fuzzing || job.mode === "fuzz_single" || job.mode === "fuzz_project") checks.push("fuzzing");
    return checks;
  }

  function statusClass(status) {
    return `status status-${status}`;
  }

  function setStatusBadge(element, status) {
    if (!element) return;
    element.className = statusClass(status);
    element.textContent = valueLabel("status", status);
  }

  function findingBadgeClass(severity) {
    if (severity === "critical" || severity === "high") return "status status-failed";
    if (severity === "medium") return "status status-running";
    return "status status-skipped";
  }

  function renderCheckTags(job) {
    return enabledChecks(job)
      .map((check) => `<span class="tag">${escapeHtml(valueLabel("check", check))}</span>`)
      .join("");
  }

  function renderArtifactButtons(job) {
    const buttons = [];
    if (job.html_report) {
      buttons.push(`<a class="button-secondary" href="/jobs/${job.id}/artifacts/${encodeURIComponent(job.html_report)}">${escapeHtml(t("HTML report"))}</a>`);
    }
    if (job.pdf_report) {
      buttons.push(`<a class="button-secondary" href="/jobs/${job.id}/artifacts/${encodeURIComponent(job.pdf_report)}">${escapeHtml(t("PDF report"))}</a>`);
    }
    for (const artifact of job.artifacts || []) {
      buttons.push(
        `<a class="button-secondary" href="/jobs/${job.id}/artifacts/${encodeURIComponent(artifact.filename)}">${escapeHtml(artifact.label)}</a>`
      );
    }
    if (job.status === "queued" || job.status === "running") {
      buttons.push(
        `<form action="/jobs/${job.id}/pause" method="post"><button type="submit">${escapeHtml(t("Pause"))}</button></form>`
      );
    }
    if (job.status === "paused") {
      buttons.push(
        `<form action="/jobs/${job.id}/resume" method="post"><button type="submit">${escapeHtml(t("Resume"))}</button></form>`
      );
    }
    if (job.status === "queued" || job.status === "paused") {
      buttons.push(
        `<form action="/jobs/${job.id}/queue/up" method="post"><button type="submit">${escapeHtml(t("Move up"))}</button></form>`
      );
      buttons.push(
        `<form action="/jobs/${job.id}/queue/down" method="post"><button type="submit">${escapeHtml(t("Move down"))}</button></form>`
      );
    }
    if (job.status === "queued" || job.status === "running") {
      buttons.push(
        `<form action="/jobs/${job.id}/cancel" method="post"><button type="submit">${escapeHtml(t("Cancel"))}</button></form>`
      );
    }
    buttons.push(`<a class="button-secondary" href="/jobs/${job.id}/rerun">${escapeHtml(t("Rerun"))}</a>`);
    return buttons.join("");
  }

  function renderDecisionSummary(job) {
    const summary = job.summaries || {};
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Risk score"))}</span>
        <strong>${escapeHtml(summary.risk_score ?? 0)}/100</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Highest severity"))}</span>
        <strong>${escapeHtml(valueLabel("severity", summary.highest_severity ?? "pending"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Execution verdict"))}</span>
        <strong>${escapeHtml(summary.execution_verdict ?? "pending")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Total findings"))}</span>
        <strong>${escapeHtml(summary.total_findings ?? 0)}</strong>
      </div>
    `;
  }

  function renderActions(job) {
    const actions = job.summaries?.next_actions || [];
    if (!actions.length) {
      return `<p class="empty-state">${escapeHtml(t("Recommended next actions will appear after report generation."))}</p>`;
    }
    return actions
      .map(
        (action) => `
          <article class="action-card">
            <strong>${escapeHtml(action.title)}</strong>
            <small>${escapeHtml(valueLabel("severity", action.severity))}</small>
            <p>${escapeHtml(action.recommendation)}</p>
          </article>
        `
      )
      .join("");
  }

  function renderReferenceCards(references, emptyMessage) {
    if (!references || !references.length) {
      return `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
    }
    return references
      .map(
        (reference) => `
          <article class="reference-item">
            <strong>${escapeHtml(reference.id)}</strong>
            <p>${escapeHtml(reference.title || reference.id)}</p>
            <small>${escapeHtml(reference.source || t("Local Knowledge Base"))}</small>
          </article>
        `
      )
      .join("");
  }

  function renderKnowledgeBaseSummary(job) {
    const kb = job.metadata?.knowledge_base || {};
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Mirror"))}</span>
        <strong>${escapeHtml(t(kb.available ? "ready" : "pending"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Sources"))}</span>
        <strong>${escapeHtml(kb.source_count ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Matched refs"))}</span>
        <strong>${escapeHtml(kb.matched_reference_count ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Project refs"))}</span>
        <strong>${escapeHtml(kb.project_reference_count ?? 0)}</strong>
      </div>
    `;
  }

  function renderHardwarePlan(job) {
    const host = job.metadata?.host_hardware || {};
    const plan = job.metadata?.execution_plan || {};
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("CPU budget"))}</span>
        <strong>${escapeHtml(plan.cpu_threads_for_job ?? 0)} / ${escapeHtml(host.cpu_threads_target ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("RAM budget"))}</span>
        <strong>${escapeHtml(plan.memory_mb_for_job ?? 0)} MB</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("GPU strategy"))}</span>
        <strong>${escapeHtml(plan.gpu_strategy || "pending")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Assigned GPUs"))}</span>
        <strong>${escapeHtml((plan.assigned_gpu_ids || []).join(", ") || "cpu-only")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Build threads"))}</span>
        <strong>${escapeHtml(plan.build_parallelism ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Suggested workers"))}</span>
        <strong>${escapeHtml(plan.suggested_worker_processes ?? 0)}</strong>
      </div>
    `;
  }

  function renderGpuInventory(job) {
    const host = job.metadata?.host_hardware || {};
    const gpus = host.gpus || [];
    if (!gpus.length) {
      return `<p class="empty-state">${escapeHtml(t("No GPU inventory was attached to this job. CPU/RAM adaptive planning is still active."))}</p>`;
    }
    return gpus
      .map(
        (gpu) => `
          <article class="reference-item">
            <strong>GPU ${escapeHtml(gpu.index)}</strong>
            <p>${escapeHtml(gpu.name || "Unknown GPU")}</p>
            <small>${escapeHtml(gpu.memory_total_mb || 0)} MB</small>
          </article>
        `
      )
      .join("");
  }

  function renderComparisonSummary(job) {
    const comparison = job.metadata?.comparison || {};
    const retestScope = valueLabel("retest_scope", job.options?.retest_scope === "changes_only" ? "changes_only" : "full_project");
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Scope"))}</span>
        <strong>${escapeHtml(retestScope)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Repeat submission"))}</span>
        <strong>${escapeHtml(t(job.metadata?.repeat_submission ? "yes" : "no"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Baseline job"))}</span>
        <strong>${escapeHtml(job.metadata?.baseline_job_id || t("none"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Changed files"))}</span>
        <strong>${escapeHtml(comparison.changed_file_count ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Changed text files"))}</span>
        <strong>${escapeHtml(comparison.changed_text_file_count ?? 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Removed files"))}</span>
        <strong>${escapeHtml((comparison.removed_files || []).length)}</strong>
      </div>
    `;
  }

  function renderComparisonFiles(job) {
    const comparison = job.metadata?.comparison || {};
    const changed = comparison.changed_files || [];
    const removed = comparison.removed_files || [];
    if (!changed.length && !removed.length) {
      if (job.metadata?.repeat_submission) {
        return `<p class="empty-state">${escapeHtml(t("This run is linked to a previous submission, but a file-level diff is not available yet."))}</p>`;
      }
      return `<p class="empty-state">${escapeHtml(t("This job is the first known submission for the selected project identity."))}</p>`;
    }
    const changedMarkup = changed.slice(0, 10).map((path) => `
      <article class="reference-item">
        <strong>${escapeHtml(t("Changed"))}</strong>
        <p>${escapeHtml(path)}</p>
      </article>
    `);
    const removedMarkup = removed.slice(0, 5).map((path) => `
      <article class="reference-item">
        <strong>${escapeHtml(t("Removed"))}</strong>
        <p>${escapeHtml(path)}</p>
      </article>
    `);
    return [...changedMarkup, ...removedMarkup].join("");
  }

  function renderAiReview(job) {
    const review = job.metadata?.ai_review || null;
    if (!review) {
      return `<p class="empty-state">${escapeHtml(t("AI review will appear during report generation."))}</p>`;
    }
    const blockers = (review.blockers || []).length
      ? review.blockers.map((item) => `<p>${escapeHtml(item)}</p>`).join("")
      : `<p>${escapeHtml(t("No blockers generated."))}</p>`;
    const quickWins = (review.quick_wins || []).length
      ? review.quick_wins.map((item) => `<p>${escapeHtml(item)}</p>`).join("")
      : `<p>${escapeHtml(t("No quick wins generated."))}</p>`;
    return `
      <div class="summary-grid">
        <div class="summary-card">
          <span>${escapeHtml(t("Source"))}</span>
          <strong>${escapeHtml(review.source || "unknown")}</strong>
        </div>
        <div class="summary-card">
          <span>${escapeHtml(t("Decision"))}</span>
          <strong>${escapeHtml(review.release_decision || "pending")}</strong>
        </div>
        <div class="summary-card">
          <span>${escapeHtml(t("Confidence"))}</span>
          <strong>${escapeHtml(review.confidence || "pending")}</strong>
        </div>
      </div>
      <article class="action-card">
        <strong>${escapeHtml(t("Overview"))}</strong>
        <p>${escapeHtml(review.overview || t("No AI review yet."))}</p>
      </article>
      <article class="action-card">
        <strong>${escapeHtml(t("Risk Narrative"))}</strong>
        <p>${escapeHtml(review.risk_narrative || t("No risk narrative yet."))}</p>
      </article>
      <div class="two-column">
        <article class="action-card">
          <strong>${escapeHtml(t("Blockers"))}</strong>
          ${blockers}
        </article>
        <article class="action-card">
          <strong>${escapeHtml(t("Quick Wins"))}</strong>
          ${quickWins}
        </article>
      </div>
      <p class="empty-state">${escapeHtml(review.reason || "")}</p>
    `;
  }

  function renderExecution(job) {
    const functionality = job.metadata?.functionality || {};
    const project = job.metadata?.project || {};
    const buildSystems = (project.build_systems || []).join(", ") || t("none");
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Configured"))}</span>
        <strong>${escapeHtml(t(functionality.configured ? "yes" : "no"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Built"))}</span>
        <strong>${escapeHtml(t(functionality.built ? "yes" : "no"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Tests ran"))}</span>
        <strong>${escapeHtml(t(functionality.tests_ran ? "yes" : "no"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Build system"))}</span>
        <strong>${escapeHtml(buildSystems)}</strong>
      </div>
    `;
  }

  function renderSteps(job) {
    return (job.steps || [])
      .map(
        (step) => `
          <div class="step">
            <div class="job-card-top">
              <strong>${escapeHtml(t(step.title))}</strong>
              <span class="${statusClass(step.status)}">${escapeHtml(valueLabel("status", step.status))}</span>
            </div>
            <div class="progress-track">
              <div class="progress-bar" style="width: ${Number(step.progress || 0)}%"></div>
            </div>
            <small>${escapeHtml(t(step.message || "Waiting"))}</small>
          </div>
        `
      )
      .join("");
  }

  function renderSeveritySummary(job) {
    const severityCounts = job.summaries?.severity_counts || {};
    const keys = ["critical", "high", "medium", "low", "info"];
    const hasData = keys.some((key) => Number(severityCounts[key] || 0) > 0) || Number(job.summaries?.total_findings || 0) > 0;
    if (!hasData) {
      return `<p class="empty-state">${escapeHtml(t("Findings will appear after the analysis reaches the reporting stage."))}</p>`;
    }
    return keys
      .map(
        (key) => `
          <div class="summary-card">
            <span>${escapeHtml(valueLabel("severity", key))}</span>
            <strong>${escapeHtml(severityCounts[key] || 0)}</strong>
          </div>
        `
      )
      .join("");
  }

  function renderFindings(job) {
    const findings = job.sorted_findings || [];
    if (!findings.length) {
      return `<p class="empty-state">${escapeHtml(t("No findings yet."))}</p>`;
    }
    return findings
      .map(
        (finding) => `
          <article class="finding-card severity-${escapeHtml(finding.severity)}">
            <div class="job-card-top">
              <strong>${escapeHtml(finding.title)}</strong>
              <span class="${findingBadgeClass(finding.severity)}">${escapeHtml(valueLabel("severity", finding.severity))}</span>
            </div>
            <p class="finding-meta">
              ${escapeHtml(valueLabel("category", finding.category))}${finding.path ? ` | ${escapeHtml(finding.path)}` : ""}${finding.line ? `:${escapeHtml(finding.line)}` : ""}
            </p>
            <p>${escapeHtml(finding.description)}</p>
            ${finding.references?.length ? `<div class="reference-list compact">${renderReferenceCards(finding.references.slice(0, 4), "")}</div>` : ""}
            ${finding.recommendation ? `<small>${escapeHtml(finding.recommendation)}</small>` : ""}
          </article>
        `
      )
      .join("");
  }

  function renderTools(job) {
    const tools = job.metadata?.tools || {};
    return Object.entries(tools)
      .map(
        ([tool, path]) => `
          <div class="tool-row">
            <code>${escapeHtml(tool)}</code>
            <span class="${statusClass(path ? "completed" : "skipped")}">${escapeHtml(path || t("not installed"))}</span>
          </div>
        `
      )
      .join("");
  }

  function renderReportPreview(job) {
    if (!job.report_preview_url) {
      return `<p class="empty-state">${escapeHtml(t("HTML report preview will appear after report generation."))}</p>`;
    }
    return `<iframe class="report-frame" src="${escapeHtml(job.report_preview_url)}" title="${escapeHtml(t("HTML preview"))}"></iframe>`;
  }

  function updateJobPage(job) {
    setStatusBadge(document.getElementById("job-status"), job.status);
    const progressBar = document.getElementById("job-progress-bar");
    if (progressBar) progressBar.style.width = `${Number(job.progress || 0)}%`;
    const progressText = document.getElementById("job-progress-text");
    if (progressText) progressText.textContent = `${Number(job.progress || 0)}%`;
    const currentStep = document.getElementById("job-current-step");
    if (currentStep) currentStep.textContent = t(job.current_step || "Queued");
    const mode = document.getElementById("job-mode");
    if (mode) mode.textContent = valueLabel("mode", job.mode || "full_scan");
    const inputType = document.getElementById("job-input-type");
    if (inputType) inputType.textContent = valueLabel("input_type", job.input_type || "archive");
    const finishedAt = document.getElementById("job-finished-at");
    if (finishedAt) finishedAt.textContent = job.finished_at || t("in progress");
    const sourceRoot = document.getElementById("job-source-root");
    if (sourceRoot) sourceRoot.textContent = job.metadata?.project?.relative_root_name || t("pending");
    const fileCount = document.getElementById("job-file-count");
    if (fileCount) fileCount.textContent = String(job.metadata?.project?.file_count || 0);
    const queuePosition = document.getElementById("job-queue-position");
    if (queuePosition) queuePosition.textContent = `#${job.queue_position || 0}`;
    const retestScope = document.getElementById("job-retest-scope");
    if (retestScope) retestScope.textContent = valueLabel("retest_scope", job.options?.retest_scope === "changes_only" ? "changes_only" : "full_project");
    const preset = document.getElementById("job-preset");
    if (preset) preset.textContent = valueLabel("preset", job.options?.preset || "balanced");
    const fuzzBudget = document.getElementById("job-fuzz-budget");
    if (fuzzBudget) fuzzBudget.textContent = `${job.options?.fuzz_duration_seconds || 0} sec`;
    const reportLimit = document.getElementById("job-report-limit");
    if (reportLimit) reportLimit.textContent = String(job.options?.max_report_findings || 0);

    const selectedChecks = document.getElementById("selected-checks");
    if (selectedChecks) selectedChecks.innerHTML = renderCheckTags(job);
    const artifactButtons = document.getElementById("artifact-buttons");
    if (artifactButtons) artifactButtons.innerHTML = renderArtifactButtons(job);
    const decisionSummary = document.getElementById("decision-summary");
    if (decisionSummary) decisionSummary.innerHTML = renderDecisionSummary(job);
    const nextActions = document.getElementById("next-actions");
    if (nextActions) nextActions.innerHTML = renderActions(job);
    const executionSummary = document.getElementById("execution-summary");
    if (executionSummary) executionSummary.innerHTML = renderExecution(job);
    const stepsContainer = document.getElementById("steps-container");
    if (stepsContainer) stepsContainer.innerHTML = renderSteps(job);
    const severitySummary = document.getElementById("severity-summary");
    if (severitySummary) severitySummary.innerHTML = renderSeveritySummary(job);
    const findingList = document.getElementById("finding-list");
    if (findingList) findingList.innerHTML = renderFindings(job);
    const toolList = document.getElementById("tool-list");
    if (toolList) toolList.innerHTML = renderTools(job);
    const aiReview = document.getElementById("ai-review");
    if (aiReview) aiReview.innerHTML = renderAiReview(job);
    const kbSummary = document.getElementById("kb-summary");
    if (kbSummary) kbSummary.innerHTML = renderKnowledgeBaseSummary(job);
    const kbTopReferences = document.getElementById("kb-top-references");
    if (kbTopReferences) {
      kbTopReferences.innerHTML = renderReferenceCards(
        job.metadata?.knowledge_base?.top_references || [],
        "Knowledge base matches will appear once reporting begins."
      );
    }
    const hardwarePlan = document.getElementById("hardware-plan-summary");
    if (hardwarePlan) hardwarePlan.innerHTML = renderHardwarePlan(job);
    const comparisonSummary = document.getElementById("comparison-summary");
    if (comparisonSummary) comparisonSummary.innerHTML = renderComparisonSummary(job);
    const comparisonFiles = document.getElementById("comparison-files");
    if (comparisonFiles) comparisonFiles.innerHTML = renderComparisonFiles(job);
    const gpuInventory = document.getElementById("gpu-inventory");
    if (gpuInventory) gpuInventory.innerHTML = renderGpuInventory(job);
    const reportPreview = document.getElementById("report-preview");
    if (reportPreview) reportPreview.innerHTML = renderReportPreview(job);
    const logBox = document.getElementById("job-log");
    if (logBox) logBox.textContent = (job.logs || []).join("\n");
  }

  async function pollJob(jobId) {
    const response = await fetch(`/api/jobs/${jobId}`, { headers: { Accept: "application/json" } });
    if (!response.ok) return null;
    return response.json();
  }

  function initJobPage(root) {
    const jobId = root.dataset.jobId;
    if (!jobId) return;

    let timerId = null;

    const tick = async () => {
      try {
        const job = await pollJob(jobId);
        if (!job) return;
        updateJobPage(job);
        root.dataset.jobStatus = job.status;
        if (job.status === "queued" || job.status === "running") {
          timerId = window.setTimeout(tick, 3000);
        }
      } catch (_error) {
        timerId = window.setTimeout(tick, 5000);
      }
    };

    if (root.dataset.jobStatus === "queued" || root.dataset.jobStatus === "running") {
      timerId = window.setTimeout(tick, 1500);
    }

    window.addEventListener("beforeunload", function () {
      if (timerId) {
        window.clearTimeout(timerId);
      }
    });
  }

  function applyPreset(form, presetKey) {
    const presets = JSON.parse(form.dataset.presets || "[]");
    const preset = presets.find((item) => item.key === presetKey);
    if (!preset) return;

    const options = preset.options || {};
    const fields = ["functionality", "security", "style", "quality", "fuzzing"];
    for (const field of fields) {
      const checkbox = form.querySelector(`[data-check="${field}"]`);
      if (checkbox) checkbox.checked = Boolean(options[`run_${field}`]);
    }

    const fuzzDuration = form.querySelector('[data-field="fuzz_duration_seconds"]');
    if (fuzzDuration) fuzzDuration.value = String(options.fuzz_duration_seconds ?? 60);
    const maxFindings = form.querySelector('[data-field="max_report_findings"]');
    if (maxFindings) maxFindings.value = String(options.max_report_findings ?? 200);

    const summary = form.querySelector("[data-preset-summary]");
    if (summary) summary.textContent = preset.description || t("Balanced preset selected.");

    for (const card of form.querySelectorAll(".preset-card")) {
      const input = card.querySelector("[data-preset-option]");
      card.classList.toggle("selected", input?.value === presetKey);
    }
  }

  function syncMode(form) {
    const modeSelect = form.querySelector("[data-mode-select]");
    const fuzzCheckbox = form.querySelector('[data-check="fuzzing"]');
    const fuzzCopy = form.querySelector("[data-fuzz-copy]");
    if (!modeSelect || !fuzzCheckbox) return;

    const fuzzOnlyMode = modeSelect.value === "fuzz_single" || modeSelect.value === "fuzz_project";
    fuzzCheckbox.disabled = fuzzOnlyMode;
    if (fuzzOnlyMode) {
      fuzzCheckbox.checked = true;
    }
    if (fuzzCopy) {
      fuzzCopy.textContent = fuzzOnlyMode
        ? t("Required by the selected fuzz mode and locked for this run.")
        : t("Generate harnesses, plan corpus work and fuzz workflow.");
    }
  }

  function initPresetForm(form) {
    const presetInputs = form.querySelectorAll("[data-preset-option]");
    for (const input of presetInputs) {
      input.addEventListener("change", function () {
        if (input.checked) {
          applyPreset(form, input.value);
          syncMode(form);
        }
      });
    }

    const modeSelect = form.querySelector("[data-mode-select]");
    if (modeSelect) {
      modeSelect.addEventListener("change", function () {
        syncMode(form);
      });
    }

    const selectedPreset = form.querySelector("[data-preset-option]:checked");
    applyPreset(form, selectedPreset ? selectedPreset.value : "balanced");
    syncMode(form);
  }

  function syncRepeatQuestion(form) {
    const knownProjects = JSON.parse(form.dataset.knownProjects || "[]");
    const uploadInput = form.querySelector("[data-upload-input]");
    const question = form.querySelector("[data-repeat-question]");
    const hiddenScope = form.querySelector("[data-retest-scope-input]");
    const selectionText = form.querySelector("[data-repeat-selection]");
    const copy = form.querySelector("[data-repeat-copy]");
    const cards = form.querySelectorAll("[data-retest-choice]");
    if (!uploadInput || !question || !hiddenScope) return;

    const selectedFiles = Array.from(uploadInput.files || []);
    const matchedProjects = selectedFiles
      .map((file) => {
        const key = normalizeProjectKey(file.name);
        return knownProjects.find((item) => item.project_key === key);
      })
      .filter(Boolean);

    if (!matchedProjects.length) {
      question.hidden = true;
      hiddenScope.value = "full_project";
      if (selectionText) {
        selectionText.textContent = t("Choose a rerun strategy for the repeated project submission.");
      }
      for (const card of cards) {
        card.classList.remove("selected");
      }
      return;
    }

    question.hidden = false;
    const firstMatch = matchedProjects[0];
    if (copy) {
      copy.textContent = t(
        "A previous run of {filename} was found in history. Choose how the repeated submission should be tested.",
        { filename: firstMatch.original_filename }
      );
    }
    const currentScope = hiddenScope.value || "";
    if (currentScope !== "changes_only" && currentScope !== "full_project") {
      hiddenScope.value = "";
    }
    for (const card of cards) {
      card.classList.toggle("selected", card.dataset.retestChoice === hiddenScope.value);
    }
    if (selectionText) {
      selectionText.textContent = hiddenScope.value
        ? t("Selected strategy: {strategy}.", {
            strategy: hiddenScope.value === "changes_only"
              ? valueLabel("retest_scope", "changes_only")
              : valueLabel("retest_scope", "full_project"),
          })
        : t("Choose a rerun strategy for the repeated project submission.");
    }
  }

  function initRepeatQuestion(form) {
    const uploadInput = form.querySelector("[data-upload-input]");
    const hiddenScope = form.querySelector("[data-retest-scope-input]");
    const selectionText = form.querySelector("[data-repeat-selection]");
    const question = form.querySelector("[data-repeat-question]");
    const cards = form.querySelectorAll("[data-retest-choice]");
    if (!uploadInput || !hiddenScope || !question) return;

    uploadInput.addEventListener("change", function () {
      hiddenScope.value = "";
      syncRepeatQuestion(form);
    });

    for (const card of cards) {
      card.addEventListener("click", function () {
        hiddenScope.value = card.dataset.retestChoice || "";
        for (const item of cards) {
          item.classList.toggle("selected", item === card);
        }
        if (selectionText) {
          selectionText.textContent = hiddenScope.value === "changes_only"
            ? t("Selected strategy: {strategy}.", { strategy: valueLabel("retest_scope", "changes_only") })
            : t("Selected strategy: {strategy}.", { strategy: valueLabel("retest_scope", "full_project") });
        }
      });
    }

    form.addEventListener("submit", function (event) {
      if (!question.hidden && hiddenScope.value !== "changes_only" && hiddenScope.value !== "full_project") {
        event.preventDefault();
        if (selectionText) {
          selectionText.textContent = t("Select one of the rerun strategies before starting the repeated submission.");
        }
      }
      if (question.hidden && !hiddenScope.value) {
        hiddenScope.value = "full_project";
      }
    });

    syncRepeatQuestion(form);
  }

  async function repositionQueueJob(jobId, targetJobId, placement) {
    const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/queue/reposition`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        target_job_id: targetJobId,
        placement,
      }),
    });
    if (!response.ok) {
      throw new Error(`Queue reorder failed with status ${response.status}`);
    }
    return response.json();
  }

  function clearQueueDropState(container) {
    for (const card of container.querySelectorAll("[data-queue-job-id]")) {
      card.classList.remove("dragging", "drop-before", "drop-after");
    }
  }

  function initQueueDragAndDrop(container) {
    const movableCards = Array.from(container.querySelectorAll('[data-queue-movable="true"]'));
    if (movableCards.length < 2) return;

    let draggedCard = null;
    let dragPlacement = "before";

    for (const card of movableCards) {
      card.addEventListener("dragstart", function (event) {
        draggedCard = card;
        dragPlacement = "before";
        card.classList.add("dragging");
        if (event.dataTransfer) {
          event.dataTransfer.effectAllowed = "move";
          event.dataTransfer.setData("text/plain", card.dataset.queueJobId || "");
        }
      });

      card.addEventListener("dragend", function () {
        clearQueueDropState(container);
        draggedCard = null;
      });

      card.addEventListener("dragover", function (event) {
        if (!draggedCard || draggedCard === card) return;
        event.preventDefault();
        const rect = card.getBoundingClientRect();
        dragPlacement = event.clientY > rect.top + rect.height / 2 ? "after" : "before";
        card.classList.toggle("drop-before", dragPlacement === "before");
        card.classList.toggle("drop-after", dragPlacement === "after");
      });

      card.addEventListener("dragleave", function () {
        card.classList.remove("drop-before", "drop-after");
      });

      card.addEventListener("drop", async function (event) {
        if (!draggedCard || draggedCard === card) return;
        event.preventDefault();
        const draggedJobId = draggedCard.dataset.queueJobId;
        const targetJobId = card.dataset.queueJobId;
        if (!draggedJobId || !targetJobId) return;
        clearQueueDropState(container);
        container.classList.add("queue-reordering");
        try {
          await repositionQueueJob(draggedJobId, targetJobId, dragPlacement);
          window.location.reload();
        } catch (_error) {
          container.classList.remove("queue-reordering");
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const presetForm = document.querySelector("[data-preset-form]");
    if (presetForm) {
      initPresetForm(presetForm);
      initRepeatQuestion(presetForm);
    }

    const queueList = document.querySelector("[data-queue-list]");
    if (queueList) initQueueDragAndDrop(queueList);

    const jobRoot = document.querySelector("[data-job-id]");
    if (jobRoot) initJobPage(jobRoot);
  });
})();
