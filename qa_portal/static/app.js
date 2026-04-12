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

  function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex += 1;
    }
    return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
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

  function queueStatusRank(status) {
    const order = {
      running: 0,
      queued: 1,
      paused: 2,
      failed: 3,
      completed: 4,
      cancelled: 5,
    };
    return Object.prototype.hasOwnProperty.call(order, status) ? order[status] : 99;
  }

  function sortQueueJobs(jobs) {
    return [...(jobs || [])].sort(function (left, right) {
      const statusDiff = queueStatusRank(left.status) - queueStatusRank(right.status);
      if (statusDiff !== 0) return statusDiff;
      const leftPosition = Number(left.queue_position || 0) > 0 ? Number(left.queue_position) : Number.MAX_SAFE_INTEGER;
      const rightPosition = Number(right.queue_position || 0) > 0 ? Number(right.queue_position) : Number.MAX_SAFE_INTEGER;
      if (leftPosition !== rightPosition) return leftPosition - rightPosition;
      return String(left.created_at || "").localeCompare(String(right.created_at || ""));
    });
  }

  function renderArtifactButtons(job) {
    const buttons = [];
    if (job.view_report_url) {
      buttons.push(`<a class="button-secondary" href="${escapeHtml(job.view_report_url)}">${escapeHtml(t("View report"))}</a>`);
    }
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
    if (job.can_delete) {
      buttons.push(
        `<form action="/jobs/${job.id}/delete" method="post"><input type="hidden" name="next_url" value="/"><button type="submit">${escapeHtml(t("Delete"))}</button></form>`
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

  function renderJobKnowledgeBaseSummary(job) {
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
              <div class="progress-bar ${step.status === "running" ? "progress-bar-active" : ""}" style="width: ${Number(step.progress || 0)}%"></div>
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

  function currentSearchParams() {
    return new URLSearchParams(window.location.search);
  }

  function renderDashboardActionForm(actionUrl, apiUrl, labelText, hiddenInputs = "") {
    return `
      <form action="${escapeHtml(actionUrl)}" method="post" data-dashboard-action data-api-endpoint="${escapeHtml(apiUrl)}">
        ${hiddenInputs}
        <button type="submit">${escapeHtml(labelText)}</button>
      </form>
    `;
  }

  function renderSettingsActionForm(actionUrl, apiUrl, labelText, hiddenInputs = "", buttonClass = "button-secondary") {
    return `
      <form action="${escapeHtml(actionUrl)}" method="post" data-settings-action data-api-endpoint="${escapeHtml(apiUrl)}">
        ${hiddenInputs}
        <button type="submit" class="${escapeHtml(buttonClass)}">${escapeHtml(labelText)}</button>
      </form>
    `;
  }

  function renderDashboardJobCard(job) {
    const queueMovable = job.status === "queued" || job.status === "paused";
    const queueControls = [];
    if (job.html_report) {
      queueControls.push(`<a class="button-secondary" href="/jobs/${job.id}/report">${escapeHtml(t("View report"))}</a>`);
    }
    if (job.status === "queued" || job.status === "running") {
      queueControls.push(renderDashboardActionForm(`/jobs/${job.id}/pause`, `/api/jobs/${job.id}/pause`, t("Pause")));
    }
    if (job.status === "paused") {
      queueControls.push(renderDashboardActionForm(`/jobs/${job.id}/resume`, `/api/jobs/${job.id}/resume`, t("Resume")));
    }
    if (queueMovable) {
      queueControls.push(renderDashboardActionForm(`/jobs/${job.id}/queue/up`, `/api/jobs/${job.id}/queue/up`, t("Up")));
      queueControls.push(renderDashboardActionForm(`/jobs/${job.id}/queue/down`, `/api/jobs/${job.id}/queue/down`, t("Down")));
    }
    if (job.status !== "running") {
      queueControls.push(
        renderDashboardActionForm(
          `/jobs/${job.id}/delete`,
          `/api/jobs/${job.id}/delete`,
          t("Delete"),
          '<input type="hidden" name="next_url" value="/">'
        )
      );
    }
    return `
      <article
        class="job-card ${queueMovable ? "queue-draggable" : ""}"
        data-queue-job-id="${escapeHtml(job.id)}"
        data-queue-movable="${queueMovable ? "true" : "false"}"
        data-queue-position="${escapeHtml(job.queue_position || 0)}"
        draggable="${queueMovable ? "true" : "false"}"
      >
        <div class="job-card-top">
          <strong>
            <a class="job-card-link" href="/jobs/${job.id}">${escapeHtml(job.name)}</a>
            ${queueMovable ? `<span class="drag-handle" aria-hidden="true">${escapeHtml(t("Drag"))}</span>` : ""}
          </strong>
          <span class="${statusClass(job.status)}">${escapeHtml(valueLabel("status", job.status))}</span>
        </div>
        <p>${escapeHtml(job.original_filename || "")}</p>
        <p class="queue-meta">${escapeHtml(t("Queue #{position}", { position: job.queue_position || 0 }))}</p>
        <div class="tag-row">
          <span class="tag tag-soft">${escapeHtml(valueLabel("preset", job.options?.preset || "balanced"))}</span>
          ${job.metadata?.repeat_submission ? `<span class="tag tag-soft">${escapeHtml(job.options?.retest_scope === "changes_only" ? valueLabel("retest_scope", "changes_only") : t("full retest"))}</span>` : ""}
          ${(job.metadata?.project?.programming_languages || []).slice(0, 3).map((language) => `<span class="tag tag-soft">${escapeHtml(language)}</span>`).join("")}
          ${enabledChecks(job).map((check) => `<span class="tag">${escapeHtml(valueLabel("check", check))}</span>`).join("")}
        </div>
        <div class="progress-track">
          <div class="progress-bar ${job.status === "running" ? "progress-bar-active" : ""}" style="width: ${Number(job.progress || 0)}%"></div>
        </div>
        <div class="job-card-foot">
          <small>${escapeHtml(t(job.current_step || "Queued"))}</small>
          <small>${escapeHtml(`${Number(job.progress || 0)}%`)}</small>
        </div>
        <div class="queue-controls">
          ${queueControls.join("")}
        </div>
      </article>
    `;
  }

  function renderQueueList(jobs) {
    const orderedJobs = sortQueueJobs(jobs);
    if (!orderedJobs.length) {
      return `<p class="empty-state">${escapeHtml(t("No jobs match the current filters yet."))}</p>`;
    }
    return `<div class="job-list" data-queue-list>${orderedJobs.map(renderDashboardJobCard).join("")}</div>`;
  }

  function renderToolInventory(inventory) {
    return (inventory || [])
      .map(function (tool) {
        if (tool.installed) {
          return `
            <div class="tool-row">
              <div class="tool-main">
                <code>${escapeHtml(tool.key)}</code>
                <small>${escapeHtml(tool.description || "")}</small>
              </div>
              <div class="tool-actions">
                <span class="status status-completed">${escapeHtml(tool.path || "")}</span>
              </div>
            </div>
          `;
        }
        const installForm = tool.installable
          ? renderSettingsActionForm(
              `/tools/install/${tool.key}`,
              `/api/tools/install/${tool.key}`,
              t("Install"),
              `<input type="hidden" name="next_url" value="${escapeHtml(window.location.pathname + window.location.search)}">`
            ).replace("<form ", '<form class="tool-install-form" ')
          : "";
        return `
          <div class="tool-row tool-row-missing">
            <div class="tool-main">
              <code>${escapeHtml(tool.key)}</code>
              <small>${escapeHtml(tool.description || "")}</small>
            </div>
            <div class="tool-actions">
              <div class="tool-install-slot">
                <span class="status status-skipped">${escapeHtml(t("not installed"))}</span>
                ${installForm}
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  }

  function aiCopyText(aiBackend) {
    if (aiBackend?.configured) {
      return t("Remote AI review is configured and will augment the scan reports.");
    }
    if (aiBackend?.mode === "local-llm") {
      return t("A downloaded local model is ready and will be used for AI-assisted review.");
    }
    return t("Remote AI review is not configured, so the portal will generate a deterministic local review instead.");
  }

  function renderAiSummary(aiBackend, workerMode) {
    const installedCount = (aiBackend?.local_models || []).filter((item) => item.installed).length;
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Mode"))}</span>
        <strong>${escapeHtml(aiBackend?.mode || "local-fallback")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Worker mode"))}</span>
        <strong>${escapeHtml(workerMode || "unknown")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Provider"))}</span>
        <strong>${escapeHtml(aiBackend?.provider || "scanforge-local")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Model"))}</span>
        <strong>${escapeHtml(aiBackend?.model || "")}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Status"))}</span>
        <strong>${escapeHtml(t(aiBackend?.configured ? "ready" : "fallback"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Local runner"))}</span>
        <strong>${escapeHtml(t(aiBackend?.local_runner?.available ? "ready" : "not installed"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Local models"))}</span>
        <strong>${escapeHtml(installedCount)}</strong>
      </div>
    `;
  }

  function renderModelDownloadState(model) {
    const state = model.download_state || {};
    if (model.installed) {
      return `<span class="tag">${escapeHtml(t("Installed"))}</span>`;
    }
    if (state.running) {
      const progress = Math.max(0, Math.min(100, Number(state.progress_percent || 0)));
      let meta = t("Preparing download...");
      if (Number(state.total_bytes || 0) > 0) {
        meta = t("Downloaded {loaded} of {total}.", {
          loaded: formatBytes(state.downloaded_bytes || 0),
          total: formatBytes(state.total_bytes || 0),
        });
      } else if (Number(state.downloaded_bytes || 0) > 0) {
        meta = t("Downloaded {loaded}.", { loaded: formatBytes(state.downloaded_bytes || 0) });
      }
      return `
        <span class="tag tag-soft">${escapeHtml(t("Downloading"))}</span>
        <div class="download-progress">
          <div class="progress-track compact">
            <div class="progress-bar progress-bar-active" style="width: ${progress}%"></div>
          </div>
          <small class="download-progress-meta">${escapeHtml(meta)}</small>
        </div>
      `;
    }
    const retryNotice = state.error
      ? `<small class="download-progress-meta">${escapeHtml(t("Download failed: {error}", { error: state.error }))}</small>`
      : "";
    return `
      ${retryNotice}
      ${renderSettingsActionForm(
        `/assistant/models/${model.id}/download`,
        `/api/assistant/models/${model.id}/download`,
        t("Download"),
        `<input type="hidden" name="next_url" value="${escapeHtml(window.location.pathname + window.location.search)}">`
      )}
    `;
  }

  function renderAiModelList(aiBackend) {
    const defaultCard = `
      <article class="reference-item">
        <strong>${escapeHtml(aiBackend.default_model?.label || "ScanForge Local Analyst")}</strong>
        <p>${escapeHtml(t("Default assistant model"))}</p>
        <small>${escapeHtml(aiBackend.default_model?.description || "")}</small>
      </article>
    `;
    const localModels = (aiBackend.local_models || []).map(function (model) {
      return `
        <article class="reference-item">
          <strong>${escapeHtml(model.label)}</strong>
          <p>${escapeHtml(model.description || "")}</p>
          <small>
            ${escapeHtml(t("Role"))}: ${escapeHtml(model.role || "")}
            ${model.size_hint_gb ? ` · ~${escapeHtml(model.size_hint_gb)} GB` : ""}
          </small>
          <div class="reference-actions">
            ${renderModelDownloadState(model)}
          </div>
        </article>
      `;
    }).join("");
    return `${defaultCard}${localModels}`;
  }

  function renderSystemKnowledgeBaseSummary(kb) {
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("Status"))}</span>
        <strong>${escapeHtml(t(kb.available ? "ready" : "empty"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Sources"))}</span>
        <strong>${escapeHtml(kb.successful_sources || 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Updated"))}</span>
        <strong>${escapeHtml(kb.updated_at || t("pending"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Stale"))}</span>
        <strong>${escapeHtml(t(kb.stale ? "yes" : "no"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Weekly sync"))}</span>
        <strong>${escapeHtml(t(kb.weekly_schedule?.enabled ? "on" : "off"))}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("NVD yearly"))}</span>
        <strong>${escapeHtml(kb.nvd_yearly?.enabled ? kb.nvd_yearly.year_count : 0)}</strong>
      </div>
    `;
  }

  function renderKnowledgeBaseScheduleCopy(kb) {
    const parts = [];
    if (kb.weekly_schedule?.enabled) {
      parts.push(
        t("Weekly sync is scheduled for {day} at {time}.", {
          day: t(kb.weekly_schedule.day_label),
          time: `${String(kb.weekly_schedule.hour).padStart(2, "0")}:${String(kb.weekly_schedule.minute).padStart(2, "0")}`,
        })
      );
    } else {
      parts.push(t("Weekly sync is disabled."));
    }
    if (kb.nvd_yearly?.enabled) {
      parts.push(
        t("The portal is configured to maintain an NVD yearly mirror from {year_start} to {year_end}.", {
          year_start: kb.nvd_yearly.year_start,
          year_end: kb.nvd_yearly.year_end,
        })
      );
    }
    return parts.join(" ");
  }

  function renderKnowledgeBaseSources(kb) {
    if (!(kb.sources_list || []).length) {
      return `<p class="empty-state">${escapeHtml(t("Knowledge base sync has not been run yet."))}</p>`;
    }
    return (kb.sources_list || [])
      .map(function (source) {
        return `
          <article class="reference-item">
            <strong>${escapeHtml(source.label)}</strong>
            <small>
              ${escapeHtml(source.status || "")}${source.count ? ` · ${escapeHtml(source.count)}` : ""}
              ${source.year_start && source.year_end ? ` · ${escapeHtml(source.year_start)}-${escapeHtml(source.year_end)}` : ""}
            </small>
          </article>
        `;
      })
      .join("");
  }

  function renderHardwareSummary(system) {
    return `
      <div class="summary-card">
        <span>${escapeHtml(t("CPU target"))}</span>
        <strong>${escapeHtml(system.hardware.cpu_threads_target || 0)}/${escapeHtml(system.hardware.cpu_threads_total || 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("RAM target"))}</span>
        <strong>${escapeHtml(system.hardware.memory_target_mb || 0)} MB</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("GPUs"))}</span>
        <strong>${escapeHtml(system.hardware.gpu_count || 0)}</strong>
      </div>
      <div class="summary-card">
        <span>${escapeHtml(t("Recommended workers"))}</span>
        <strong>${escapeHtml(system.recommended_worker_processes || 0)}</strong>
      </div>
    `;
  }

  function renderHardwareGpuList(system) {
    const gpus = system.hardware?.gpus || [];
    if (!gpus.length) {
      return `<p class="empty-state">${escapeHtml(t("No NVIDIA GPUs were detected, so the portal will run in CPU/RAM adaptive mode."))}</p>`;
    }
    return gpus
      .map(function (gpu) {
        return `
          <article class="reference-item">
            <strong>GPU ${escapeHtml(gpu.index)}</strong>
            <p>${escapeHtml(gpu.name || "Unknown GPU")}</p>
            <small>${escapeHtml(gpu.memory_total_mb || 0)} MB${gpu.utilization_percent !== null && gpu.utilization_percent !== undefined ? ` · ${escapeHtml(gpu.utilization_percent)}% util` : ""}</small>
          </article>
        `;
      })
      .join("");
  }

  async function fetchJson(url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  async function fetchDashboardState() {
    const query = currentSearchParams().toString();
    return fetchJson(query ? `/api/dashboard?${query}` : "/api/dashboard");
  }

  async function fetchSettingsState() {
    return fetchJson("/api/system");
  }

  function updateDashboardPage(root, payload) {
    for (const [key, value] of Object.entries(payload.overview || {})) {
      const target = root.querySelector(`[data-overview-key="${key}"]`);
      if (target) target.textContent = String(value);
    }

    const historyCopy = root.querySelector("[data-history-copy]");
    if (historyCopy) {
      historyCopy.textContent = t("Showing {visible} of {total} saved jobs.", {
        visible: (payload.jobs || []).length,
        total: payload.all_jobs_count || 0,
      });
    }

    const queueContainer = root.querySelector("[data-queue-container]");
    if (queueContainer) {
      queueContainer.innerHTML = renderQueueList(payload.jobs || []);
      const queueList = queueContainer.querySelector("[data-queue-list]");
      if (queueList) initQueueDragAndDrop(queueList);
    }
  }

  function updateSettingsPage(root, payload) {
    const toolList = root.querySelector("[data-tool-list]");
    if (toolList) toolList.innerHTML = renderToolInventory(payload.tool_inventory || []);

    const aiSummary = root.querySelector("[data-ai-summary]");
    if (aiSummary) aiSummary.innerHTML = renderAiSummary(payload.ai_backend || {}, payload.worker_mode || "");

    const aiCopy = root.querySelector("[data-ai-copy]");
    if (aiCopy) aiCopy.textContent = aiCopyText(payload.ai_backend || {});

    const aiModels = root.querySelector("[data-ai-model-list]");
    if (aiModels) aiModels.innerHTML = renderAiModelList(payload.ai_backend || { default_model: {}, local_models: [] });

    const kbSummary = root.querySelector("[data-kb-summary]");
    if (kbSummary) kbSummary.innerHTML = renderSystemKnowledgeBaseSummary(payload.knowledge_base || {});

    const kbScheduleCopy = root.querySelector("[data-kb-schedule-copy]");
    if (kbScheduleCopy) kbScheduleCopy.textContent = renderKnowledgeBaseScheduleCopy(payload.knowledge_base || {});

    const kbSources = root.querySelector("[data-kb-sources]");
    if (kbSources) kbSources.innerHTML = renderKnowledgeBaseSources(payload.knowledge_base || {});

    const kbNotice = root.querySelector("[data-kb-sync-notice]");
    if (kbNotice) kbNotice.hidden = !(payload.knowledge_base?.sync?.running);

    const kbFormButton = root.querySelector("[data-kb-sync-form] button[type='submit']");
    if (kbFormButton) kbFormButton.disabled = Boolean(payload.knowledge_base?.sync?.running);

    const hardwareSummary = root.querySelector("[data-hardware-summary]");
    if (hardwareSummary) hardwareSummary.innerHTML = renderHardwareSummary(payload);

    const gpuList = root.querySelector("[data-gpu-list]");
    if (gpuList) gpuList.innerHTML = renderHardwareGpuList(payload);
  }

  function shouldPollDashboard(payload) {
    return (payload.jobs || []).some((job) => ["queued", "running", "paused"].includes(job.status));
  }

  function shouldPollSettings(payload) {
    return Boolean(payload.ai_backend?.downloads_running) || Boolean(payload.knowledge_base?.sync?.running);
  }

  function initAsyncForms(root, attributeName, refreshFn) {
    const boundAttr = `${attributeName}-listener-bound`;
    if (root.hasAttribute(boundAttr)) return;
    root.setAttribute(boundAttr, "true");
    root.addEventListener("submit", async function (event) {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (!form.hasAttribute(attributeName)) return;
      event.preventDefault();

      const apiEndpoint = form.dataset.apiEndpoint || form.getAttribute("action");
      if (!apiEndpoint) return;

      form.classList.add("is-pending");
      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton) submitButton.disabled = true;
      try {
        const response = await fetch(apiEndpoint, {
          method: "POST",
          headers: { Accept: "application/json" },
        });
        if (!response.ok) {
          throw new Error(`Action failed with status ${response.status}`);
        }
        await refreshFn();
      } catch (_error) {
        window.location.reload();
      } finally {
        form.classList.remove("is-pending");
        if (submitButton) submitButton.disabled = false;
      }
    });
  }

  function initScrollRestoration() {
    const storageKey = `scanforge:scroll:${window.location.pathname}${window.location.search}`;
    const saved = window.sessionStorage.getItem(storageKey);
    if (saved) {
      window.sessionStorage.removeItem(storageKey);
      window.scrollTo({ top: Number(saved), behavior: "auto" });
    }

    document.addEventListener("submit", function (event) {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const method = String(form.getAttribute("method") || "get").toLowerCase();
      if (method !== "post") return;
      if (form.hasAttribute("data-dashboard-action") || form.hasAttribute("data-settings-action") || form.hasAttribute("data-upload-form")) return;
      window.sessionStorage.setItem(storageKey, String(window.scrollY));
    }, true);
  }

  function initDashboard(root) {
    let timerId = null;

    const refresh = async function () {
      let nextDelay = 5000;
      try {
        const payload = await fetchDashboardState();
        updateDashboardPage(root, payload);
        nextDelay = shouldPollDashboard(payload) ? 3000 : 12000;
      } catch (_error) {
        nextDelay = 5000;
      }
      if (timerId) window.clearTimeout(timerId);
      timerId = window.setTimeout(refresh, nextDelay);
    };

    root.__refreshDashboard = refresh;
    initAsyncForms(root, "data-dashboard-action", refresh);

    const queueList = root.querySelector("[data-queue-list]");
    if (queueList) initQueueDragAndDrop(queueList);

    if (timerId) window.clearTimeout(timerId);
    timerId = window.setTimeout(refresh, 3000);
    window.addEventListener("beforeunload", function () {
      if (timerId) window.clearTimeout(timerId);
    });
  }

  function initSettingsPage(root) {
    let timerId = null;

    const refresh = async function () {
      let nextDelay = 5000;
      try {
        const payload = await fetchSettingsState();
        updateSettingsPage(root, payload);
        nextDelay = shouldPollSettings(payload) ? 2500 : 10000;
      } catch (_error) {
        nextDelay = 5000;
      }
      if (timerId) window.clearTimeout(timerId);
      timerId = window.setTimeout(refresh, nextDelay);
    };

    root.__refreshSettings = refresh;
    initAsyncForms(root, "data-settings-action", refresh);

    if (timerId) window.clearTimeout(timerId);
    timerId = window.setTimeout(refresh, 2500);
    window.addEventListener("beforeunload", function () {
      if (timerId) window.clearTimeout(timerId);
    });
  }

  function updateJobPage(job) {
    setStatusBadge(document.getElementById("job-status"), job.status);
    const progressBar = document.getElementById("job-progress-bar");
    if (progressBar) {
      progressBar.style.width = `${Number(job.progress || 0)}%`;
      progressBar.classList.toggle("progress-bar-active", job.status === "running");
    }
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
    const languages = document.getElementById("job-languages");
    if (languages) {
      languages.textContent = (job.metadata?.project?.programming_languages || []).join(", ") || t("none");
    }
    const polyglot = document.getElementById("job-polyglot");
    if (polyglot) polyglot.textContent = t(job.metadata?.project?.polyglot ? "yes" : "no");
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
    if (kbSummary) kbSummary.innerHTML = renderJobKnowledgeBaseSummary(job);
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

  function setUploadProgress(form, loaded, total) {
    const root = form.querySelector("[data-upload-progress]");
    const bar = form.querySelector("[data-upload-progress-bar]");
    const text = form.querySelector("[data-upload-progress-text]");
    const meta = form.querySelector("[data-upload-progress-meta]");
    if (!root || !bar || !text || !meta) return;
    root.hidden = false;
    const percent = total > 0 ? Math.max(0, Math.min(100, Math.round((loaded / total) * 100))) : 0;
    bar.style.width = `${percent}%`;
    bar.classList.toggle("progress-bar-active", true);
    text.textContent = `${percent}%`;
    meta.textContent = t("Uploaded {loaded} of {total}.", {
      loaded: formatBytes(loaded),
      total: formatBytes(total),
    });
  }

  function initUploadProgress(form) {
    const submitButton = form.querySelector('button[type="submit"]');
    const progressRoot = form.querySelector("[data-upload-progress]");
    if (!submitButton || !progressRoot) return;

    form.addEventListener("submit", function (event) {
      if (event.defaultPrevented) return;
      event.preventDefault();

      submitButton.disabled = true;
      setUploadProgress(form, 0, 0);

      const request = new XMLHttpRequest();
      request.open("POST", "/api/jobs/upload");
      request.responseType = "json";

      request.upload.addEventListener("progress", function (progressEvent) {
        if (progressEvent.lengthComputable) {
          setUploadProgress(form, progressEvent.loaded, progressEvent.total);
        }
      });

      request.addEventListener("load", function () {
        submitButton.disabled = false;
        const bar = form.querySelector("[data-upload-progress-bar]");
        if (bar) bar.classList.remove("progress-bar-active");
        if (request.status >= 200 && request.status < 300) {
          const payload = request.response || {};
          const redirectUrl = payload.redirect_url || "/";
          window.location.assign(redirectUrl);
          return;
        }
        const meta = form.querySelector("[data-upload-progress-meta]");
        if (meta) {
          meta.textContent = t("Upload failed. Please try again.");
        }
      });

      request.addEventListener("error", function () {
        submitButton.disabled = false;
        const bar = form.querySelector("[data-upload-progress-bar]");
        if (bar) bar.classList.remove("progress-bar-active");
        const meta = form.querySelector("[data-upload-progress-meta]");
        if (meta) {
          meta.textContent = t("Upload failed. Please try again.");
        }
      });

      request.send(new FormData(form));
    });
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
    if (container.hasAttribute("data-queue-dnd-bound")) return;
    container.setAttribute("data-queue-dnd-bound", "true");
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
          const dashboardRoot = container.closest("[data-dashboard-root]");
          if (dashboardRoot && typeof dashboardRoot.__refreshDashboard === "function") {
            await dashboardRoot.__refreshDashboard();
          } else {
            window.location.reload();
          }
        } catch (_error) {
          window.location.reload();
        } finally {
          container.classList.remove("queue-reordering");
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    initScrollRestoration();

    const presetForm = document.querySelector("[data-preset-form]");
    if (presetForm) {
      initPresetForm(presetForm);
      initRepeatQuestion(presetForm);
      initUploadProgress(presetForm);
    }

    const dashboardRoot = document.querySelector("[data-dashboard-root]");
    if (dashboardRoot) initDashboard(dashboardRoot);

    const settingsRoot = document.querySelector("[data-settings-root]");
    if (settingsRoot) initSettingsPage(settingsRoot);

    const jobRoot = document.querySelector("[data-job-id]");
    if (jobRoot) initJobPage(jobRoot);
  });
})();
