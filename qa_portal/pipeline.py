from __future__ import annotations

from datetime import datetime, timezone
import json
import platform
import traceback
from pathlib import Path
from typing import Any

from . import PROJECT_NAME, PROJECT_VERSION
from .analysis import (
    analyze_dynamic,
    analyze_functionality,
    analyze_fuzzing,
    analyze_quality,
    analyze_security,
    analyze_style,
    cleanup_job_paths,
    compare_project_versions,
    detect_project,
    extract_input,
    iter_text_files,
    run_clang_tidy,
    run_cppcheck,
    summarize_findings,
)
from .ai_review import build_ai_review_markdown, generate_ai_review
from .compliance import build_compliance_profiles
from .dependency_analysis import analyze_dependencies
from .finding_lifecycle import apply_review_states, compare_with_baseline
from .hardware import build_execution_plan, detect_host_hardware
from .knowledge_base import enrich_findings_with_knowledge_base
from .models import Artifact, Finding
from .release_gate import evaluate_release_gate
from .reporting import build_pdf_report, prepare_report_data, render_html_report
from .runtime import CURRENT_RUNTIME_SIGNATURE
from .runtime_scans import analyze_service_runtime, analyze_vm_runtime
from .sarif import import_sarif_tree, normalize_findings, write_sarif_report
from .storage import JobContext
from .tooling import detect_toolchain


class JobCancelledError(RuntimeError):
    pass


class JobPausedError(RuntimeError):
    pass


def _ensure_not_cancelled(ctx: JobContext, current_key: str | None = None) -> None:
    if not ctx.is_cancel_requested():
        return
    ctx.log("Cancellation requested. Stopping job.")
    ctx.cancel_pending_steps(current_key=current_key, message="Cancelled by user.")
    ctx.set_status("cancelled", progress=100, current_step="Cancelled", finished=True)
    raise JobCancelledError("Job cancelled by user.")


def _pause_if_requested(ctx: JobContext) -> None:
    if not ctx.is_pause_requested():
        return
    ctx.log("Pause requested. Job suspended at the nearest checkpoint.")
    current = ctx.get()
    ctx.set_metadata(
        {
            "pause_requested": False,
            "paused_at": current.updated_at,
        }
    )
    ctx.set_status("paused", progress=current.progress, current_step="Paused")
    raise JobPausedError("Job paused by user.")


def _step(ctx: JobContext, key: str, progress: int, message: str) -> None:
    _ensure_not_cancelled(ctx, key)
    _pause_if_requested(ctx)
    ctx.update_step(key, status="running", progress=progress, message=message)
    ctx.set_status("running", progress=progress, current_step=message)
    ctx.log(message)


def _finish_step(ctx: JobContext, key: str, progress: int, message: str) -> None:
    ctx.update_step(key, status="completed", progress=100, message=message)
    ctx.set_status("running", progress=progress, current_step=message)
    ctx.log(message)


def _skip_step(ctx: JobContext, key: str, progress: int, message: str) -> None:
    ctx.update_step(key, status="skipped", progress=100, message=message)
    ctx.set_status("running", progress=progress, current_step=message)
    ctx.log(message)


def _step_state(ctx: JobContext, key: str) -> str:
    for step in ctx.get().steps:
        if step.key == key:
            return step.status
    return "pending"


def _load_existing_source_root(ctx: JobContext) -> Path | None:
    job = ctx.get()
    candidate = job.extracted_path or job.metadata.get("source_root")
    if not candidate:
        return None
    path = Path(candidate)
    return path if path.exists() else None


def _current_execution_plan(ctx: JobContext, hardware_profile):
    running_job_ids = [item.id for item in ctx.store.list() if item.status == "running"]
    if ctx.job_id not in running_job_ids:
        running_job_ids.append(ctx.job_id)
    plan = build_execution_plan(
        job_id=ctx.job_id,
        running_job_ids=running_job_ids,
        profile=hardware_profile,
    )
    ctx.set_metadata({"execution_plan": plan.to_dict()})
    return plan


def run_job(ctx: JobContext) -> None:
    job = ctx.get()
    upload_path = Path(job.upload_path)
    workspace = Path(job.workspace_path)
    output_dir = Path(job.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    tools = detect_toolchain()
    hardware_profile = detect_host_hardware()
    options = job.options

    try:
        _ensure_not_cancelled(ctx)
        ctx.set_status("running", progress=3, current_step="Preparing workspace")
        ctx.set_metadata({"tools": tools})
        ctx.set_metadata({"host_hardware": hardware_profile.to_dict()})
        ctx.set_metadata({"selected_checks": options.enabled_checks(job.mode)})
        ctx.log(
            "Adaptive host profile detected: "
            f"{hardware_profile.cpu_threads_target}/{hardware_profile.cpu_threads_total} CPU threads, "
            f"{hardware_profile.memory_target_mb}/{hardware_profile.memory_total_mb} MB RAM target, "
            f"{len(hardware_profile.gpus)} GPU(s)."
        )

        source_root = _load_existing_source_root(ctx)
        if _step_state(ctx, "ingest") == "completed" and source_root is not None:
            input_type = ctx.get().metadata.get("input_type_detected", job.input_type)
            ctx.log("Reusing extracted workspace from paused job state.")
        else:
            _step(ctx, "ingest", 5, "Extracting uploaded input")
            source_root, input_type = extract_input(upload_path, workspace)
            ctx.set_metadata(
                {
                    "input_type_detected": input_type,
                    "source_root": str(source_root),
                }
            )
            ctx.store.mutate(ctx.job_id, lambda current: setattr(current, "extracted_path", str(source_root)))
            _finish_step(ctx, "ingest", 12, "Upload extracted")

        _pause_if_requested(ctx)

        if _step_state(ctx, "discovery") == "completed" and ctx.get().metadata.get("project"):
            project_info = ctx.get().metadata["project"]
            ctx.log("Reusing project discovery data from paused job state.")
        else:
            _step(ctx, "discovery", 15, "Inspecting project structure")
            project_info = detect_project(source_root)
            ctx.set_metadata({"project": project_info})
            _finish_step(ctx, "discovery", 25, "Project discovery complete")

        files = iter_text_files(source_root)
        comparison = ctx.get().metadata.get("comparison", {})
        retest_scope = getattr(options, "retest_scope", "full_project")
        changed_text_files: list[Path] = []
        baseline_source_root: Path | None = None
        baseline_job_record = None
        baseline_dependency_inventory: dict[str, Any] | None = None
        baseline_job_id = ctx.get().metadata.get("baseline_job_id")
        if comparison.get("changed_text_files"):
            file_map = {str(path.relative_to(source_root)): path for path in files}
            changed_text_files = [
                file_map[relative]
                for relative in comparison.get("changed_text_files", [])
                if relative in file_map
            ]
        elif baseline_job_id:
            try:
                baseline_job = ctx.store.load(baseline_job_id)
            except FileNotFoundError:
                baseline_job = None
            baseline_job_record = baseline_job
            if baseline_job is not None and Path(baseline_job.upload_path).exists():
                baseline_workspace = workspace / "baseline_compare"
                baseline_root, _baseline_input_type = extract_input(Path(baseline_job.upload_path), baseline_workspace)
                baseline_source_root = baseline_root
                comparison, changed_text_files = compare_project_versions(source_root, baseline_root)
                comparison.update(
                    {
                        "baseline_job_id": baseline_job.id,
                        "baseline_job_name": baseline_job.name,
                        "baseline_created_at": baseline_job.created_at,
                        "retest_scope": retest_scope,
                    }
                )
                ctx.set_metadata({"comparison": comparison})
                ctx.log(
                    "Loaded previous project baseline: "
                    f"{baseline_job.id} with {comparison.get('changed_file_count', 0)} changed files "
                    f"and {comparison.get('removed_files', []) and len(comparison.get('removed_files', [])) or 0} removed files."
                )
            else:
                comparison = {
                    "baseline_job_id": baseline_job_id,
                    "retest_scope": retest_scope,
                    "baseline_available": False,
                }
                ctx.set_metadata({"comparison": comparison})
                ctx.log("Previous baseline upload is unavailable, so the run will proceed without change comparison.")
        elif retest_scope == "changes_only":
            comparison = {
                "retest_scope": retest_scope,
                "baseline_available": False,
            }
            ctx.set_metadata({"comparison": comparison})

        analysis_files = files
        if retest_scope == "changes_only":
            analysis_files = changed_text_files
            ctx.log(
                "Incremental retest enabled: "
                f"{len(changed_text_files)} changed text files will be used for file-scoped checks."
            )

        all_findings: list[Finding] = list(ctx.get().findings)
        build_dir = workspace / "build"
        functionality_meta: dict[str, Any] = dict(ctx.get().metadata.get("functionality", {}))
        _ensure_not_cancelled(ctx)
        _pause_if_requested(ctx)

        if _step_state(ctx, "functionality") == "completed":
            ctx.log("Skipping functionality step because it was already completed before pause.")
        elif options.is_enabled("functionality", job.mode):
            functionality_plan = _current_execution_plan(ctx, hardware_profile)
            _step(ctx, "functionality", 28, "Evaluating build and test readiness")
            functionality_findings, functionality_logs, functionality_meta = analyze_functionality(
                source_root,
                project_info,
                tools,
                build_dir,
                functionality_plan,
                changes_only=retest_scope == "changes_only",
                changed_files=comparison.get("changed_files", []),
            )
            for entry in functionality_logs:
                ctx.log(entry)
            ctx.set_metadata({"functionality": functionality_meta})
            all_findings.extend(functionality_findings)
            ctx.add_findings(functionality_findings)
            _finish_step(
                ctx,
                "functionality",
                45,
                f"Functionality checks complete: {len(functionality_findings)} findings",
            )
            _pause_if_requested(ctx)
        else:
            _skip_step(ctx, "functionality", 45, "Functionality scan skipped")

        if _step_state(ctx, "security") == "completed":
            ctx.log("Skipping security step because it was already completed before pause.")
        elif options.is_enabled("security", job.mode):
            security_plan = _current_execution_plan(ctx, hardware_profile)
            _step(ctx, "security", 48, "Running built-in security checks")
            security_findings = analyze_security(
                source_root,
                analysis_files,
                max_workers=security_plan.file_scan_workers,
            )
            all_findings.extend(security_findings)
            ctx.add_findings(security_findings)
            _finish_step(ctx, "security", 58, f"Security checks complete: {len(security_findings)} findings")
            _pause_if_requested(ctx)
        else:
            _skip_step(ctx, "security", 58, "Security scan skipped")

        if _step_state(ctx, "style") == "completed":
            ctx.log("Skipping style step because it was already completed before pause.")
        elif options.is_enabled("style", job.mode):
            style_plan = _current_execution_plan(ctx, hardware_profile)
            _step(ctx, "style", 61, "Running style checks")
            style_findings = analyze_style(
                source_root,
                analysis_files,
                max_workers=style_plan.file_scan_workers,
            )
            clang_tidy_findings, clang_tidy_logs = run_clang_tidy(
                source_root,
                build_dir,
                tools,
                style_plan,
                focus_files=analysis_files,
            )
            for entry in clang_tidy_logs:
                ctx.log(entry)
            style_findings.extend(clang_tidy_findings)
            all_findings.extend(style_findings)
            ctx.add_findings(style_findings)
            _finish_step(ctx, "style", 72, f"Style checks complete: {len(style_findings)} findings")
            _pause_if_requested(ctx)
        else:
            _skip_step(ctx, "style", 72, "Style scan skipped")

        if _step_state(ctx, "quality") == "completed":
            ctx.log("Skipping quality step because it was already completed before pause.")
        elif options.is_enabled("quality", job.mode):
            quality_plan = _current_execution_plan(ctx, hardware_profile)
            _step(ctx, "quality", 75, "Running quality checks")
            quality_findings = analyze_quality(
                source_root,
                analysis_files,
                project_info,
                max_workers=quality_plan.file_scan_workers,
            )
            cppcheck_findings, cppcheck_logs = run_cppcheck(source_root, analysis_files, tools, quality_plan)
            for entry in cppcheck_logs:
                ctx.log(entry)
            quality_findings.extend(cppcheck_findings)
            all_findings.extend(quality_findings)
            ctx.add_findings(quality_findings)
            _finish_step(ctx, "quality", 86, f"Quality checks complete: {len(quality_findings)} findings")
            _pause_if_requested(ctx)
        else:
            _skip_step(ctx, "quality", 86, "Quality scan skipped")

        if _step_state(ctx, "dependency") == "completed":
            dependency_inventory = ctx.get().metadata.get("dependencies", {})
            ctx.log("Skipping dependency step because it was already completed before pause.")
        else:
            _step(ctx, "dependency", 88, "Running dependency and SCA checks")
            if baseline_source_root is not None:
                _baseline_findings, baseline_dependency_inventory = analyze_dependencies(baseline_source_root)
            dependency_findings, dependency_inventory = analyze_dependencies(
                source_root,
                baseline_inventory=baseline_dependency_inventory,
            )
            if dependency_inventory.get("component_count", 0):
                ctx.log(
                    "Dependency inventory complete: "
                    f"{dependency_inventory.get('component_count', 0)} components across "
                    f"{dependency_inventory.get('manifest_count', 0)} manifests."
                )
            ctx.set_metadata(
                {
                    "dependencies": dependency_inventory,
                    "dependency_diff": dependency_inventory.get("dependency_diff", {}),
                }
            )
            all_findings.extend(dependency_findings)
            ctx.add_findings(dependency_findings)
            _finish_step(ctx, "dependency", 90, f"Dependency and SCA checks complete: {len(dependency_findings)} findings")
            _pause_if_requested(ctx)

        if _step_state(ctx, "service_runtime") == "completed":
            service_runtime_meta = ctx.get().metadata.get("service_runtime", {})
            ctx.log("Skipping service runtime step because it was already completed before pause.")
        else:
            _step(ctx, "service_runtime", 91, "Running DAST and IAST oriented checks")
            service_runtime_context = dict(ctx.get().metadata.get("ci_context", {}))
            service_runtime_context.update(ctx.get().metadata.get("service_runtime_request", {}))
            service_runtime_findings, service_runtime_artifacts, service_runtime_logs, service_runtime_meta = analyze_service_runtime(
                source_root,
                output_dir,
                ci_context=service_runtime_context,
            )
            for entry in service_runtime_logs:
                ctx.log(entry)
            for artifact in service_runtime_artifacts:
                ctx.add_artifact(artifact)
            ctx.set_metadata({"service_runtime": service_runtime_meta})
            all_findings.extend(service_runtime_findings)
            ctx.add_findings(service_runtime_findings)
            _finish_step(ctx, "service_runtime", 92, f"DAST and IAST checks complete: {len(service_runtime_findings)} findings")
            _pause_if_requested(ctx)

        if _step_state(ctx, "dynamic") == "completed":
            dynamic_meta = ctx.get().metadata.get("dynamic_analysis", {})
            ctx.log("Skipping dynamic step because it was already completed before pause.")
        else:
            _step(ctx, "dynamic", 93, "Running instrumented runtime checks")
            dynamic_findings, dynamic_artifacts, dynamic_logs, dynamic_meta = analyze_dynamic(
                source_root,
                project_info,
                tools,
                build_dir,
                output_dir,
                functionality_meta,
                plan=_current_execution_plan(ctx, hardware_profile),
            )
            for entry in dynamic_logs:
                ctx.log(entry)
            for artifact in dynamic_artifacts:
                ctx.add_artifact(artifact)
            ctx.set_metadata({"dynamic_analysis": dynamic_meta})
            all_findings.extend(dynamic_findings)
            ctx.add_findings(dynamic_findings)
            _finish_step(ctx, "dynamic", 94, f"Instrumented runtime checks complete: {len(dynamic_findings)} findings")
            _pause_if_requested(ctx)

        if _step_state(ctx, "fuzzing") == "completed":
            ctx.log("Skipping fuzzing step because it was already completed before pause.")
        elif options.is_enabled("fuzzing", job.mode):
            fuzz_mode = job.mode if job.mode != "full_scan" else ("fuzz_single" if job.input_type == "single_file" else "fuzz_project")
            fuzz_plan = _current_execution_plan(ctx, hardware_profile)
            _step(ctx, "fuzzing", 95, "Preparing fuzzing assessment")
            fuzz_findings, fuzz_artifacts, fuzz_logs = analyze_fuzzing(
                source_root,
                analysis_files or files,
                tools,
                fuzz_mode,
                output_dir,
                options.fuzz_duration_seconds,
                fuzz_plan,
                focus_files=analysis_files if retest_scope == "changes_only" else None,
            )
            for entry in fuzz_logs:
                ctx.log(entry)
            for artifact in fuzz_artifacts:
                ctx.add_artifact(artifact)
            all_findings.extend(fuzz_findings)
            ctx.add_findings(fuzz_findings)
            _finish_step(ctx, "fuzzing", 96, f"Fuzzing assessment complete: {len(fuzz_findings)} findings")
            _pause_if_requested(ctx)
        else:
            _skip_step(ctx, "fuzzing", 96, "Fuzzing step skipped")

        if _step_state(ctx, "vm_runtime") == "completed":
            vm_runtime_meta = ctx.get().metadata.get("vm_runtime", {})
            ctx.log("Skipping VM runtime step because it was already completed before pause.")
        else:
            _step(ctx, "vm_runtime", 97, "Running VM and full-system runtime checks")
            vm_runtime_findings, vm_runtime_artifacts, vm_runtime_logs, vm_runtime_meta = analyze_vm_runtime(
                source_root,
                build_dir,
                output_dir,
                functionality_meta=functionality_meta,
            )
            for entry in vm_runtime_logs:
                ctx.log(entry)
            for artifact in vm_runtime_artifacts:
                ctx.add_artifact(artifact)
            ctx.set_metadata({"vm_runtime": vm_runtime_meta})
            all_findings.extend(vm_runtime_findings)
            ctx.add_findings(vm_runtime_findings)
            _finish_step(ctx, "vm_runtime", 98, f"VM and full-system runtime checks complete: {len(vm_runtime_findings)} findings")
            _pause_if_requested(ctx)

        _step(ctx, "reporting", 99, "Generating HTML, PDF, JSON, and SARIF reports")
        sarif_import_findings, sarif_import_summary = import_sarif_tree(source_root)
        if sarif_import_summary.get("file_count", 0):
            ctx.log(
                "Imported SARIF findings: "
                f"{sarif_import_summary.get('imported_findings', 0)} result(s) from "
                f"{sarif_import_summary.get('file_count', 0)} file(s)."
            )
            all_findings.extend(sarif_import_findings)
            ctx.add_findings(sarif_import_findings)
        ctx.set_metadata({"sarif_import": sarif_import_summary})

        functionality_meta = ctx.get().metadata.get("functionality", {})
        all_findings = normalize_findings(all_findings, source_root=source_root)
        all_findings, knowledge_base_summary = enrich_findings_with_knowledge_base(
            all_findings,
            root=source_root,
            files=files,
        )
        ctx.set_metadata({"knowledge_base": knowledge_base_summary})
        project_key = str(ctx.get().metadata.get("project_key", project_info.get("relative_root_name", "project")))
        lifecycle_state_summary = apply_review_states(project_key, all_findings)
        baseline_job_id = ctx.get().metadata.get("baseline_job_id")
        lifecycle_summary = {
            "baseline_total": 0,
            "current_total": len(all_findings),
            "new_count": len(all_findings),
            "persisting_count": 0,
            "fixed_count": 0,
            "new_findings": [],
            "persisting_findings": [],
            "fixed_findings": [],
            **lifecycle_state_summary,
        }
        if baseline_job_id:
            if baseline_job_record is None:
                try:
                    baseline_job_record = ctx.store.load(str(baseline_job_id))
                except FileNotFoundError:
                    baseline_job_record = None
            if baseline_job_record is not None:
                lifecycle_summary.update(compare_with_baseline(all_findings, list(baseline_job_record.findings)))
                lifecycle_summary.update(lifecycle_state_summary)
        lifecycle_summary["new_high_count"] = sum(
            1 for item in lifecycle_summary.get("new_findings", []) if item.get("severity") == "high"
        )
        lifecycle_summary["new_critical_count"] = sum(
            1 for item in lifecycle_summary.get("new_findings", []) if item.get("severity") == "critical"
        )
        lifecycle_summary["persisting_high_count"] = sum(
            1 for item in lifecycle_summary.get("persisting_findings", []) if item.get("severity") == "high"
        )
        ctx.set_metadata({"finding_lifecycle": lifecycle_summary})
        baseline_dependency_snapshot = (
            baseline_dependency_inventory
            or (baseline_job_record.metadata.get("dependencies", {}) if baseline_job_record is not None else {})
        )
        baseline_summary_snapshot = baseline_job_record.summaries if baseline_job_record is not None else {}
        baseline_snapshot = {}
        if baseline_job_record is not None:
            baseline_snapshot = {
                "job_id": baseline_job_record.id,
                "created_at": baseline_job_record.created_at,
                "risk_score": int(baseline_summary_snapshot.get("risk_score", 0) or 0),
                "total_findings": int(baseline_summary_snapshot.get("total_findings", 0) or 0),
                "highest_severity": str(baseline_summary_snapshot.get("highest_severity", "info") or "info"),
                "severity_counts": dict(baseline_summary_snapshot.get("severity_counts", {}) or {}),
                "vulnerable_component_count": int(baseline_dependency_snapshot.get("vulnerable_component_count", 0) or 0),
                "reachable_vulnerable_component_count": int(
                    baseline_dependency_snapshot.get("reachable_vulnerable_component_count", 0) or 0
                ),
                "component_count": int(baseline_dependency_snapshot.get("component_count", 0) or 0),
            }
        ctx.set_metadata({"baseline_snapshot": baseline_snapshot})
        ctx.store.mutate(ctx.job_id, lambda current, findings=all_findings: setattr(current, "findings", list(findings)))
        summary = summarize_findings(
            all_findings,
            functionality=functionality_meta,
            project_info=project_info,
            selected_checks=options.enabled_checks(job.mode),
        )
        ctx.set_summaries(summary)
        report_data = {
            "job": ctx.get().to_dict(),
            "lang": ctx.get().metadata.get("ui_language", "en"),
            "project": project_info,
            "summary": summary,
            "tools": tools,
            "host_hardware": hardware_profile.to_dict(),
            "execution_plan": ctx.get().metadata.get("execution_plan", {}),
            "findings": [finding.__dict__ for finding in all_findings[: options.max_report_findings]],
            "knowledge_base": knowledge_base_summary,
            "comparison": ctx.get().metadata.get("comparison", {}),
            "baseline_snapshot": baseline_snapshot,
            "dependencies": dependency_inventory,
            "dependency_diff": ctx.get().metadata.get("dependency_diff", {}),
            "finding_lifecycle": lifecycle_summary,
            "sarif_import": sarif_import_summary,
            "service_runtime": ctx.get().metadata.get("service_runtime", {}),
            "dynamic_analysis": dynamic_meta,
            "vm_runtime": ctx.get().metadata.get("vm_runtime", {}),
            "ci_context": ctx.get().metadata.get("ci_context", {}),
        }
        ai_review, ai_logs = generate_ai_review(report_data)
        for entry in ai_logs:
            ctx.log(entry)
        ctx.set_metadata({"ai_review": ai_review})
        report_data["ai_review"] = ai_review
        compliance_profiles = build_compliance_profiles(report_data)
        release_gate = evaluate_release_gate(report_data)
        ctx.set_metadata({"compliance_profiles": compliance_profiles, "release_gate": release_gate})
        report_data["compliance_profiles"] = compliance_profiles
        report_data["release_gate"] = release_gate
        report_metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_schema": "scanforge-report-v1",
            "formats": ["html", "pdf", "json", "sarif"],
            "engine": {
                "name": PROJECT_NAME,
                "version": PROJECT_VERSION,
                "runtime_signature": CURRENT_RUNTIME_SIGNATURE,
            },
            "runtime": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
        }
        ctx.set_metadata({"report_metadata": report_metadata})
        report_data["report_metadata"] = report_metadata
        report_data = prepare_report_data(report_data)
        html_path = output_dir / "report.html"
        pdf_path = output_dir / "report.pdf"
        json_path = output_dir / "report.json"
        sarif_path = output_dir / "report.sarif"
        ai_review_path = output_dir / "ai_review.md"
        kb_path = output_dir / "knowledge_base_matches.json"
        sbom_path = output_dir / "sbom.json"
        lifecycle_path = output_dir / "finding_lifecycle.json"
        release_gate_path = output_dir / "release_gate.json"
        executive_path = output_dir / "executive_summary.md"
        compliance_path = output_dir / "compliance_summary.json"
        dependency_path = output_dir / "dependency_inventory.md"
        integration_handoff_path = output_dir / "integration_handoff.md"
        render_html_report(report_data, html_path)
        build_pdf_report(report_data, pdf_path)
        json_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
        write_sarif_report(
            all_findings,
            sarif_path,
            root_uri=source_root.resolve().as_uri(),
            invocation={
                "executionSuccessful": True,
                "commandLine": f"{PROJECT_NAME} job {ctx.job_id}",
                "properties": {
                    "jobId": ctx.job_id,
                    "reportSchema": report_metadata["report_schema"],
                    "runtimeSignature": CURRENT_RUNTIME_SIGNATURE,
                },
            },
        )
        build_ai_review_markdown(ai_review, ai_review_path)
        kb_path.write_text(
            json.dumps(
                {
                    "summary": knowledge_base_summary,
                    "findings_with_references": [
                        finding.__dict__ for finding in all_findings if finding.references
                    ],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        sbom_path.write_text(json.dumps(dependency_inventory, indent=2, ensure_ascii=False), encoding="utf-8")
        lifecycle_path.write_text(json.dumps(lifecycle_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        release_gate_path.write_text(
            json.dumps(
                {
                    "job_id": ctx.job_id,
                    "decision": release_gate.get("decision", ai_review.get("release_decision", "review-before-release")),
                    "risk_score": summary.get("risk_score", 0),
                    "highest_severity": summary.get("highest_severity", "info"),
                    "new_findings": lifecycle_summary.get("new_count", 0),
                    "persisting_findings": lifecycle_summary.get("persisting_count", 0),
                    "dependency_components": dependency_inventory.get("component_count", 0),
                    "new_vulnerable_dependencies": ctx.get().metadata.get("dependency_diff", {}).get("new_vulnerable_count", 0),
                    "new_reachable_vulnerable_dependencies": ctx.get().metadata.get("dependency_diff", {}).get(
                        "new_reachable_vulnerable_count",
                        0,
                    ),
                    "dependency_regressions": ctx.get().metadata.get("dependency_diff", {}).get("dependency_regression_count", 0),
                    "baseline_snapshot": baseline_snapshot,
                    "policy_hits": release_gate.get("hits", []),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        executive_path.write_text(
            "\n".join(
                [
                    "# Executive summary",
                    "",
                    f"Job: {ctx.get().name} ({ctx.job_id})",
                    f"Decision: {release_gate.get('decision', ai_review.get('release_decision', 'review-before-release'))}",
                    f"Risk score: {summary.get('risk_score', 0)}/100",
                    f"Highest severity: {summary.get('highest_severity', 'info')}",
                    f"Execution verdict: {summary.get('execution_verdict', 'not-run')}",
                    f"Findings: {summary.get('total_findings', 0)}",
                    f"New findings: {lifecycle_summary.get('new_count', 0)}",
                    f"Persisting findings: {lifecycle_summary.get('persisting_count', 0)}",
                    f"New vulnerable dependencies: {ctx.get().metadata.get('dependency_diff', {}).get('new_vulnerable_count', 0)}",
                    "",
                    "Top actions:",
                    *[f"- {item.get('recommendation', '')}" for item in summary.get("next_actions", [])[:5]],
                ]
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        compliance_path.write_text(
            json.dumps(
                {
                    "profile": "scanforge-native",
                    "checks": options.enabled_checks(job.mode),
                    "knowledge_base_sources": knowledge_base_summary.get("source_count", 0),
                    "dependency_sbom_generated": bool(dependency_inventory.get("component_count", 0)),
                    "dynamic_analysis_eligible": bool(dynamic_meta.get("eligible")),
                    "report_formats": ["html", "pdf", "json"],
                    "profiles": compliance_profiles.get("profiles", []),
                    "details": compliance_profiles.get("details", {}),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        dependency_path.write_text(
            "\n".join(
                [
                    "# Dependency inventory",
                    "",
                    f"Components: {dependency_inventory.get('component_count', 0)}",
                    f"Manifests: {dependency_inventory.get('manifest_count', 0)}",
                    f"Ecosystems: {', '.join(sorted((dependency_inventory.get('ecosystem_counts') or {}).keys())) or 'none'}",
                    f"Flags: {json.dumps(dependency_inventory.get('flag_counts', {}), ensure_ascii=False)}",
                ]
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        integration_handoff_path.write_text(
            "\n".join(
                [
                    "# CI handoff",
                    "",
                    f"Provider: {report_data['ci_context'].get('integration_provider', 'manual')}",
                    f"Repository: {report_data['ci_context'].get('repository_url', '')}",
                    f"Branch: {report_data['ci_context'].get('branch', '')}",
                    f"Commit: {report_data['ci_context'].get('commit_sha', '')}",
                    f"Pipeline URL: {report_data['ci_context'].get('pipeline_url', '')}",
                ]
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        ctx.add_artifact(Artifact(label="JSON report", filename=json_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="SARIF report", filename=sarif_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="AI review", filename=ai_review_path.name, kind="text"))
        ctx.add_artifact(Artifact(label="Knowledge base matches", filename=kb_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="SBOM", filename=sbom_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="Finding lifecycle", filename=lifecycle_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="Release gate", filename=release_gate_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="Executive summary", filename=executive_path.name, kind="text"))
        ctx.add_artifact(Artifact(label="Compliance summary", filename=compliance_path.name, kind="json"))
        ctx.add_artifact(Artifact(label="Dependency inventory", filename=dependency_path.name, kind="text"))
        ctx.add_artifact(Artifact(label="CI handoff", filename=integration_handoff_path.name, kind="text"))
        ctx.set_report_paths(html_path.name, pdf_path.name)
        _finish_step(ctx, "reporting", 100, "Reports generated")

        ctx.set_status("completed", progress=100, current_step="Completed", finished=True)
        ctx.log("Job completed successfully.")
    except JobCancelledError:
        pass
    except JobPausedError:
        pass
    except Exception as exc:  # pragma: no cover - failure path
        ctx.log(f"Job failed: {exc}")
        ctx.log(traceback.format_exc())
        ctx.update_step(
            "reporting",
            status="failed",
            progress=0,
            message="Execution failed before report generation.",
        )
        ctx.set_status("failed", progress=100, current_step="Failed", finished=True)
    finally:
        if ctx.get().status != "paused":
            for message in cleanup_job_paths(upload_path, workspace):
                ctx.log(message)
