from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import PROJECT_NAME, PROJECT_VERSION
from .config import TEMPLATES_DIR
from .i18n import translate, translate_value


PACKAGE_DIR = Path(__file__).resolve().parent
BUNDLED_FONT_DIR = PACKAGE_DIR / "assets" / "fonts"
SYSTEM_FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def _resolve_pdf_font_paths() -> tuple[Path, Path] | None:
    bundled_regular = BUNDLED_FONT_DIR / "DejaVuSans.ttf"
    bundled_bold = BUNDLED_FONT_DIR / "DejaVuSans-Bold.ttf"
    if bundled_regular.exists():
        return bundled_regular, bundled_bold if bundled_bold.exists() else bundled_regular

    system_regular = SYSTEM_FONT_DIR / "DejaVuSans.ttf"
    system_bold = SYSTEM_FONT_DIR / "DejaVuSans-Bold.ttf"
    if system_regular.exists():
        return system_regular, system_bold if system_bold.exists() else system_regular

    return None


# Нормализуем воспроизводимые метаданные, чтобы HTML, PDF и JSON использовали одинаковый контекст.
def _build_reproducibility_context(report_data: dict[str, Any]) -> dict[str, Any]:
    metadata = deepcopy(report_data.get("report_metadata") or {})
    engine = dict(metadata.get("engine") or {})
    runtime = dict(metadata.get("runtime") or {})

    return {
        "generated_at": str(metadata.get("generated_at") or report_data.get("generated_at") or ""),
        "engine_name": str(engine.get("name") or PROJECT_NAME),
        "engine_version": str(engine.get("version") or PROJECT_VERSION),
        "runtime_signature": str(engine.get("runtime_signature") or ""),
        "report_schema": str(metadata.get("report_schema") or "scanforge-report-v1"),
        "python_runtime": str(runtime.get("python") or ""),
        "host_platform": str(runtime.get("platform") or ""),
        "formats": [str(item) for item in (metadata.get("formats") or ["html", "pdf", "json"])],
    }


# Формируем единый манифест разделов, который затем одинаково отображается в HTML и PDF.
def _has_dependency_diff(report_data: dict[str, Any]) -> bool:
    dependency_diff = report_data.get("dependency_diff") or {}
    return bool(dependency_diff.get("baseline_available"))


def _build_section_manifest(report_data: dict[str, Any], language: str) -> list[dict[str, Any]]:
    summary = report_data.get("summary") or {}
    comparison = report_data.get("comparison") or {}
    checks: list[tuple[str, str, bool]] = [
        ("summary", "Executive summary", True),
        ("selected_checks", "Selected checks", True),
        ("project_snapshot", "Project snapshot", True),
        ("retest_baseline", "Retest baseline", bool(comparison)),
        ("ci_context", "CI/CD context", True),
        ("actions", "Recommended next actions", True),
        ("ai_review", "AI Review", bool(report_data.get("ai_review"))),
        ("finding_lifecycle", "Finding lifecycle", bool(comparison)),
        ("supply_chain", "Software supply chain", True),
        ("dependency_diff", "Dependency diff", _has_dependency_diff(report_data)),
        ("service_runtime", "DAST and IAST", bool(report_data.get("service_runtime"))),
        ("dynamic_runtime", "Instrumented runtime", True),
        ("vm_runtime", "VM and full-system runtime", bool(report_data.get("vm_runtime"))),
        ("release_gate", "Release gate", bool(report_data.get("release_gate"))),
        ("compliance", "Compliance profiles", bool(report_data.get("compliance_profiles"))),
        ("hardware", "Adaptive Hardware Plan", bool(report_data.get("host_hardware"))),
        ("knowledge_base", "Local Knowledge Base", bool(report_data.get("knowledge_base"))),
        ("tools", "Detected tools", bool(report_data.get("tools"))),
        ("top_findings", "Top findings", bool(summary.get("top_findings"))),
    ]
    return [
        {
            "key": key,
            "title": translate(language, title),
            "included": included,
        }
        for key, title, included in checks
    ]


def prepare_report_data(report_data: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(report_data)
    language = str(normalized.get("lang", "en"))
    normalized["reproducibility"] = _build_reproducibility_context(normalized)
    normalized["section_manifest"] = _build_section_manifest(normalized, language)
    return normalized


def render_html_report(report_data: dict, output_path: Path) -> None:
    normalized_report = prepare_report_data(report_data)
    language = str(normalized_report.get("lang", "en"))
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["tr"] = lambda text, **kwargs: translate(language, text, **kwargs)
    env.globals["label"] = lambda category, value: translate_value(language, category, value)
    template = env.get_template("report.html")
    output_path.write_text(template.render(report=normalized_report, lang=language), encoding="utf-8")


def _configure_pdf_font(pdf: FPDF) -> str:
    font_paths = _resolve_pdf_font_paths()
    if font_paths is not None:
        regular, bold = font_paths
        pdf.add_font("ScanForgeDejaVu", "", str(regular))
        pdf.add_font("ScanForgeDejaVu", "B", str(bold))
        return "ScanForgeDejaVu"
    return "Helvetica"


def build_pdf_report(report_data: dict, output_path: Path) -> None:
    report_data = prepare_report_data(report_data)
    language = str(report_data.get("lang", "en"))
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    font_family = _configure_pdf_font(pdf)
    reproducibility = report_data.get("reproducibility") or {}
    section_manifest = report_data.get("section_manifest") or []

    def write_line(text: str, *, bold: bool = False, size: int = 11, gap: int = 6) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(font_family, "B" if bold else "", size)
        pdf.multi_cell(content_width, gap, text)

    def write_list(title: str, items: list[str], *, empty_text: str) -> None:
        write_line(title, bold=True, size=12, gap=7)
        if items:
            for item in items[:5]:
                write_line(f"- {item}", size=10, gap=5)
        else:
            write_line(empty_text, size=10, gap=5)
        pdf.ln(1)

    pdf.set_font(font_family, "B", 16)
    write_line(translate(language, "ScanForge Report"), bold=True, size=16, gap=10)
    write_line(f"{translate(language, 'Job')}: {report_data['job']['name']} ({report_data['job']['id']})")
    write_line(f"{translate(language, 'Mode')}: {translate_value(language, 'mode', report_data['job']['mode'])}")
    write_line(translate(language, "Source file: {source}", source=report_data["job"]["original_filename"]))
    write_line(
        translate(
            language,
            "Retest scope: {scope}",
            scope=translate_value(language, "retest_scope", report_data["job"]["options"].get("retest_scope")),
        )
    )
    pdf.ln(2)

    write_line(translate(language, "Report reproducibility"), bold=True, size=13, gap=8)
    write_line(f"{translate(language, 'Generated at')}: {reproducibility.get('generated_at') or translate(language, 'none')}", gap=6)
    write_line(
        f"{translate(language, 'Engine')}: "
        f"{reproducibility.get('engine_name', PROJECT_NAME)} {reproducibility.get('engine_version', PROJECT_VERSION)}".strip(),
        gap=6,
    )
    write_line(
        f"{translate(language, 'Runtime signature')}: {reproducibility.get('runtime_signature') or translate(language, 'none')}",
        size=10,
        gap=5,
    )
    write_line(f"{translate(language, 'Report schema')}: {reproducibility.get('report_schema') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Python runtime')}: {reproducibility.get('python_runtime') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Host platform')}: {reproducibility.get('host_platform') or translate(language, 'none')}", gap=6)
    write_line(
        f"{translate(language, 'Formats')}: "
        f"{', '.join(reproducibility.get('formats', [])) or translate(language, 'none')}",
        gap=6,
    )
    pdf.ln(2)

    write_line(translate(language, "Report sections"), bold=True, size=13, gap=8)
    for section in section_manifest:
        status = translate(language, "included" if section.get("included") else "omitted")
        write_line(f"- {section.get('title', '')}: {status}", size=10, gap=5)
    pdf.ln(2)

    write_line(translate(language, "Summary"), bold=True, size=13, gap=8)
    summary = report_data["summary"]
    write_line(f"{translate(language, 'Risk score')}: {summary.get('risk_score', 0)}/100", gap=6)
    write_line(
        f"{translate(language, 'Highest severity')}: "
        f"{translate_value(language, 'severity', summary.get('highest_severity', 'info'))}",
        gap=6,
    )
    write_line(f"{translate(language, 'Execution verdict')}: {summary.get('execution_verdict', 'not-run')}", gap=6)
    for severity, count in summary["severity_counts"].items():
        write_line(f"{translate_value(language, 'severity', severity)}: {count}", gap=6)
    write_line(f"{translate(language, 'Total findings')}: {summary['total_findings']}", gap=6)
    pdf.ln(2)

    write_line(translate(language, "Selected checks"), bold=True, size=13, gap=8)
    write_line(
        ", ".join(translate_value(language, "check", item) for item in summary.get("selected_checks", []))
        or translate(language, "none"),
        gap=6,
    )
    pdf.ln(2)

    write_line(translate(language, "Project snapshot"), bold=True, size=13, gap=8)
    project = report_data["project"]
    write_line(translate(language, "Detected root: {root}", root=project.get("relative_root_name", "n/a")), gap=6)
    write_line(translate(language, "Files analyzed: {count}", count=project.get("file_count", 0)), gap=6)
    write_line(
        f"{translate(language, 'Build systems')}: {', '.join(project.get('build_systems', [])) or translate(language, 'none')}",
        gap=6,
    )
    write_line(
        f"{translate(language, 'Programming languages')}: "
        f"{', '.join(project.get('programming_languages', [])) or translate(language, 'none')}",
        gap=6,
    )
    write_line(
        f"{translate(language, 'Polyglot')}: {translate(language, 'yes' if project.get('polyglot') else 'no')}",
        gap=6,
    )
    write_line(f"{translate(language, 'Qt project: {value}', value=translate(language, 'yes' if project.get('is_qt_project') else 'no'))}", gap=6)
    write_line(f"{translate(language, 'Tests detected')}: {translate(language, 'yes' if project.get('has_tests') else 'no')}", gap=6)
    for note in (project.get("multilinguality") or {}).get("notes", [])[:4]:
        write_line(f"{translate(language, 'Multilinguality')}: {note}", size=10, gap=5)
    pdf.ln(2)

    comparison = report_data.get("comparison") or {}
    if comparison:
        write_line(translate(language, "Retest baseline"), bold=True, size=13, gap=8)
        write_line(
            translate(
                language,
                "Repeat submission: {value}",
                value=translate(language, "yes" if report_data["job"]["metadata"].get("repeat_submission") else "no"),
            ),
            gap=6,
        )
        write_line(f"{translate(language, 'Baseline job')}: {comparison.get('baseline_job_id', translate(language, 'none'))}", gap=6)
        write_line(f"{translate(language, 'Changed files')}: {comparison.get('changed_file_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Changed text files')}: {comparison.get('changed_text_file_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Removed files')}: {len(comparison.get('removed_files', []))}", gap=6)
        for path in comparison.get("changed_files", [])[:10]:
            write_line(f"{translate(language, 'Changed')}: {path}", size=10, gap=5)
        for path in comparison.get("removed_files", [])[:5]:
            write_line(f"{translate(language, 'Removed')}: {path}", size=10, gap=5)
        pdf.ln(2)

    ci_context = report_data.get("ci_context") or {}
    write_line(translate(language, "CI/CD context"), bold=True, size=13, gap=8)
    write_line(
        f"{translate(language, 'Integration provider')}: "
        f"{translate_value(language, 'integration_provider', ci_context.get('integration_provider') or 'manual')}",
        gap=6,
    )
    write_line(f"{translate(language, 'Repository')}: {ci_context.get('repository_url') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Branch')}: {ci_context.get('branch') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Commit')}: {ci_context.get('commit_sha') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Pipeline')}: {ci_context.get('pipeline_url') or translate(language, 'none')}", gap=6)
    write_line(f"{translate(language, 'Merge request')}: {ci_context.get('merge_request') or translate(language, 'none')}", gap=6)
    pdf.ln(2)

    hardware = report_data.get("host_hardware") or {}
    execution_plan = report_data.get("execution_plan") or {}
    if hardware:
        write_line(translate(language, "Adaptive Hardware Plan"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'CPU target')}: {hardware.get('cpu_threads_target', 0)}/{hardware.get('cpu_threads_total', 0)}", gap=6)
        write_line(f"{translate(language, 'RAM target')}: {hardware.get('memory_target_mb', 0)} MB", gap=6)
        write_line(translate(language, "GPUs detected: {count}", count=hardware.get("gpu_count", 0)), gap=6)
        write_line(f"{translate(language, 'Job CPU budget')}: {execution_plan.get('cpu_threads_for_job', 0)}", gap=6)
        write_line(f"{translate(language, 'Job RAM budget')}: {execution_plan.get('memory_mb_for_job', 0)} MB", gap=6)
        write_line(f"{translate(language, 'GPU strategy')}: {execution_plan.get('gpu_strategy', 'cpu-only')}", gap=6)
        if execution_plan.get("assigned_gpu_ids"):
            write_line(
                translate(
                    language,
                    "Assigned GPUs: {gpus}",
                    gpus=", ".join(str(item) for item in execution_plan.get("assigned_gpu_ids", [])),
                ),
                gap=6,
            )
        pdf.ln(2)

    knowledge_base = report_data.get("knowledge_base") or {}
    if knowledge_base:
        write_line(translate(language, "Local Knowledge Base"), bold=True, size=13, gap=8)
        write_line(
            f"{translate(language, 'Mirror available')}: {translate(language, 'yes' if knowledge_base.get('available') else 'no')}",
            gap=6,
        )
        write_line(f"{translate(language, 'Sources ready')}: {knowledge_base.get('source_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Matched references')}: {knowledge_base.get('matched_reference_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Project reference hits')}: {knowledge_base.get('project_reference_count', 0)}", gap=6)
        if knowledge_base.get("updated_at"):
            write_line(f"{translate(language, 'Last sync')}: {knowledge_base.get('updated_at')}", gap=6)
        pdf.ln(2)

    write_line(translate(language, "Recommended next actions"), bold=True, size=13, gap=8)
    for action in summary.get("next_actions", []):
        write_line(
            f"[{action.get('severity', 'info').upper()}] {action.get('title', 'Action')}: {action.get('recommendation', '')}",
            size=10,
            gap=6,
        )
    pdf.ln(2)

    ai_review = report_data.get("ai_review") or {}
    if ai_review:
        write_line(translate(language, "AI Review"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'Source')}: {ai_review.get('source', 'unknown')}", gap=6)
        write_line(f"{translate(language, 'Decision')}: {ai_review.get('release_decision', 'unknown')}", gap=6)
        write_line(
            f"{translate(language, 'Active playbooks')}: "
            f"{', '.join(translate(language, item) for item in ai_review.get('active_playbooks', [])) or translate(language, 'none')}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Routing reason')}: {ai_review.get('routing_reason') or translate(language, 'none')}",
            size=10,
            gap=5,
        )
        write_line(ai_review.get("overview", "No overview generated."), size=10, gap=5)
        write_line(ai_review.get("risk_narrative", "No risk narrative generated."), size=10, gap=5)
        pdf.ln(1)
        write_list(
            translate(language, "Root Causes"),
            list(ai_review.get("root_causes", [])),
            empty_text=translate(language, "No root causes generated."),
        )
        write_list(
            translate(language, "Fix Strategy"),
            list(ai_review.get("fix_strategy", [])),
            empty_text=translate(language, "No fix strategy generated."),
        )
        write_list(
            translate(language, "Suggested Tests"),
            list(ai_review.get("suggested_tests", [])),
            empty_text=translate(language, "No suggested tests generated."),
        )
        write_list(
            translate(language, "Fuzz Targets"),
            list(ai_review.get("fuzz_targets", [])),
            empty_text=translate(language, "No fuzz targets generated."),
        )
        write_list(
            translate(language, "Dependency Notes"),
            list(ai_review.get("dependency_notes", [])),
            empty_text=translate(language, "No dependency notes generated."),
        )
        write_list(
            translate(language, "Crash Clusters"),
            list(ai_review.get("crash_clusters", [])),
            empty_text=translate(language, "No crash clusters generated."),
        )
        write_list(
            translate(language, "Runtime Explanations"),
            list(ai_review.get("runtime_explanations", [])),
            empty_text=translate(language, "No runtime explanations generated."),
        )
        write_list(
            translate(language, "Patch Candidates"),
            list(ai_review.get("patch_candidates", [])),
            empty_text=translate(language, "No patch candidates generated."),
        )
        write_list(
            translate(language, "Regression Tests"),
            list(ai_review.get("regression_tests", [])),
            empty_text=translate(language, "No regression tests generated."),
        )
        pdf.ln(2)

    lifecycle = report_data.get("finding_lifecycle") or {}
    if comparison:
        write_line(translate(language, "Finding lifecycle"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'New findings')}: {lifecycle.get('new_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Persisting findings')}: {lifecycle.get('persisting_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Fixed findings')}: {lifecycle.get('fixed_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Tracked decisions')}: {lifecycle.get('tracked_decisions', 0)}", gap=6)
        write_line(f"{translate(language, 'Muted active')}: {lifecycle.get('muted_active_count', 0)}", gap=6)
        pdf.ln(2)

    dependencies = report_data.get("dependencies") or {}
    write_line(translate(language, "Software supply chain"), bold=True, size=13, gap=8)
    if dependencies.get("manifest_count", 0):
        write_line(f"{translate(language, 'Component count')}: {dependencies.get('component_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Dependency manifests')}: {dependencies.get('manifest_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Lockfiles')}: {dependencies.get('lockfile_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Resolved components')}: {dependencies.get('resolved_component_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Transitive components')}: {dependencies.get('transitive_component_count', 0)}", gap=6)
        write_line(
            f"{translate(language, 'Ecosystems')}: "
            f"{', '.join(sorted((dependencies.get('ecosystem_counts') or {}).keys())) or translate(language, 'none')}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Dependency flags')}: "
            f"{', '.join(f'{key}={value}' for key, value in (dependencies.get('flag_counts') or {}).items()) or translate(language, 'none')}",
            gap=6,
        )
        write_line(f"{translate(language, 'License gaps')}: {dependencies.get('license_gap_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Vulnerable components')}: {dependencies.get('vulnerable_component_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Reachable vulnerable components')}: {dependencies.get('reachable_vulnerable_component_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Suppressed vulnerabilities')}: {dependencies.get('suppressed_vulnerability_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Suppression rules')}: {dependencies.get('suppression_rule_count', 0)}", gap=6)
        for item in dependencies.get("top_vulnerable_components", [])[:5]:
            write_line(
                f"- {item.get('name')}: {item.get('version') or translate(language, 'none')} | "
                f"{translate(language, 'Reachable')}: {translate(language, 'yes' if item.get('reachable') else 'no')} | "
                f"{translate(language, 'Active vulnerabilities').lower()}: {item.get('active_vulnerability_count', 0)} | "
                f"KEV: {item.get('kev_count', 0)}",
                size=10,
                gap=5,
            )
            if item.get("cve_ids"):
                write_line(
                    f"  CVE: {', '.join(str(value) for value in item.get('cve_ids', [])[:5])}",
                    size=9,
                    gap=4,
                )
            if item.get("bdu_ids"):
                write_line(
                    f"  {translate(language, 'FSTEC IDs')}: {', '.join(str(value) for value in item.get('bdu_ids', [])[:5])}",
                    size=9,
                    gap=4,
                )
    else:
        write_line(translate(language, "No dependency manifests were detected for this run."), size=10, gap=5)
    pdf.ln(2)

    dependency_diff = report_data.get("dependency_diff") or {}
    if dependency_diff.get("baseline_available"):
        write_line(translate(language, "Dependency diff"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'New vulnerable dependencies')}: {dependency_diff.get('new_vulnerable_count', 0)}", gap=6)
        write_line(
            f"{translate(language, 'New reachable vulnerable dependencies')}: "
            f"{dependency_diff.get('new_reachable_vulnerable_count', 0)}",
            gap=6,
        )
        write_line(f"{translate(language, 'Fixed vulnerable dependencies')}: {dependency_diff.get('fixed_vulnerable_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Dependency baseline regressions')}: {dependency_diff.get('dependency_regression_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Added components')}: {dependency_diff.get('added_count', len(dependency_diff.get('added_components', [])))}", gap=6)
        write_line(f"{translate(language, 'Removed components')}: {dependency_diff.get('removed_count', len(dependency_diff.get('removed_components', [])))}", gap=6)
        write_line(
            f"{translate(language, 'Version changed components')}: "
            f"{dependency_diff.get('version_changed_count', len(dependency_diff.get('version_changed_components', [])))}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Current vulnerable components')}: {dependency_diff.get('current_vulnerable_count', 0)} | "
            f"{translate(language, 'Baseline vulnerable components')}: {dependency_diff.get('baseline_vulnerable_count', 0)} | "
            f"{translate(language, 'Vulnerable dependency delta').lower()}: {dependency_diff.get('vulnerability_count_delta', 0)}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Current reachable vulnerable components')}: {dependency_diff.get('current_reachable_vulnerable_count', 0)} | "
            f"{translate(language, 'Baseline reachable vulnerable components')}: {dependency_diff.get('baseline_reachable_vulnerable_count', 0)} | "
            f"{translate(language, 'Reachable vulnerable delta').lower()}: {dependency_diff.get('reachable_vulnerability_count_delta', 0)}",
            gap=6,
        )
        for item in dependency_diff.get("worsened_components", [])[:4]:
            write_line(
                f"- {item.get('name')}: {item.get('baseline_version') or translate(language, 'none')} -> "
                f"{item.get('current_version') or translate(language, 'none')} "
                f"({item.get('baseline_vulnerability_count', 0)} -> {item.get('current_vulnerability_count', 0)})",
                size=10,
                gap=5,
            )
        pdf.ln(2)

    service_runtime = report_data.get("service_runtime") or {}
    if service_runtime:
        write_line(translate(language, "DAST and IAST"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'Frameworks')}: {', '.join(service_runtime.get('frameworks', [])) or translate(language, 'none')}", gap=6)
        write_line(f"{translate(language, 'Detected routes')}: {service_runtime.get('route_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Route inventory')}: {service_runtime.get('route_inventory_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Route source files')}: {service_runtime.get('route_source_file_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Runtime target URL')}: {service_runtime.get('target_url') or translate(language, 'none')}", gap=6)
        write_line(f"{translate(language, 'Verified routes')}: {service_runtime.get('verified_route_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Source-correlated routes')}: {service_runtime.get('source_correlated_paths', 0)}", gap=6)
        write_line(f"{translate(language, 'Live verification requests')}: {service_runtime.get('verification_request_count', 0)}", gap=6)
        write_line(f"{translate(language, 'OpenAPI specs')}: {len(service_runtime.get('openapi_specs', []))}", gap=6)
        write_line(
            f"{translate(language, 'Verification profile')}: {translate(language, service_runtime.get('verification_profile', 'passive'))}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Authentication')}: {translate(language, service_runtime.get('auth_mode', 'none'))}",
            gap=6,
        )
        write_line(f"{translate(language, 'Request timeout, seconds')}: {service_runtime.get('request_timeout_seconds', 3)}", gap=6)
        write_line(f"{translate(language, 'Skipped requests')}: {len(service_runtime.get('skipped_requests', []))}", gap=6)
        write_line(f"{translate(language, 'Runtime server errors')}: {service_runtime.get('server_error_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Unauthenticated writes')}: {service_runtime.get('unauthenticated_write_count', 0)}", gap=6)
        write_line(f"{translate(language, 'Security-declared bypasses')}: {service_runtime.get('security_declared_bypass_count', 0)}", gap=6)
        if service_runtime.get("documentation_exposure_paths"):
            write_line(
                f"{translate(language, 'Exposed documentation surfaces')}: "
                f"{', '.join(str(item) for item in service_runtime.get('documentation_exposure_paths', []))}",
                gap=6,
            )
        if service_runtime.get("replay_script"):
            write_line(f"{translate(language, 'Verification replay')}: {service_runtime.get('replay_script')}", gap=6)
        for item in service_runtime.get("verification_results", [])[:8]:
            write_line(
                f"- {item.get('method', 'GET')} {item.get('path', '/')} -> HTTP {item.get('status', 0)} "
                f"[{translate(language, item.get('auth_used', 'none'))}]",
                size=10,
                gap=5,
            )
        pdf.ln(2)

    dynamic = report_data.get("dynamic_analysis") or {}
    write_line(translate(language, "Instrumented runtime"), bold=True, size=13, gap=8)
    if dynamic:
        write_line(f"{translate(language, 'Eligible')}: {translate(language, 'yes' if dynamic.get('eligible') else 'no')}", gap=6)
        write_line(
            f"{translate(language, 'Sanitizer configured')}: "
            f"{translate(language, 'yes' if dynamic.get('sanitizer_configured') else 'no')}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Sanitizer built')}: "
            f"{translate(language, 'yes' if dynamic.get('sanitizer_built') else 'no')}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Instrumented tests')}: "
            f"{translate(language, 'yes' if dynamic.get('sanitizer_tests_ran') else 'no')}",
            gap=6,
        )
        if dynamic.get("report"):
            write_line(f"{translate(language, 'Run log')}: {dynamic.get('report')}", gap=6)
    else:
        write_line(translate(language, "Dynamic analysis was not eligible for this job."), size=10, gap=5)
    pdf.ln(2)

    vm_runtime = report_data.get("vm_runtime") or {}
    if vm_runtime:
        write_line(translate(language, "VM and full-system runtime"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'Eligible')}: {translate(language, 'yes' if vm_runtime.get('eligible') else 'no')}", gap=6)
        write_line(f"{translate(language, 'Process trace')}: {translate(language, 'yes' if vm_runtime.get('process_trace_collected') else 'no')}", gap=6)
        write_line(f"{translate(language, 'Binary inventory')}: {len(vm_runtime.get('binary_inventory', []))}", gap=6)
        write_line(f"{translate(language, 'Taint tracking')}: {translate(language, 'yes' if vm_runtime.get('taint_tracking_available') else 'no')}", gap=6)
        if vm_runtime.get("crash_replay_script"):
            write_line(f"{translate(language, 'Crash replay')}: {vm_runtime.get('crash_replay_script')}", gap=6)
        pdf.ln(2)

    release_gate = report_data.get("release_gate") or {}
    if release_gate:
        write_line(translate(language, "Release gate"), bold=True, size=13, gap=8)
        write_line(f"{translate(language, 'Decision')}: {release_gate.get('decision', 'pass')}", gap=6)
        write_line(f"{translate(language, 'Policy hits')}: {len(release_gate.get('hits', []))}", gap=6)
        write_line(
            f"{translate(language, 'Policy source')}: "
            f"{release_gate.get('policy', {}).get('source', translate(language, 'default'))}",
            gap=6,
        )
        write_line(
            f"{translate(language, 'Risk score threshold')}: "
            f"{release_gate.get('policy', {}).get('review_on_risk_score_above', 0)}",
            gap=6,
        )
        for item in release_gate.get("hits", [])[:6]:
            write_line(f"- [{item.get('level')}] {item.get('message')} ({item.get('value')})", size=10, gap=5)
        pdf.ln(2)

    compliance_profiles = report_data.get("compliance_profiles") or {}
    if compliance_profiles:
        write_line(translate(language, "Compliance profiles"), bold=True, size=13, gap=8)
        for profile in compliance_profiles.get("profiles", []):
            write_line(
                f"{profile.get('label')}: "
                f"{profile.get('matched_rules', 0)}/{profile.get('total_rules', profile.get('matched_rules', 0))} "
                f"{translate(language, 'Rules covered').lower()} | "
                f"{translate(language, 'Mapped findings').lower()}: {profile.get('matched_findings', 0)} | "
                f"{translate(language, 'Coverage').lower()}: {profile.get('coverage_percent', 0)}% | "
                f"{translate(language, profile.get('status', 'gap'))}",
                gap=6,
            )
            for section in profile.get("report_sections", [])[:5]:
                write_line(
                    f"- {translate(language, 'Related report sections')}: {translate(language, section.get('title', ''))}",
                    size=10,
                    gap=5,
                )
            detail = (compliance_profiles.get("details") or {}).get(profile.get("profile"), {})
            for rule in detail.get("rules", [])[:6]:
                write_line(
                    f"{rule.get('control_id')}: {rule.get('title')} "
                    f"({translate(language, rule.get('status', 'gap'))}, {rule.get('match_count', 0)})",
                    size=10,
                    gap=5,
                )
                if rule.get("report_sections"):
                    write_line(
                        f"{translate(language, 'Related report sections')}: "
                        + ", ".join(translate(language, item.get("title", "")) for item in rule.get("report_sections", [])[:4]),
                        size=9,
                        gap=5,
                    )
                if rule.get("matches"):
                    for match in rule.get("matches", [])[:2]:
                        location = match.get("path") or "project"
                        if match.get("line"):
                            location = f"{location}:{match['line']}"
                        write_line(
                            f"- [{str(match.get('severity', 'info')).upper()}] {match.get('title')} | {location}",
                            size=9,
                            gap=5,
                        )
                        write_line(
                            f"{translate(language, 'Primary report section')}: "
                            f"{translate(language, match.get('report_section', {}).get('title', ''))}",
                            size=9,
                            gap=5,
                        )
                else:
                    write_line(translate(language, "No evidence mapped to this control."), size=9, gap=5)
        pdf.ln(2)

    write_line(translate(language, "Top findings"), bold=True, size=13, gap=8)
    for finding in report_data["summary"]["top_findings"][:15]:
        location = finding["path"] or "project"
        if finding.get("line"):
            location = f"{location}:{finding['line']}"
        write_line(
            f"[{finding['severity'].upper()}] {translate_value(language, 'category', finding['category'])} | {finding['title']} | {location}",
            size=10,
            gap=6,
        )
        write_line(finding["description"], size=10, gap=5)
        write_line(
            f"{translate(language, 'Lifecycle')}: "
            f"{translate_value(language, 'lifecycle_state', finding.get('lifecycle_state', 'new'))}",
            size=9,
            gap=5,
        )
        write_line(
            f"{translate(language, 'Review state')}: "
            f"{translate_value(language, 'review_state', finding.get('review_state', 'open'))}",
            size=9,
            gap=5,
        )
        if finding.get("recommendation"):
            write_line(f"{translate(language, 'Recommendation:')} {finding['recommendation']}", size=10, gap=5)
        for reference in finding.get("references", [])[:3]:
            write_line(
                translate(
                    language,
                    "Reference: {id} | {source} | {title}",
                    id=reference.get("id"),
                    source=reference.get("source", "Local KB"),
                    title=reference.get("title", ""),
                ),
                size=9,
                gap=5,
            )
        pdf.ln(1)

    if knowledge_base.get("top_references"):
        write_line(translate(language, "Matched Intelligence References"), bold=True, size=13, gap=8)
        for reference in knowledge_base.get("top_references", [])[:10]:
            write_line(
                f"{reference.get('id')} | {reference.get('source', 'Local KB')} | {reference.get('title', '')}",
                size=10,
                gap=6,
            )
            if reference.get("summary"):
                write_line(reference["summary"], size=9, gap=5)
            pdf.ln(1)

    tools = report_data.get("tools") or {}
    write_line(translate(language, "Detected tools"), bold=True, size=13, gap=8)
    if tools:
        for tool, path in tools.items():
            write_line(f"{tool}: {path or translate(language, 'not installed')}", size=10, gap=5)
    else:
        write_line(translate(language, "none"), size=10, gap=5)
    pdf.ln(2)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
