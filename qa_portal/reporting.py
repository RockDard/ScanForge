from __future__ import annotations

from pathlib import Path

from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import TEMPLATES_DIR
from .i18n import translate, translate_value


def render_html_report(report_data: dict, output_path: Path) -> None:
    language = str(report_data.get("lang", "en"))
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["tr"] = lambda text, **kwargs: translate(language, text, **kwargs)
    env.globals["label"] = lambda category, value: translate_value(language, category, value)
    template = env.get_template("report.html")
    output_path.write_text(template.render(report=report_data, lang=language), encoding="utf-8")


def _configure_pdf_font(pdf: FPDF) -> str:
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    if regular.exists():
        pdf.add_font("DejaVu", "", str(regular))
        pdf.add_font("DejaVu", "B", str(bold if bold.exists() else regular))
        return "DejaVu"
    return "Helvetica"


def build_pdf_report(report_data: dict, output_path: Path) -> None:
    language = str(report_data.get("lang", "en"))
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    font_family = _configure_pdf_font(pdf)

    def write_line(text: str, *, bold: bool = False, size: int = 11, gap: int = 6) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(font_family, "B" if bold else "", size)
        pdf.multi_cell(content_width, gap, text)

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
    write_line(f"{translate(language, 'Qt project: {value}', value=translate(language, 'yes' if project.get('is_qt_project') else 'no'))}", gap=6)
    write_line(f"{translate(language, 'Tests detected')}: {translate(language, 'yes' if project.get('has_tests') else 'no')}", gap=6)
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
        write_line(ai_review.get("overview", "No overview generated."), size=10, gap=5)
        write_line(ai_review.get("risk_narrative", "No risk narrative generated."), size=10, gap=5)
        pdf.ln(2)

    write_line(translate(language, "Top findings"), bold=True, size=13, gap=8)
    for finding in report_data["summary"]["top_findings"][:15]:
        location = finding["path"] or "project"
        if finding.get("line"):
            location = f"{location}:{finding['line']}"
        write_line(
            f"[{finding['severity'].upper()}] {finding['category']} | {finding['title']} | {location}",
            size=10,
            gap=6,
        )
        write_line(finding["description"], size=10, gap=5)
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

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
