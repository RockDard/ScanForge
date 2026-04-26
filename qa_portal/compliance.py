from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ComplianceRule:
    profile: str
    control_id: str
    title: str
    categories: tuple[str, ...]
    min_severity: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
    keyword_hints: tuple[str, ...] = ()
    rationale: str = ""


SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


# Регуляторные профили храним локально и детерминированно, чтобы отчеты были воспроизводимыми.
COMPLIANCE_RULES: tuple[ComplianceRule, ...] = (
    ComplianceRule(
        profile="fstec",
        control_id="FSTEC-DEV-SEC-01",
        title="Безопасная обработка входных данных",
        categories=("security", "dynamic", "service-runtime"),
        keyword_hints=("input", "overflow", "injection", "shell", "ssl", "tls"),
        rationale="Проверки должны фиксировать риски небезопасной обработки данных и сетевого взаимодействия.",
    ),
    ComplianceRule(
        profile="fstec",
        control_id="FSTEC-DEV-SEC-02",
        title="Контроль зависимостей и уязвимостей поставки",
        categories=("dependency",),
        min_severity=("low", "medium", "high", "critical"),
        rationale="Зависимости и внешние компоненты должны быть прослеживаемы и проверяемы по локальным каталогам уязвимостей.",
    ),
    ComplianceRule(
        profile="gost",
        control_id="GOST-QUALITY-01",
        title="Контроль качества и сопровождаемости кода",
        categories=("quality", "style"),
        min_severity=("low", "medium", "high", "critical"),
        rationale="Отчет должен отражать риски поддерживаемости, избыточности и устойчивости кода.",
    ),
    ComplianceRule(
        profile="gost",
        control_id="GOST-TEST-02",
        title="Подтверждение работоспособности и испытаний",
        categories=("functionality", "dynamic", "vm-runtime"),
        min_severity=("info", "low", "medium", "high", "critical"),
        rationale="Результаты сборки, тестов и инструментированных прогонов должны быть трассируемы.",
    ),
    ComplianceRule(
        profile="pci_dss",
        control_id="PCI-6.3.2",
        title="Безопасная разработка и исправление уязвимостей",
        categories=("security", "dependency", "service-runtime"),
        min_severity=("medium", "high", "critical"),
        keyword_hints=("secret", "token", "password", "http", "tls", "api"),
        rationale="Критичные и высокие риски должны быть вынесены в отдельный policy-блок релизного решения.",
    ),
    ComplianceRule(
        profile="pci_dss",
        control_id="PCI-6.4.1",
        title="Тестирование после изменений",
        categories=("functionality", "dynamic", "fuzzing"),
        min_severity=("info", "low", "medium", "high", "critical"),
        rationale="После изменений должны быть отражены регрессия, фаззинг и влияние на baseline.",
    ),
)


PROFILE_LABELS = {
    "fstec": "ФСТЭК",
    "gost": "ГОСТ",
    "pci_dss": "PCI DSS",
}

REPORT_SECTION_REGISTRY: dict[str, dict[str, str]] = {
    "selected_checks": {"title": "Selected checks", "anchor": "selected-checks"},
    "finding_lifecycle": {"title": "Finding lifecycle", "anchor": "finding-lifecycle"},
    "supply_chain": {"title": "Software supply chain", "anchor": "software-supply-chain"},
    "dependency_diff": {"title": "Dependency diff", "anchor": "dependency-diff"},
    "service_runtime": {"title": "DAST and IAST", "anchor": "dast-iast"},
    "dynamic_runtime": {"title": "Instrumented runtime", "anchor": "instrumented-runtime"},
    "vm_runtime": {"title": "VM and full-system runtime", "anchor": "vm-full-system-runtime"},
    "release_gate": {"title": "Release gate", "anchor": "release-gate"},
    "top_findings": {"title": "Top findings", "anchor": "top-findings"},
}

CATEGORY_REPORT_SECTIONS: dict[str, tuple[str, ...]] = {
    "functionality": ("top_findings", "selected_checks"),
    "security": ("top_findings", "release_gate"),
    "style": ("top_findings",),
    "quality": ("top_findings",),
    "fuzzing": ("top_findings", "selected_checks"),
    "dependency": ("supply_chain", "dependency_diff", "top_findings"),
    "service-runtime": ("service_runtime", "release_gate", "top_findings"),
    "dynamic": ("dynamic_runtime", "top_findings"),
    "vm-runtime": ("vm_runtime", "top_findings"),
}


def _severity_meets(rule: ComplianceRule, severity: str) -> bool:
    return severity in rule.min_severity


def _matches_rule(rule: ComplianceRule, finding: dict[str, Any]) -> bool:
    if str(finding.get("category", "")) not in rule.categories:
        return False
    if not _severity_meets(rule, str(finding.get("severity", "info"))):
        return False
    if not rule.keyword_hints:
        return True
    haystack = " ".join(
        [
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("recommendation", "")),
            str(finding.get("source", "")),
        ]
    ).casefold()
    return any(keyword.casefold() in haystack for keyword in rule.keyword_hints)


def _section_included(report_data: dict[str, Any], section_key: str) -> bool:
    comparison = report_data.get("comparison") or {}
    summary = report_data.get("summary") or {}
    checks = {
        "selected_checks": True,
        "finding_lifecycle": bool(comparison),
        "supply_chain": bool(report_data.get("dependencies")),
        "dependency_diff": bool((report_data.get("dependency_diff") or {}).get("baseline_available")),
        "service_runtime": bool(report_data.get("service_runtime")),
        "dynamic_runtime": True,
        "vm_runtime": bool(report_data.get("vm_runtime")),
        "release_gate": bool(report_data.get("release_gate")),
        "top_findings": bool(summary.get("top_findings") or report_data.get("findings")),
    }
    return bool(checks.get(section_key, False))


def _section_payload(section_key: str, report_data: dict[str, Any]) -> dict[str, Any]:
    metadata = REPORT_SECTION_REGISTRY.get(section_key, {"title": section_key, "anchor": section_key.replace("_", "-")})
    return {
        "key": section_key,
        "title": metadata["title"],
        "anchor": metadata["anchor"],
        "included": _section_included(report_data, section_key),
    }


def _finding_ref(finding: dict[str, Any]) -> str:
    path = str(finding.get("path", "") or "project")
    line = finding.get("line")
    location = f"{path}:{line}" if line else path
    return f"{finding.get('category', 'unknown')}::{finding.get('title', '')}::{location}"


def _sections_for_finding(finding: dict[str, Any], report_data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    keys = CATEGORY_REPORT_SECTIONS.get(str(finding.get("category", "")), ("top_findings",))
    sections = [
        _section_payload(section_key, report_data)
        for section_key in keys
        if _section_included(report_data, section_key)
    ]
    if not sections:
        sections = [_section_payload("top_findings", report_data)]
    return sections[0], sections[1:]


# По каждому профилю строим трассируемый mapping: правило -> связанные findings -> evidence.
def build_compliance_profiles(report_data: dict[str, Any]) -> dict[str, Any]:
    findings = list(report_data.get("findings", []))
    profiles: dict[str, dict[str, Any]] = {}

    for profile_key, profile_label in PROFILE_LABELS.items():
        profiles[profile_key] = {
            "profile": profile_key,
            "label": profile_label,
            "total_rules": 0,
            "matched_rules": 0,
            "matched_findings": 0,
            "coverage_percent": 0,
            "status": "gap",
            "report_sections": [],
            "rules": [],
        }

    for rule in COMPLIANCE_RULES:
        matches: list[dict[str, Any]] = []
        for finding in findings:
            if not _matches_rule(rule, finding):
                continue
            primary_section, related_sections = _sections_for_finding(finding, report_data)
            matches.append(
                {
                    "finding_ref": _finding_ref(finding),
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", "info"),
                    "category": finding.get("category", ""),
                    "path": finding.get("path", ""),
                    "line": finding.get("line"),
                    "source": finding.get("source", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "report_section": primary_section,
                    "related_sections": related_sections,
                }
            )
        matches.sort(
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item.get("severity", "info")), 0),
                str(item.get("category", "")),
                str(item.get("path", "")),
                int(item.get("line") or 0),
            )
        )
        rule_payload = {
            "control_id": rule.control_id,
            "title": rule.title,
            "rationale": rule.rationale,
            "status": "covered" if matches else "gap",
            "match_count": len(matches),
            "report_sections": sorted(
                {
                    section["key"]: section
                    for item in matches
                    for section in [item["report_section"], *item.get("related_sections", [])]
                }.values(),
                key=lambda item: item["title"],
            ),
            "matches": matches[:12],
        }
        profiles[rule.profile]["rules"].append(rule_payload)
        profiles[rule.profile]["total_rules"] += 1
        if matches:
            profiles[rule.profile]["matched_rules"] += 1
            profiles[rule.profile].setdefault("_finding_refs", set()).update(item["finding_ref"] for item in matches)
            profiles[rule.profile].setdefault("_report_sections", {}).update(
                {
                    section["key"]: section
                    for item in matches
                    for section in [item["report_section"], *item.get("related_sections", [])]
                }
            )

    summaries = []
    for profile_key in ("fstec", "gost", "pci_dss"):
        profile = profiles[profile_key]
        finding_refs = profile.pop("_finding_refs", set())
        report_sections = profile.pop("_report_sections", {})
        profile["matched_findings"] = len(finding_refs)
        profile["report_sections"] = sorted(report_sections.values(), key=lambda item: item["title"])
        if profile["total_rules"]:
            profile["coverage_percent"] = int(round((profile["matched_rules"] / profile["total_rules"]) * 100))
        if profile["matched_rules"] == 0:
            profile["status"] = "gap"
        elif profile["matched_rules"] == profile["total_rules"]:
            profile["status"] = "covered"
        else:
            profile["status"] = "partial"
        summaries.append(
            {
                "profile": profile["profile"],
                "label": profile["label"],
                "total_rules": profile["total_rules"],
                "matched_rules": profile["matched_rules"],
                "matched_findings": profile["matched_findings"],
                "coverage_percent": profile["coverage_percent"],
                "status": profile["status"],
                "report_sections": profile["report_sections"],
            }
        )

    return {
        "profiles": summaries,
        "details": profiles,
    }
