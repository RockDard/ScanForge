import tempfile
import unittest
from pathlib import Path

try:
    from qa_portal.reporting import (
        _resolve_pdf_font_paths,
        build_pdf_report,
        prepare_report_data,
        render_html_report,
    )
except ModuleNotFoundError as exc:
    if exc.name == "fpdf":
        raise unittest.SkipTest("reporting tests require fpdf2 from requirements.txt") from exc
    raise


# Базовый набор данных отчета покрывает HTML/PDF рендер и содержит кириллицу для проверки Unicode-шрифтов.
def sample_report_data() -> dict:
    top_finding = {
        "severity": "high",
        "category": "security",
        "title": "Опасное копирование строки",
        "description": "Обнаружен небезопасный вызов strcpy в пользовательском буфере.",
        "path": "src/main.cpp",
        "line": 14,
        "source": "built-in-security-rules",
        "recommendation": "Замените strcpy на bounded-вариант и добавьте проверку длины.",
        "references": [
            {
                "id": "CWE-120",
                "source": "CWE",
                "title": "Buffer Copy without Checking Size of Input",
                "flags": ["memory-safety"],
            }
        ],
        "lifecycle_state": "new",
        "review_state": "open",
    }
    return {
        "lang": "ru",
        "job": {
            "name": "Русский отчет",
            "id": "job-report-001",
            "mode": "full_scan",
            "status": "completed",
            "original_filename": "project.zip",
            "options": {
                "preset": "balanced",
                "retest_scope": "full_project",
            },
            "metadata": {
                "repeat_submission": False,
            },
        },
        "project": {
            "relative_root_name": "sample_qt_project",
            "file_count": 12,
            "build_systems": ["cmake"],
            "is_qt_project": True,
            "has_tests": True,
            "programming_languages": ["C++", "QML"],
            "polyglot": True,
            "multilinguality": {
                "notes": ["Проект сочетает C++ и QML, поэтому важно держать единые правила интерфейсных контрактов."],
            },
        },
        "summary": {
            "risk_score": 64,
            "highest_severity": "high",
            "execution_verdict": "build-and-tests-ran",
            "total_findings": 1,
            "selected_checks": ["functionality", "security", "style"],
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "category_breakdown": [
                {"category": "security", "count": 1},
            ],
            "next_actions": [
                {
                    "severity": "high",
                    "title": "Исправить небезопасное копирование",
                    "recommendation": "Перевести копирование на ограниченный API и прогнать регрессионные тесты.",
                }
            ],
            "top_findings": [top_finding],
        },
        "tools": {
            "cmake": "/usr/bin/cmake",
            "clang-tidy": "/usr/bin/clang-tidy",
        },
        "host_hardware": {
            "cpu_threads_target": 14,
            "cpu_threads_total": 16,
            "memory_target_mb": 24576,
            "gpu_count": 0,
            "gpus": [],
        },
        "execution_plan": {
            "cpu_threads_for_job": 8,
            "memory_mb_for_job": 8192,
            "gpu_strategy": "cpu-only",
            "assigned_gpu_ids": [],
        },
        "findings": [top_finding],
        "knowledge_base": {
            "available": True,
            "source_count": 2,
            "matched_reference_count": 1,
            "project_reference_count": 1,
            "updated_at": "2026-04-13T12:00:00+00:00",
            "sources": [
                {"label": "CWE", "count": 1, "status": "ready"},
                {"label": "FSTEC", "count": 0, "status": "cached"},
            ],
            "top_references": [
                {
                    "id": "CWE-120",
                    "source": "CWE",
                    "title": "Buffer Copy without Checking Size of Input",
                    "summary": "Potential classic buffer overflow pattern.",
                    "flags": ["memory-safety"],
                }
            ],
        },
        "comparison": {},
        "dependencies": {
            "manifest_count": 0,
            "component_count": 0,
            "lockfile_count": 0,
            "resolved_component_count": 0,
            "transitive_component_count": 0,
            "ecosystem_counts": {},
            "flag_counts": {},
            "license_gap_count": 0,
            "vulnerable_component_count": 0,
            "reachable_vulnerable_component_count": 0,
            "suppressed_vulnerability_count": 0,
            "manifests": [],
        },
        "dependency_diff": {},
        "finding_lifecycle": {},
        "service_runtime": {},
        "dynamic_analysis": {},
        "vm_runtime": {},
        "ci_context": {
            "integration_provider": "manual",
            "repository_url": "",
            "branch": "",
            "commit_sha": "",
            "pipeline_url": "",
            "merge_request": "",
        },
        "ai_review": {
            "source": "local-fallback",
            "release_decision": "needs-fixes",
            "confidence": "medium",
            "model": "ScanForge Local Analyst",
            "overview": "Локальный обзор рекомендует исправить найденную проблему памяти перед релизом.",
            "risk_narrative": "Основной риск связан с переполнением буфера в пользовательском коде.",
            "blockers": ["Исправить strcpy и повторно проверить путь обработки пользовательского ввода."],
            "quick_wins": ["Добавить unit-тест на длинный ввод."],
            "root_causes": ["Используется небезопасный API работы со строками."],
            "fix_strategy": ["Заменить strcpy на безопасную обертку с ограничением длины."],
            "suggested_tests": ["Проверить копирование строки длиной 4 КБ."],
            "fuzz_targets": ["src/main.cpp:copy_user_name"],
            "dependency_notes": [],
            "reason": "Сгенерировано локально.",
        },
        "release_gate": {
            "decision": "needs-fixes",
            "hits": [
                {"rule_id": "RG-001", "level": "high", "message": "High severity finding present", "value": 1}
            ],
        },
        "compliance_profiles": {
            "profiles": [
                {
                    "profile": "fstec",
                    "label": "FSTEC",
                    "matched_rules": 1,
                    "total_rules": 2,
                    "matched_findings": 1,
                    "coverage_percent": 50,
                    "status": "partial",
                    "report_sections": [
                        {"key": "service_runtime", "title": "DAST and IAST", "anchor": "dast-iast", "included": True}
                    ],
                },
            ],
            "details": {
                "fstec": {
                    "rules": [
                        {
                            "control_id": "FSTEC-DEV-SEC-01",
                            "title": "Безопасная обработка входных данных",
                            "rationale": "Проверки должны фиксировать риски небезопасной обработки данных и сетевого взаимодействия.",
                            "status": "covered",
                            "match_count": 1,
                            "report_sections": [
                                {"key": "service_runtime", "title": "DAST and IAST", "anchor": "dast-iast", "included": True}
                            ],
                            "matches": [
                                {
                                    "finding_ref": "service-runtime::Controlled service verification completed::project",
                                    "title": "Controlled service verification completed",
                                    "severity": "medium",
                                    "category": "service-runtime",
                                    "path": "",
                                    "line": None,
                                    "source": "service-runtime",
                                    "recommendation": "Replay the verified routes.",
                                    "report_section": {
                                        "key": "service_runtime",
                                        "title": "DAST and IAST",
                                        "anchor": "dast-iast",
                                        "included": True,
                                    },
                                    "related_sections": [
                                        {"key": "release_gate", "title": "Release gate", "anchor": "release-gate", "included": True},
                                        {"key": "top_findings", "title": "Top findings", "anchor": "top-findings", "included": True},
                                    ],
                                }
                            ],
                        }
                    ]
                }
            },
        },
        "report_metadata": {
            "generated_at": "2026-04-13T20:15:00+00:00",
            "report_schema": "scanforge-report-v1",
            "formats": ["html", "pdf", "json"],
            "engine": {
                "name": "ScanForge",
                "version": "0.2.0",
                "runtime_signature": "deadbeefcafebabe",
            },
            "runtime": {
                "python": "3.12.3",
                "platform": "Linux-6.8.0-test-x86_64",
            },
        },
    }


class ReportingTests(unittest.TestCase):
    def test_prepare_report_data_adds_reproducibility_and_manifest(self):
        report = prepare_report_data(sample_report_data())

        self.assertEqual(report["reproducibility"]["engine_name"], "ScanForge")
        self.assertEqual(report["reproducibility"]["runtime_signature"], "deadbeefcafebabe")
        manifest = {item["key"]: item for item in report["section_manifest"]}
        self.assertTrue(manifest["summary"]["included"])
        self.assertTrue(manifest["supply_chain"]["included"])
        self.assertTrue(manifest["dynamic_runtime"]["included"])
        self.assertTrue(manifest["tools"]["included"])
        self.assertFalse(manifest["finding_lifecycle"]["included"])
        self.assertFalse(manifest["dependency_diff"]["included"])
        self.assertTrue(manifest["ai_review"]["included"])

    def test_pdf_font_paths_prefer_bundled_repo_fonts(self):
        regular, bold = _resolve_pdf_font_paths() or (None, None)

        self.assertIsNotNone(regular)
        self.assertIsNotNone(bold)
        self.assertIn("qa_portal/assets/fonts", str(regular))
        self.assertIn("qa_portal/assets/fonts", str(bold))

    def test_html_and_pdf_reports_render_for_russian_locale(self):
        report = sample_report_data()

        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "report.html"
            pdf_path = Path(temp_dir) / "report.pdf"

            render_html_report(report, html_path)
            build_pdf_report(report, pdf_path)

            html = html_path.read_text(encoding="utf-8")
            pdf_exists = pdf_path.exists()
            pdf_size = pdf_path.stat().st_size

        self.assertIn("Отчет ScanForge", html)
        self.assertIn("Воспроизводимость отчета", html)
        self.assertIn("Разделы отчета", html)
        self.assertIn("FSTEC-DEV-SEC-01", html)
        self.assertIn("Опасное копирование строки", html)
        self.assertTrue(pdf_exists)
        self.assertGreater(pdf_size, 1024)

    def test_service_runtime_report_uses_verified_route_metrics(self):
        report = sample_report_data()
        report["service_runtime"] = {
            "frameworks": ["fastapi"],
            "route_count": 4,
            "route_inventory_count": 6,
            "route_source_file_count": 2,
            "target_url": "http://127.0.0.1:8080",
            "verified_route_count": 5,
            "source_correlated_paths": 3,
            "verification_request_count": 7,
            "openapi_specs": ["openapi.json"],
            "verification_profile": "safe-active",
            "auth_mode": "none",
            "request_timeout_seconds": 5,
            "skipped_requests": [],
            "server_error_count": 1,
            "unauthenticated_write_count": 1,
            "security_declared_bypass_count": 2,
            "documentation_exposure_paths": ["/openapi.json", "/swagger"],
            "replay_script": "verification_replay.sh",
            "route_inventory": [],
            "verification_results": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "runtime-report.html"
            pdf_path = Path(temp_dir) / "runtime-report.pdf"
            render_html_report(report, html_path)
            build_pdf_report(report, pdf_path)
            html = html_path.read_text(encoding="utf-8")
            pdf_size = pdf_path.stat().st_size

        self.assertIn("<strong>Подтвержденные маршруты</strong><br>5", html)
        self.assertIn("<strong>Маршруты с привязкой к исходникам</strong><br>3", html)
        self.assertIn("<strong>Исходные файлы маршрутов</strong><br>2", html)
        self.assertIn("Открытая поверхность документации", html)
        self.assertIn("/openapi.json", html)
        self.assertIn("/swagger", html)
        self.assertGreater(pdf_size, 1024)

    def test_dependency_report_renders_top_vulnerable_components(self):
        report = sample_report_data()
        report["dependencies"] = {
            "manifest_count": 1,
            "component_count": 3,
            "lockfile_count": 1,
            "resolved_component_count": 2,
            "transitive_component_count": 1,
            "ecosystem_counts": {"node": 3},
            "flag_counts": {"resolved": 2, "transitive": 1},
            "license_gap_count": 0,
            "vulnerable_component_count": 1,
            "reachable_vulnerable_component_count": 1,
            "suppressed_vulnerability_count": 1,
            "suppression_rule_count": 2,
            "manifests": [{"path": "package.json", "kind": "package.json", "role": "manifest", "component_count": 3, "license": "MIT"}],
            "top_vulnerable_components": [
                {
                    "name": "demo-lib",
                    "ecosystem": "node",
                    "scope": "runtime",
                    "manifest": "package.json",
                    "version": "1.2.3",
                    "reachable": True,
                    "active_vulnerability_count": 2,
                    "kev_count": 1,
                    "bdu_ids": ["BDU:2026-00001"],
                    "cve_ids": ["CVE-2026-1000", "CVE-2026-1001"],
                    "sources": ["NVD", "FSTEC"],
                    "suppressed_count": 1,
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "dependency-report.html"
            pdf_path = Path(temp_dir) / "dependency-report.pdf"
            render_html_report(report, html_path)
            build_pdf_report(report, pdf_path)
            html = html_path.read_text(encoding="utf-8")
            pdf_size = pdf_path.stat().st_size

        self.assertIn("demo-lib", html)
        self.assertIn("CVE-2026-1000, CVE-2026-1001", html)
        self.assertIn("Идентификаторы ФСТЭК", html)
        self.assertIn("BDU:2026-00001", html)
        self.assertIn("Правила подавления", html)
        self.assertGreater(pdf_size, 1024)


if __name__ == "__main__":
    unittest.main()
