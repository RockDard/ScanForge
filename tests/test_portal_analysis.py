import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
import zipfile

from qa_portal.app import app
from qa_portal.analysis import (
    ExtractionError,
    analyze_fuzzing,
    analyze_quality,
    analyze_security,
    analyze_style,
    detect_project,
    extract_input,
    iter_text_files,
    summarize_findings,
)
from qa_portal.models import JobOptions
from qa_portal.pipeline import run_job
from qa_portal.presets import list_presets
from qa_portal.storage import JobContext, JobStore, default_steps


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "sample_qt_project"


class PortalAnalysisTests(unittest.TestCase):
    def test_app_imports(self):
        self.assertEqual(app.title, "ScanForge")

    def test_default_steps_respect_selected_checks(self):
        options = JobOptions(
            run_functionality=True,
            run_security=False,
            run_style=True,
            run_quality=False,
            run_fuzzing=False,
        )
        steps = {step.key: step for step in default_steps("full_scan", options)}
        self.assertEqual(steps["security"].status, "skipped")
        self.assertEqual(steps["quality"].status, "skipped")
        self.assertEqual(steps["functionality"].status, "pending")
        self.assertEqual(steps["style"].status, "pending")

    def test_project_detection_flags_qt_and_tests(self):
        info = detect_project(FIXTURE_ROOT)
        self.assertTrue(info["is_qt_project"])
        self.assertTrue(info["has_tests"])
        self.assertIn("cmake", info["build_systems"])
        self.assertIn("C/C++", info["programming_languages"])

    def test_static_rules_find_expected_findings(self):
        files = iter_text_files(FIXTURE_ROOT)
        security = analyze_security(FIXTURE_ROOT, files)
        style = analyze_style(FIXTURE_ROOT, files)
        quality = analyze_quality(FIXTURE_ROOT, files, detect_project(FIXTURE_ROOT))

        self.assertTrue(any(item.title == "Potential buffer overflow" for item in security))
        self.assertTrue(any(item.title == "Tab indentation" for item in style))
        self.assertTrue(any(item.title.startswith("Outstanding marker") for item in quality))

    def test_quality_rules_detect_redundant_disabled_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "widget.cpp"
            source.write_text(
                "\n".join(
                    [
                        "#include <vector>",
                        "#include <vector>",
                        "int live() { return 0; }",
                        "",
                        "// int disabled() {",
                        "//     return 1;",
                        "// }",
                        "",
                        "/*",
                        "QString legacyName() {",
                        '    return "old";',
                        "}",
                        "*/",
                        "",
                        "#if 0",
                        "int oldPath() {",
                        "    return 2;",
                        "}",
                        "#endif",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_quality(root, [source], detect_project(root))
            titles = {item.title for item in findings}

            self.assertIn("Commented-out code block", titles)
            self.assertIn("Disabled code region", titles)
            self.assertIn("Duplicate include/import directive", titles)

    def test_project_detection_recognizes_polyglot_languages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "tools").mkdir()
            (root / "tools" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "ui").mkdir()
            (root / "ui" / "MainView.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")

            info = detect_project(root)

            self.assertTrue(info["polyglot"])
            self.assertIn("C/C++", info["programming_languages"])
            self.assertIn("Python", info["programming_languages"])
            self.assertIn("QML", info["programming_languages"])
            self.assertGreaterEqual(info["multilinguality"]["programming_language_count"], 3)

    def test_quality_analysis_adds_multilinguality_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            source = root / "src" / "main.cpp"
            source.write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")

            project_info = detect_project(root)
            findings = analyze_quality(root, iter_text_files(root), project_info)
            titles = {item.title for item in findings}

            self.assertIn("Polyglot project detected", titles)
            self.assertIn("Polyglot project without detected tests", titles)

    def test_fuzzing_generates_artifacts(self):
        files = iter_text_files(FIXTURE_ROOT)
        with tempfile.TemporaryDirectory() as temp_dir:
            findings, artifacts, _ = analyze_fuzzing(
                FIXTURE_ROOT,
                files,
                tools={"afl_fuzz": None, "clangxx": None},
                mode="fuzz_project",
                output_dir=Path(temp_dir),
                duration_seconds=60,
            )
            self.assertGreaterEqual(len(findings), 2)
            self.assertTrue(any(item.filename == "generated_fuzz_harness.cpp" for item in artifacts))
            self.assertTrue((Path(temp_dir) / "generated_fuzz_harness.cpp").exists())

    def test_summary_counts_findings(self):
        files = iter_text_files(FIXTURE_ROOT)
        findings = analyze_security(FIXTURE_ROOT, files)
        summary = summarize_findings(findings)
        self.assertGreater(summary["total_findings"], 0)
        self.assertIn("high", summary["severity_counts"])
        self.assertGreater(summary["risk_score"], 0)
        self.assertTrue(summary["next_actions"])

    def test_presets_catalog_exposes_named_profiles(self):
        presets = {item["key"]: item for item in list_presets()}
        self.assertIn("balanced", presets)
        self.assertIn("deep", presets)
        self.assertTrue(presets["fuzz"]["options"]["run_fuzzing"])

    def test_extract_input_rejects_zip_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            upload = temp_root / "malicious.zip"
            workspace = temp_root / "workspace"
            with zipfile.ZipFile(upload, "w") as archive:
                archive.writestr("../escape.txt", "boom")

            with self.assertRaises(ExtractionError):
                extract_input(upload, workspace)

    def test_pause_and_resume_continue_from_completed_steps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            jobs_dir = temp_root / "jobs"
            uploads_dir = temp_root / "uploads"
            store = JobStore(jobs_dir)
            upload = uploads_dir / "sample_qt_project.zip"
            upload.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(upload, "w") as archive:
                for path in FIXTURE_ROOT.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(FIXTURE_ROOT.parent))

            with patch("qa_portal.app.store", store):
                from qa_portal import app as app_module

                job = app_module.create_job_record(
                    name="Pause pipeline",
                    mode="full_scan",
                    original_name=upload.name,
                    upload_path=upload,
                    options=JobOptions(preset="balanced"),
                )
                store.save(job)
                context = JobContext(store, job.id)
                call_count = {"functionality": 0}

                def pause_after_functionality(*args, **kwargs):
                    call_count["functionality"] += 1
                    store.request_pause(job.id)
                    return [], [], {"configured": False, "built": False, "tests_ran": False}

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=pause_after_functionality):
                    run_job(context)

                paused = store.load(job.id)
                self.assertEqual(paused.status, "paused")
                self.assertEqual(call_count["functionality"], 1)
                self.assertEqual(next(step for step in paused.steps if step.key == "functionality").status, "completed")

                resumed = store.resume_job(job.id)
                self.assertEqual(resumed.status, "queued")

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=AssertionError("should not rerun")):
                    run_job(context)

                completed = store.load(job.id)
                self.assertEqual(completed.status, "completed")
                self.assertTrue(completed.html_report)
                self.assertTrue(completed.pdf_report)

    def test_changes_only_retest_limits_file_scoped_checks_to_changed_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            jobs_dir = temp_root / "jobs"
            uploads_dir = temp_root / "uploads"
            store = JobStore(jobs_dir)
            baseline_upload = uploads_dir / "project.zip"
            current_upload = uploads_dir / "project_new.zip"
            uploads_dir.mkdir(parents=True, exist_ok=True)

            baseline_files = {
                "project/src/app.cpp": "int main() { return 0; }\n",
                "project/src/helper.cpp": "int helper() { return 1; }\n",
            }
            current_files = {
                "project/src/app.cpp": "int main() { return 1; }\n",
                "project/src/helper.cpp": "int helper() { return 1; }\n",
            }

            with zipfile.ZipFile(baseline_upload, "w") as archive:
                for relative, content in baseline_files.items():
                    archive.writestr(relative, content)

            with zipfile.ZipFile(current_upload, "w") as archive:
                for relative, content in current_files.items():
                    archive.writestr(relative, content)

            captured: dict[str, object] = {}

            def fake_analyze_functionality(root, project_info, tools, build_dir, plan, changes_only=False, changed_files=None):
                captured["functionality_changes_only"] = changes_only
                captured["functionality_changed_files"] = list(changed_files or [])
                return [], [], {"configured": False, "built": False, "tests_ran": False}

            def fake_analyze_security(root, files, max_workers=1):
                captured["security_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_analyze_style(root, files, max_workers=1):
                captured["style_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_run_clang_tidy(root, build_dir, tools, plan, focus_files=None):
                captured["clang_tidy_files"] = [str(path.relative_to(root)) for path in (focus_files or [])]
                return [], []

            def fake_analyze_quality(root, files, project_info, max_workers=1):
                captured["quality_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_run_cppcheck(root, files, tools, plan):
                captured["cppcheck_files"] = [str(path.relative_to(root)) for path in files]
                return [], []

            def fake_analyze_fuzzing(root, files, tools, mode, output_dir, duration_seconds, plan, focus_files=None):
                captured["fuzzing_files"] = [str(path.relative_to(root)) for path in files]
                captured["fuzzing_focus_files"] = [str(path.relative_to(root)) for path in (focus_files or [])]
                return [], [], []

            with patch("qa_portal.app.store", store):
                from qa_portal import app as app_module

                baseline_job = app_module.create_job_record(
                    name="Baseline",
                    mode="full_scan",
                    original_name="project.zip",
                    upload_path=baseline_upload,
                    options=JobOptions(preset="balanced"),
                )
                store.save(baseline_job)

                options = JobOptions(**asdict(JobOptions(preset="balanced")))
                options.retest_scope = "changes_only"
                options.run_fuzzing = True
                job = app_module.create_job_record(
                    name="Incremental retest",
                    mode="full_scan",
                    original_name="project.zip",
                    upload_path=current_upload,
                    options=options,
                    metadata={
                        "project_key": baseline_job.metadata["project_key"],
                        "repeat_submission": True,
                        "baseline_job_id": baseline_job.id,
                        "baseline_job_name": baseline_job.name,
                        "retest_scope": "changes_only",
                    },
                )
                store.save(job)
                context = JobContext(store, job.id)

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=fake_analyze_functionality), \
                    patch("qa_portal.pipeline.analyze_security", side_effect=fake_analyze_security), \
                    patch("qa_portal.pipeline.analyze_style", side_effect=fake_analyze_style), \
                    patch("qa_portal.pipeline.run_clang_tidy", side_effect=fake_run_clang_tidy), \
                    patch("qa_portal.pipeline.analyze_quality", side_effect=fake_analyze_quality), \
                    patch("qa_portal.pipeline.run_cppcheck", side_effect=fake_run_cppcheck), \
                    patch("qa_portal.pipeline.analyze_fuzzing", side_effect=fake_analyze_fuzzing):
                    run_job(context)

                completed = store.load(job.id)
                self.assertEqual(completed.status, "completed")
                self.assertTrue(completed.metadata["comparison"]["has_changes"])
                self.assertEqual(completed.metadata["comparison"]["changed_files"], ["src/app.cpp"])
                self.assertTrue(captured["functionality_changes_only"])
                self.assertEqual(captured["functionality_changed_files"], ["src/app.cpp"])
                self.assertEqual(captured["security_files"], ["src/app.cpp"])
                self.assertEqual(captured["style_files"], ["src/app.cpp"])
                self.assertEqual(captured["clang_tidy_files"], ["src/app.cpp"])
                self.assertEqual(captured["quality_files"], ["src/app.cpp"])
                self.assertEqual(captured["cppcheck_files"], ["src/app.cpp"])
                self.assertEqual(captured["fuzzing_files"], ["src/app.cpp"])
                self.assertEqual(captured["fuzzing_focus_files"], ["src/app.cpp"])


if __name__ == "__main__":
    unittest.main()
