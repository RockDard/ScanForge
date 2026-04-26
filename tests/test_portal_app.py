import base64
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

if os.name == "nt":
    raise unittest.SkipTest("portal app tests require the target Linux runtime")

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    raise unittest.SkipTest("portal app tests require FastAPI from requirements.txt") from exc

import qa_portal.app as app_module
from qa_portal.finding_lifecycle import load_project_review_states
from qa_portal.models import JobOptions
from qa_portal.storage import JobStore


class PortalAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.jobs_dir = root / "jobs"
        self.uploads_dir = root / "uploads"
        self.finding_lifecycle_dir = root / "finding_lifecycle"
        self.integration_events_dir = root / "integration_events"
        self.integration_settings_path = root / "integrations.json"
        self.ai_settings_path = root / "ai_backend.json"
        self.release_gate_policy_path = root / "release_gate_policy.json"
        self.dependency_suppressions_path = root / "dependency_suppressions.json"
        self.store = JobStore(self.jobs_dir)

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.start_background_job = self.stack.enter_context(
            patch.object(app_module, "start_background_job")
        )
        self.stack.enter_context(patch.object(app_module, "store", self.store))
        self.stack.enter_context(patch.object(app_module, "UPLOAD_DIR", self.uploads_dir))
        self.stack.enter_context(
            patch("qa_portal.finding_lifecycle.FINDING_LIFECYCLE_DIR", self.finding_lifecycle_dir)
        )
        self.stack.enter_context(
            patch("qa_portal.integrations.INTEGRATION_EVENTS_DIR", self.integration_events_dir)
        )
        self.stack.enter_context(
            patch("qa_portal.integrations.INTEGRATIONS_SETTINGS_PATH", self.integration_settings_path)
        )
        self.stack.enter_context(
            patch("qa_portal.config.AI_SETTINGS_PATH", self.ai_settings_path)
        )
        self.stack.enter_context(
            patch("qa_portal.release_gate.RELEASE_GATE_POLICY_PATH", self.release_gate_policy_path)
        )
        self.stack.enter_context(
            patch("qa_portal.dependency_analysis.DEPENDENCY_SUPPRESSIONS_PATH", self.dependency_suppressions_path)
        )
        self.client = TestClient(app_module.app)

    def auth_header(self, username: str, password: str) -> dict[str, str]:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def test_create_job_route_persists_selected_preset(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Release audit",
                "mode": "full_scan",
                "preset": "security",
                "run_functionality": "on",
                "run_security": "on",
                "run_quality": "on",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        jobs = self.store.list()
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.name, "Release audit")
        self.assertEqual(job.options.preset, "security")
        self.assertFalse(job.options.run_style)
        self.assertEqual(job.steps[4].status, "skipped")
        self.start_background_job.assert_called_once_with(job.id)

    def test_create_job_route_uses_preset_defaults_without_js(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Default preset run",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        job = self.store.list()[0]
        self.assertTrue(job.options.run_functionality)
        self.assertTrue(job.options.run_security)
        self.assertTrue(job.options.run_style)
        self.assertTrue(job.options.run_quality)

    def test_create_job_route_accepts_multiple_uploads(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Batch",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files=[
                ("upload", ("widget_a.cpp", b"int main() { return 0; }\n", "text/plain")),
                ("upload", ("widget_b.cpp", b"int main() { return 0; }\n", "text/plain")),
            ],
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        jobs = sorted(self.store.list(), key=lambda job: job.queue_position)
        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[0].queue_position, 1)
        self.assertEqual(jobs[1].queue_position, 2)
        self.assertEqual(self.start_background_job.call_count, 2)

    def test_upload_route_rejects_oversized_file_and_removes_partial_upload(self):
        with patch.object(app_module, "MAX_UPLOAD_BYTES", 8):
            response = self.client.post(
                "/jobs",
                data={
                    "name": "Too large",
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": ("big.cpp", b"0123456789", "text/plain")},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(list(self.uploads_dir.glob("*")), [])

    def test_upload_route_rejects_too_many_files(self):
        with patch.object(app_module, "MAX_UPLOAD_FILES", 1):
            response = self.client.post(
                "/jobs",
                data={
                    "name": "Too many",
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files=[
                    ("upload", ("one.cpp", b"int one;\n", "text/plain")),
                    ("upload", ("two.cpp", b"int two;\n", "text/plain")),
                ],
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.store.list(), [])

    def test_create_job_api_returns_redirect_payload(self):
        response = self.client.post(
            "/api/jobs/upload",
            data={
                "name": "API upload",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["jobs"]), 1)
        self.assertTrue(payload["redirect_url"].startswith("/jobs/"))

    def test_create_job_api_keeps_runtime_secrets_private_and_returns_public_summary(self):
        response = self.client.post(
            "/api/jobs/upload",
            data={
                "name": "Runtime upload",
                "mode": "full_scan",
                "preset": "balanced",
                "service_target_url": "http://127.0.0.1:9000",
                "service_runtime_profile": "safe-active",
                "service_request_timeout_seconds": "9",
                "auth_token": "top-secret-token",
                "auth_header_name": "Authorization",
                "auth_token_prefix": "Bearer",
                "service_request_headers": '{"X-Env": "stage"}',
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["jobs"]), 1)

        job = self.store.list()[0]
        self.assertEqual(job.metadata["service_runtime_request"]["target_url"], "http://127.0.0.1:9000")
        self.assertEqual(job.metadata["service_runtime_request"]["auth_token"], "top-secret-token")
        self.assertEqual(job.metadata["service_runtime_request"]["request_headers"]["X-Env"], "stage")
        self.assertEqual(job.metadata["service_runtime_request_public"]["target_url"], "http://127.0.0.1:9000")
        self.assertEqual(job.metadata["service_runtime_request_public"]["auth_mode_requested"], "bearer")

        response_job = payload["jobs"][0]
        self.assertNotIn("service_runtime_request", response_job["metadata"])
        self.assertEqual(
            response_job["metadata"]["service_runtime_request_public"]["target_url"],
            "http://127.0.0.1:9000",
        )
        self.assertEqual(
            response_job["metadata"]["service_runtime_request_public"]["auth_mode_requested"],
            "bearer",
        )

    def test_dashboard_filters_jobs(self):
        upload_path = self.uploads_dir / "sample.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        release_job = app_module.create_job_record(
            name="Release gate",
            mode="full_scan",
            original_name="release.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="security", run_functionality=True, run_security=True, run_quality=True),
        )
        release_job.status = "completed"
        self.store.save(release_job)

        fuzz_job = app_module.create_job_record(
            name="Fuzz pass",
            mode="fuzz_project",
            original_name="fuzz.zip",
            upload_path=upload_path,
            options=JobOptions(preset="fuzz", run_functionality=True, run_fuzzing=True),
        )
        fuzz_job.status = "running"
        self.store.save(fuzz_job)

        response = self.client.get("/?query=release&status=completed&preset=security")

        self.assertEqual(response.status_code, 200)
        body = response.text
        self.assertIn("Release gate", body)
        self.assertNotIn("Fuzz pass", body)
        self.assertIn("Showing 1 of 2 saved jobs.", body)

    def test_dashboard_supports_russian_language_switch(self):
        response = self.client.get("/?lang=ru")

        self.assertEqual(response.status_code, 200)
        self.assertIn('lang="ru"', response.text)
        self.assertIn("Создать задачу", response.text)
        self.assertIn("scanforge_lang=ru", response.headers.get("set-cookie", ""))

        follow_up = self.client.get("/")
        self.assertEqual(follow_up.status_code, 200)
        self.assertIn("Создать задачу", follow_up.text)
        self.assertIn("Анализатор проектов", response.text)

    def test_dashboard_moves_system_controls_to_settings_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/settings"', response.text)
        self.assertNotIn('action="/knowledge-base/sync"', response.text)
        self.assertNotIn("Host toolchain", response.text)
        self.assertNotIn("AI review backend", response.text)
        self.assertNotIn("Local knowledge base", response.text)
        self.assertNotIn("Host hardware", response.text)

    def test_settings_page_renders_knowledge_base_sync_button(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/knowledge-base/sync"', response.text)
        self.assertIn("Sync now", response.text)
        self.assertIn("Technical settings", response.text)

    def test_settings_page_renders_tool_install_button_for_missing_tools(self):
        fake_inventory = [
            {
                "key": "clang_tidy",
                "label": "clang-tidy",
                "path": None,
                "installed": False,
                "package_manager": "apt",
                "packages": ["clang-tidy"],
                "installable": True,
                "description": "Static checks",
            }
        ]
        with patch.object(app_module, "describe_toolchain", return_value=fake_inventory):
            response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/tools/install/clang_tidy"', response.text)
        self.assertIn("Install", response.text)

    def test_settings_page_renders_system_sections(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Environment diagnostics", response.text)
        self.assertIn("Host toolchain", response.text)
        self.assertIn("AI review backend", response.text)
        self.assertIn("Release gate policy", response.text)
        self.assertIn("Local knowledge base", response.text)
        self.assertIn("Host hardware", response.text)

    def test_settings_page_renders_ai_backend_config_form(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-ai-config-form', response.text)
        self.assertIn("Save AI settings", response.text)
        self.assertIn("Probe backend", response.text)
        self.assertIn("PDF generation", response.text)

    def test_tool_install_route_queues_background_installer(self):
        with patch.object(app_module, "start_tool_install_job", return_value={"id": "install-1", "status": "queued"}) as installer:
            response = self.client.post(
                "/tools/install/clang_tidy",
                data={"next_url": "/", "packages": ["clang-tidy"]},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        installer.assert_called_once_with("clang_tidy", confirmed_packages=["clang-tidy"])

    def test_tool_install_api_requires_confirmation_after_dry_run(self):
        with patch.object(app_module, "dry_run_host_tool", return_value={
            "ok": True,
            "status": "ready",
            "packages": ["clang-tidy"],
            "confirmation_required": True,
            "message": "clang-tidy can be installed.",
        }):
            response = self.client.post("/api/tools/install/clang_tidy")

        self.assertEqual(response.status_code, 409)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "confirmation-required")
        self.assertEqual(payload["packages"], ["clang-tidy"])

    def test_tool_install_api_requires_confirmed_package_list(self):
        with patch.object(app_module, "dry_run_host_tool", return_value={
            "ok": True,
            "status": "ready",
            "packages": ["clang-tidy"],
            "confirmation_required": True,
            "message": "clang-tidy can be installed.",
        }):
            response = self.client.post("/api/tools/install/clang_tidy", json={"confirmed": True})

        self.assertEqual(response.status_code, 409)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "confirmation-required")
        self.assertEqual(payload["packages"], ["clang-tidy"])

    def test_tool_install_api_queues_job_and_returns_refreshed_inventory(self):
        refreshed_inventory = [
            {
                "key": "clang_tidy",
                "label": "clang-tidy",
                "path": "/usr/bin/clang-tidy",
                "installed": True,
                "package_manager": "apt",
                "packages": ["clang-tidy"],
                "installable": False,
                "description": "Static checks",
            }
        ]
        with patch.object(app_module, "start_tool_install_job", return_value={"id": "install-1", "status": "queued", "message": "Queued"}) as installer:
            with patch.object(app_module, "describe_toolchain", return_value=refreshed_inventory):
                response = self.client.post(
                    "/api/tools/install/clang_tidy",
                    json={"confirmed": True, "packages": ["clang-tidy"]},
                )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["install_job"]["id"], "install-1")
        self.assertEqual(payload["tool_inventory"], refreshed_inventory)
        installer.assert_called_once_with("clang_tidy", confirmed_packages=["clang-tidy"])

    def test_tool_install_api_rejects_confirmed_package_mismatch(self):
        with patch.object(app_module, "start_tool_install_job", return_value={
            "ok": False,
            "status": "package-confirmation-mismatch",
            "message": "Confirmed package list no longer matches the current install plan.",
            "packages": ["clang-tidy"],
        }):
            response = self.client.post(
                "/api/tools/install/clang_tidy",
                json={"confirmed": True, "packages": ["old-clang-tidy"]},
            )

        self.assertEqual(response.status_code, 409)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "package-confirmation-mismatch")

    def test_tool_install_api_returns_error_status_for_unsupported_confirmed_install(self):
        with patch.object(app_module, "start_tool_install_job", return_value={
            "ok": False,
            "status": "unsupported",
            "message": "Tool cannot be installed automatically.",
        }):
            response = self.client.post(
                "/api/tools/install/missing_tool",
                json={"confirmed": True, "packages": ["missing-tool"]},
            )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "unsupported")

    def test_tool_install_dry_run_api_returns_package_plan(self):
        with patch.object(app_module, "dry_run_host_tool", return_value={"ok": True, "packages": ["clang-tidy"]}) as dry_run:
            response = self.client.post("/api/tools/install/clang_tidy/dry-run")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["packages"], ["clang-tidy"])
        dry_run.assert_called_once_with("clang_tidy")

    def test_manual_knowledge_base_sync_route_starts_background_sync(self):
        with patch.object(app_module, "start_background_knowledge_base_sync", return_value=True) as start_sync:
            response = self.client.post(
                "/knowledge-base/sync",
                data={"next_url": "/?lang=ru"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/?lang=ru")
        start_sync.assert_called_once_with(force=True)

    def test_manual_knowledge_base_sync_api_returns_start_status(self):
        knowledge_base_payload = {
            "available": False,
            "updated_at": None,
            "stale": True,
            "source_count": 0,
            "successful_sources": 0,
            "failed_sources": 0,
            "sources": {},
            "sources_list": [],
            "feed_runs": {},
            "totals": {},
            "nvd_yearly": {"enabled": False, "year_start": None, "year_end": None, "year_count": 0},
            "weekly_schedule": {"enabled": False, "day": 0, "day_label": "Monday", "hour": 2, "minute": 0, "next_run_at": None},
            "sync": {"running": True, "trigger": "manual"},
        }
        with patch.object(app_module, "start_background_knowledge_base_sync", return_value=False) as start_sync:
            with patch.object(app_module, "knowledge_base_status", return_value=knowledge_base_payload):
                response = self.client.post("/api/knowledge-base/sync")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["started"])
        self.assertTrue(payload["knowledge_base"]["sync"]["running"])
        start_sync.assert_called_once_with(force=True)

    def test_assistant_model_download_route_starts_background_download(self):
        with patch.object(app_module, "start_local_model_download", return_value={"started": True}) as start_download:
            response = self.client.post(
                "/assistant/models/qwen2.5-coder-3b-instruct/download",
                data={"next_url": "/"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        start_download.assert_called_once_with("qwen2.5-coder-3b-instruct")

    def test_rerun_route_clones_job(self):
        upload_path = self.uploads_dir / "original.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        original = app_module.create_job_record(
            name="Original run",
            mode="full_scan",
            original_name="original.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced", run_functionality=True, run_security=True),
        )
        self.store.save(original)

        response = self.client.post(
            f"/jobs/{original.id}/rerun",
            data={"retest_scope": "changes_only"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        jobs = self.store.list()
        self.assertEqual(len(jobs), 2)
        rerun = next(job for job in jobs if job.id != original.id)
        self.assertTrue(rerun.name.endswith("(rerun)"))
        self.assertEqual(rerun.metadata["rerun_of"], original.id)
        self.assertEqual(rerun.metadata["baseline_job_id"], original.id)
        self.assertEqual(rerun.options.retest_scope, "changes_only")
        self.start_background_job.assert_called_once_with(rerun.id)

    def test_rerun_route_preserves_runtime_request_metadata(self):
        upload_path = self.uploads_dir / "runtime.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        original = app_module.create_job_record(
            name="Runtime baseline",
            mode="full_scan",
            original_name="runtime.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced", run_functionality=True, run_security=True),
            metadata={
                "project_key": "runtime.cpp",
                "service_runtime_request": {
                    "target_url": "http://127.0.0.1:8081",
                    "service_runtime_profile": "safe-active",
                    "request_timeout_seconds": 8,
                    "auth_token": "secret",
                    "request_headers": {"X-Stage": "test"},
                },
                "service_runtime_request_public": {
                    "target_url": "http://127.0.0.1:8081",
                    "verification_profile": "safe-active",
                    "request_timeout_seconds": 8,
                    "auth_mode_requested": "bearer",
                },
            },
        )
        self.store.save(original)

        response = self.client.post(
            f"/jobs/{original.id}/rerun",
            data={"retest_scope": "changes_only"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        jobs = self.store.list()
        rerun = next(job for job in jobs if job.id != original.id)
        self.assertEqual(
            rerun.metadata["service_runtime_request"]["target_url"],
            "http://127.0.0.1:8081",
        )
        self.assertEqual(
            rerun.metadata["service_runtime_request"]["auth_token"],
            "secret",
        )
        self.assertEqual(
            rerun.metadata["service_runtime_request_public"]["service_runtime_profile"],
            "safe-active",
        )
        self.assertNotIn("verification_profile", rerun.metadata["service_runtime_request_public"])
        self.assertEqual(
            rerun.metadata["service_runtime_request_public"]["auth_mode_requested"],
            "bearer",
        )

    def test_job_api_normalizes_legacy_runtime_public_summary(self):
        upload_path = self.uploads_dir / "legacy.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        legacy_job = app_module.create_job_record(
            name="Legacy runtime job",
            mode="full_scan",
            original_name="legacy.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced", run_functionality=True, run_security=True),
            metadata={
                "service_runtime_request_public": {
                    "target_url": "http://127.0.0.1:8088",
                    "verification_profile": "safe-active",
                    "request_timeout_seconds": 7,
                    "auth_mode_requested": "cookie",
                }
            },
        )
        self.store.save(legacy_job)

        response = self.client.get(f"/api/jobs/{legacy_job.id}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        runtime = payload["metadata"]["service_runtime_request_public"]
        self.assertEqual(runtime["target_url"], "http://127.0.0.1:8088")
        self.assertEqual(runtime["service_runtime_profile"], "safe-active")
        self.assertEqual(runtime["auth_mode_requested"], "cookie")
        self.assertNotIn("verification_profile", runtime)

    def test_job_detail_renders_legacy_runtime_public_summary(self):
        upload_path = self.uploads_dir / "legacy-detail.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        legacy_job = app_module.create_job_record(
            name="Legacy runtime detail",
            mode="full_scan",
            original_name="legacy-detail.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced", run_functionality=True, run_security=True),
            metadata={
                "service_runtime_request_public": {
                    "target_url": "http://127.0.0.1:8090",
                    "verification_profile": "safe-active",
                    "request_timeout_seconds": 6,
                    "auth_mode_requested": "basic",
                }
            },
        )
        self.store.save(legacy_job)

        response = self.client.get(f"/jobs/{legacy_job.id}")

        self.assertEqual(response.status_code, 200)
        self.assertIn("http://127.0.0.1:8090", response.text)
        self.assertIn("safe-active", response.text)
        self.assertIn("basic", response.text)

    def test_rerun_get_route_renders_choice_page(self):
        upload_path = self.uploads_dir / "widget.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        original = app_module.create_job_record(
            name="Original run",
            mode="full_scan",
            original_name="widget.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced", run_functionality=True, run_security=True),
        )
        self.store.save(original)

        response = self.client.get(f"/jobs/{original.id}/rerun")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Choose Rerun Strategy", response.text)
        self.assertIn("Changes only", response.text)
        self.assertIn("Full project", response.text)

    def test_repeated_upload_uses_selected_retest_scope_and_baseline(self):
        original_upload = self.uploads_dir / "project.zip"
        original_upload.parent.mkdir(parents=True, exist_ok=True)
        original_upload.write_text("baseline", encoding="utf-8")
        original = app_module.create_job_record(
            name="Baseline",
            mode="full_scan",
            original_name="project.zip",
            upload_path=original_upload,
            options=JobOptions(preset="balanced"),
        )
        self.store.save(original)

        response = self.client.post(
            "/jobs",
            data={
                "name": "Repeated run",
                "mode": "full_scan",
                "preset": "balanced",
                "retest_scope": "changes_only",
            },
            files={"upload": ("project.zip", b"new archive content", "application/zip")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        jobs = self.store.list()
        self.assertEqual(len(jobs), 2)
        repeated = next(job for job in jobs if job.id != original.id)
        self.assertTrue(repeated.metadata["repeat_submission"])
        self.assertEqual(repeated.metadata["baseline_job_id"], original.id)
        self.assertEqual(repeated.options.retest_scope, "changes_only")

    def test_create_job_route_persists_selected_ui_language(self):
        self.client.get("/?lang=ru")

        response = self.client.post(
            "/jobs",
            data={
                "name": "Russian UI run",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        job = self.store.list()[0]
        self.assertEqual(job.metadata["ui_language"], "ru")

    def test_system_api_exposes_ai_backend_and_tools(self):
        response = self.client.get("/api/system")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("tools", payload)
        self.assertIn("ai_backend", payload)
        self.assertIn("release_gate_policy", payload)
        self.assertIn("dependency_suppressions", payload)
        self.assertIn("knowledge_base", payload)
        self.assertIn("hardware", payload)
        self.assertIn("recommended_worker_processes", payload)
        self.assertIn("worker_mode", payload)
        self.assertIn("tool_inventory", payload)
        self.assertIn("integrations", payload)
        self.assertIn("environment", payload)
        self.assertIn("tool_install_preflight", payload)
        self.assertIn("tool_install_jobs", payload)
        self.assertIn("network", payload)
        self.assertIn("lan_urls", payload["network"])

    def test_ai_backend_config_api_persists_settings(self):
        response = self.client.post(
            "/api/assistant/config",
            json={
                "enabled": True,
                "provider": "openai-compatible",
                "url": "https://example.invalid/v1/chat/completions",
                "model": "demo-model",
                "timeout_seconds": 45,
                "routing_mode": "local-first",
                "preferred_local_model": "qwen2.5-coder-3b-instruct",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["settings"]["routing_mode"], "local-first")
        self.assertEqual(payload["settings"]["preferred_local_model"], "qwen2.5-coder-3b-instruct")
        self.assertTrue(self.ai_settings_path.exists())

    def test_ai_backend_probe_api_returns_payload(self):
        with patch.object(app_module, "probe_ai_backend", return_value={"ok": True, "mode": "local-fallback"}):
            response = self.client.post("/api/assistant/probe")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "local-fallback")

    def test_settings_page_renders_release_gate_policy_form(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-release-gate-config-form', response.text)
        self.assertIn("Save release gate policy", response.text)
        self.assertIn("Block on new reachable vulnerable dependencies", response.text)

    def test_settings_page_renders_dependency_suppression_form(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Dependency suppression policy", response.text)
        self.assertIn('data-dependency-suppressions-form', response.text)
        self.assertIn("Save suppression policy", response.text)
        self.assertIn("Suppression rules, JSON", response.text)

    def test_release_gate_config_api_persists_policy(self):
        response = self.client.post(
            "/api/release-gate/config",
            json={
                "block_on_critical_findings": True,
                "block_on_new_high_findings": True,
                "block_on_new_critical_findings": True,
                "block_on_new_vulnerable_dependencies": True,
                "block_on_new_reachable_vulnerable_dependencies": True,
                "block_on_dependency_baseline_regression": True,
                "review_on_persisting_high_findings": True,
                "review_on_risk_score_regression": True,
                "review_on_net_new_findings": True,
                "review_on_high_severity_regression": True,
                "review_on_risk_score_above": 61,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["policy"]["review_on_risk_score_above"], 61)
        self.assertTrue(payload["policy"]["block_on_dependency_baseline_regression"])
        self.assertTrue(self.release_gate_policy_path.exists())

    def test_dependency_suppressions_config_api_persists_rules(self):
        response = self.client.post(
            "/api/dependency-suppressions/config",
            json={
                "rules": [
                    {
                        "ecosystem": "node",
                        "name": "demo-lib",
                        "version": "1.2.3",
                        "cve": "CVE-2026-1000",
                        "reason": "Accepted temporarily while vendor patch is validated.",
                    }
                ]
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["rule_count"], 1)
        self.assertEqual(payload["rules"][0]["cve"], "CVE-2026-1000")
        self.assertTrue(self.dependency_suppressions_path.exists())

    def test_settings_page_renders_integrations_section(self):
        response = self.client.get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Integrations", response.text)
        self.assertIn("Webhook URL", response.text)
        self.assertIn("Save integration settings", response.text)

    def test_integrations_config_api_persists_provider_state(self):
        response = self.client.post(
            "/api/integrations/config",
            json={
                "providers": {
                    "gitlab": {
                        "enabled": True,
                        "base_url": "https://gitlab.example.test",
                        "token": "secret-token",
                        "webhook_secret": "hook-secret",
                        "default_mode": "full_scan",
                        "default_preset": "security",
                    }
                }
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["enabled_count"], 1)
        provider = next(item for item in payload["providers"] if item["key"] == "gitlab")
        self.assertTrue(provider["enabled"])
        self.assertEqual(provider["base_url"], "https://gitlab.example.test")
        self.assertTrue(provider["token_configured"])
        self.assertTrue(provider["webhook_secret_configured"])

    def test_finding_review_api_persists_operator_decision(self):
        response = self.client.post(
            "/api/projects/sample-project/findings/fp-001/review",
            json={
                "review_state": "accepted-risk",
                "review_note": "Known issue for the internal beta.",
                "muted_until": "2030-01-01T00:00",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["review_state"], "accepted-risk")

        saved = load_project_review_states("sample-project")
        self.assertIn("fp-001", saved)
        self.assertEqual(saved["fp-001"]["review_note"], "Known issue for the internal beta.")

    def test_basic_auth_requires_credentials_and_blocks_viewer_writes(self):
        env = {
            "QA_PORTAL_AUTH_ENABLED": "1",
            "QA_PORTAL_ADMIN_USER": "admin",
            "QA_PORTAL_ADMIN_PASSWORD": "secret",
            "QA_PORTAL_VIEWER_USER": "viewer",
            "QA_PORTAL_VIEWER_PASSWORD": "read-only",
        }
        with patch.dict(os.environ, env):
            self.assertEqual(self.client.get("/api/runtime").status_code, 200)
            self.assertEqual(self.client.get("/").status_code, 401)
            self.assertEqual(
                self.client.get("/", headers=self.auth_header("viewer", "read-only")).status_code,
                200,
            )
            blocked = self.client.post(
                "/jobs",
                headers=self.auth_header("viewer", "read-only"),
                data={
                    "name": "Blocked",
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
                follow_redirects=False,
            )
            self.assertEqual(blocked.status_code, 403)

            allowed = self.client.post(
                "/jobs",
                headers=self.auth_header("admin", "secret"),
                data={
                    "name": "Allowed",
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
                follow_redirects=False,
            )
            self.assertEqual(allowed.status_code, 303)

    def test_basic_auth_reports_misconfiguration_when_enabled_without_admin_password(self):
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_AUTH_ENABLED": "1",
                "QA_PORTAL_ADMIN_PASSWORD": "",
                "QA_PORTAL_AUTH_BOOTSTRAP": "0",
                "QA_PORTAL_AUTH_AUTO_SETUP": "0",
            },
        ):
            response = self.client.get("/")

        self.assertEqual(response.status_code, 503)

    def test_basic_auth_bootstrap_generates_initial_admin_password(self):
        auth_path = Path(self.temp_dir.name) / "settings" / "auth_bootstrap.json"
        env = {
            "QA_PORTAL_AUTH_ENABLED": "1",
            "QA_PORTAL_AUTH_BOOTSTRAP": "1",
            "QA_PORTAL_ADMIN_USER": "admin",
            "QA_PORTAL_ADMIN_PASSWORD": "",
        }
        with patch.dict(os.environ, env):
            with patch("qa_portal.auth.AUTH_BOOTSTRAP_PATH", auth_path):
                first_response = self.client.get("/")
                payload = json.loads(auth_path.read_text(encoding="utf-8"))
                password = payload["admin_password"]
                authenticated = self.client.get("/", headers=self.auth_header("admin", password))

        self.assertEqual(first_response.status_code, 401)
        self.assertTrue(password)
        self.assertEqual(authenticated.status_code, 200)

    def test_network_auto_setup_enables_auth_when_host_is_explicitly_network_bound(self):
        auth_path = Path(self.temp_dir.name) / "settings" / "network_auth_bootstrap.json"
        env = {
            "QA_PORTAL_HOST": "0.0.0.0",
            "QA_PORTAL_AUTH_AUTO_SETUP": "1",
            "QA_PORTAL_ADMIN_USER": "admin",
            "QA_PORTAL_ADMIN_PASSWORD": "",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("qa_portal.auth.AUTH_BOOTSTRAP_PATH", auth_path):
                response = self.client.get("/")
                payload = json.loads(auth_path.read_text(encoding="utf-8"))
                authenticated = self.client.get("/", headers=self.auth_header("admin", payload["admin_password"]))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(authenticated.status_code, 200)

    def test_public_runtime_info_omits_network_details(self):
        response = self.client.get("/api/runtime")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["name"], "ScanForge")
        self.assertIn("runtime_signature", payload)
        self.assertNotIn("network", payload)

    def test_dashboard_api_returns_filtered_jobs_and_overview(self):
        upload_path = self.uploads_dir / "release.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

        release_job = app_module.create_job_record(
            name="Release gate",
            mode="full_scan",
            original_name="release.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="security", run_functionality=True, run_security=True, run_quality=True),
        )
        release_job.status = "completed"
        self.store.save(release_job)

        fuzz_job = app_module.create_job_record(
            name="Fuzz pass",
            mode="fuzz_project",
            original_name="fuzz.zip",
            upload_path=upload_path,
            options=JobOptions(preset="fuzz", run_functionality=True, run_fuzzing=True),
        )
        fuzz_job.status = "running"
        self.store.save(fuzz_job)

        response = self.client.get("/api/dashboard?query=release&status=completed&preset=security")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["jobs"]), 1)
        self.assertEqual(payload["jobs"][0]["name"], "Release gate")
        self.assertEqual(payload["overview"]["completed_jobs"], 1)
        self.assertEqual(payload["overview"]["running_jobs"], 0)
        self.assertEqual(payload["all_jobs_count"], 2)

    def test_runtime_logs_are_exposed_in_system_api(self):
        log_dir = Path(self.temp_dir.name) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "web.log").write_text("web-one\nweb-two\n", encoding="utf-8")
        (log_dir / "worker.log").write_text("worker-one\n", encoding="utf-8")

        with patch.dict(os.environ, {"SCANFORGE_LOG_DIR": str(log_dir)}):
            response = self.client.get("/api/system")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["runtime_logs"]["log_dir"], str(log_dir))
        web_log = next(item for item in payload["runtime_logs"]["logs"] if item["key"] == "web")
        self.assertEqual(web_log["lines"][-1], "web-two")

    def test_stale_running_jobs_are_recovered_before_dashboard_api(self):
        upload_path = self.uploads_dir / "stale.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")
        job = app_module.create_job_record(
            name="Stale run",
            mode="full_scan",
            original_name="stale.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced"),
        )
        job.status = "running"
        job.current_step = "Static analysis"
        job.steps[0].status = "running"
        job.updated_at = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        self.store.job_dir(job.id).mkdir(parents=True, exist_ok=True)
        self.store.job_file(job.id).write_text(json.dumps(job.to_dict()), encoding="utf-8")

        with patch.object(app_module, "STALE_RUNNING_SECONDS", 60):
            response = self.client.get("/api/dashboard")

        self.assertEqual(response.status_code, 200)
        recovered = self.store.load(job.id)
        self.assertEqual(recovered.status, "failed")
        self.assertTrue(recovered.metadata["stale_recovered"])
        self.assertIn("worker stopped updating", recovered.logs[-1])

    def test_cancel_route_marks_queued_job_cancelled(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Queued run",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        job = self.store.list()[0]
        cancel_response = self.client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
        self.assertEqual(cancel_response.status_code, 303)
        cancelled = self.store.load(job.id)
        self.assertEqual(cancelled.status, "cancelled")
        self.assertTrue(cancelled.metadata["cancel_requested"])

    def test_force_cancel_api_marks_running_job_cancelled(self):
        upload_path = self.uploads_dir / "running.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")
        job = app_module.create_job_record(
            name="Running run",
            mode="full_scan",
            original_name="running.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced"),
        )
        job.status = "running"
        self.store.save(job)

        response = self.client.post(f"/api/jobs/{job.id}/cancel?force=true")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "cancelled")
        self.assertTrue(payload["metadata"]["force_cancelled"])

    def test_pause_and_resume_routes_toggle_queue_state(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Pause me",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        job = self.store.list()[0]

        pause_response = self.client.post(f"/jobs/{job.id}/pause", follow_redirects=False)
        self.assertEqual(pause_response.status_code, 303)
        paused = self.store.load(job.id)
        self.assertEqual(paused.status, "paused")

        resume_response = self.client.post(f"/jobs/{job.id}/resume", follow_redirects=False)
        self.assertEqual(resume_response.status_code, 303)
        resumed = self.store.load(job.id)
        self.assertEqual(resumed.status, "queued")
        self.assertFalse(resumed.metadata.get("pause_requested"))
        self.assertEqual(self.start_background_job.call_count, 2)

    def test_delete_route_removes_completed_job(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Delete me",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        job = self.store.list()[0]
        self.store.mutate(job.id, lambda current: setattr(current, "status", "completed"))

        delete_response = self.client.post(
            f"/jobs/{job.id}/delete",
            data={"next_url": "/"},
            follow_redirects=False,
        )

        self.assertEqual(delete_response.status_code, 303)
        self.assertFalse(self.store.job_dir(job.id).exists())

    def test_view_report_route_redirects_to_html_artifact(self):
        upload_path = self.uploads_dir / "sample.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")
        job = app_module.create_job_record(
            name="Reported job",
            mode="full_scan",
            original_name="sample.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced"),
        )
        job.html_report = "report.html"
        self.store.save(job)

        response = self.client.get(f"/jobs/{job.id}/report", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], f"/jobs/{job.id}/artifacts/report.html")

    def test_artifact_route_serves_only_declared_files_inside_report_dir(self):
        upload_path = self.uploads_dir / "sample.cpp"
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")
        job = app_module.create_job_record(
            name="Reported job",
            mode="full_scan",
            original_name="sample.cpp",
            upload_path=upload_path,
            options=JobOptions(preset="balanced"),
        )
        output_dir = Path(job.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "report.html").write_text("<h1>ok</h1>", encoding="utf-8")
        (output_dir / "secret.txt").write_text("hidden", encoding="utf-8")
        job.html_report = "report.html"
        self.store.save(job)

        ok_response = self.client.get(f"/jobs/{job.id}/artifacts/report.html")
        secret_response = self.client.get(f"/jobs/{job.id}/artifacts/secret.txt")
        traversal_response = self.client.get(f"/jobs/{job.id}/artifacts/%2E%2E")

        self.assertEqual(ok_response.status_code, 200)
        self.assertEqual(secret_response.status_code, 404)
        self.assertEqual(traversal_response.status_code, 404)

    def test_queue_move_routes_reorder_jobs(self):
        created = []
        for name in ("First", "Second", "Third"):
            response = self.client.post(
                "/jobs",
                data={
                    "name": name,
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": (f"{name}.cpp", b"int main() { return 0; }\n", "text/plain")},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)
            created.append(self.store.list()[0])

        ordered_before = [job.name for job in sorted(self.store.list(), key=lambda item: item.queue_position)]
        self.assertEqual(ordered_before, ["First", "Second", "Third"])

        target = next(job for job in self.store.list() if job.name == "Third")
        move_response = self.client.post(f"/jobs/{target.id}/queue/up", follow_redirects=False)
        self.assertEqual(move_response.status_code, 303)

        ordered_after = [job.name for job in sorted(self.store.list(), key=lambda item: item.queue_position)]
        self.assertEqual(ordered_after, ["First", "Third", "Second"])

    def test_queue_reposition_api_reorders_jobs_by_target(self):
        for name in ("First", "Second", "Third"):
            response = self.client.post(
                "/jobs",
                data={
                    "name": name,
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": (f"{name}.cpp", b"int main() { return 0; }\n", "text/plain")},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)

        jobs = {job.name: job for job in self.store.list()}
        response = self.client.post(
            f"/api/jobs/{jobs['Third'].id}/queue/reposition",
            json={
                "target_job_id": jobs["First"].id,
                "placement": "before",
            },
        )

        self.assertEqual(response.status_code, 200)
        ordered = [job.name for job in sorted(self.store.list(), key=lambda item: item.queue_position)]
        self.assertEqual(ordered, ["Third", "First", "Second"])

    def test_dashboard_renders_drag_and_drop_hooks(self):
        response = self.client.post(
            "/jobs",
            data={
                "name": "Draggable",
                "mode": "full_scan",
                "preset": "balanced",
            },
            files={"upload": ("drag.cpp", b"int main() { return 0; }\n", "text/plain")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn('data-queue-list', dashboard.text)
        self.assertIn('data-queue-job-id=', dashboard.text)
        self.assertIn('Drag', dashboard.text)
        self.assertIn("Delete", dashboard.text)


if __name__ == "__main__":
    unittest.main()
