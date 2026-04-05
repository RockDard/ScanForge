import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import qa_portal.app as app_module
from qa_portal.models import JobOptions
from qa_portal.storage import JobStore


class PortalAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.jobs_dir = root / "jobs"
        self.uploads_dir = root / "uploads"
        self.store = JobStore(self.jobs_dir)

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.start_background_job = self.stack.enter_context(
            patch.object(app_module, "start_background_job")
        )
        self.stack.enter_context(patch.object(app_module, "store", self.store))
        self.stack.enter_context(patch.object(app_module, "UPLOAD_DIR", self.uploads_dir))
        self.client = TestClient(app_module.app)

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

    def test_dashboard_renders_knowledge_base_sync_button(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/knowledge-base/sync"', response.text)
        self.assertIn("Sync now", response.text)

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
        self.assertIn("knowledge_base", payload)
        self.assertIn("hardware", payload)
        self.assertIn("recommended_worker_processes", payload)
        self.assertIn("worker_mode", payload)

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


if __name__ == "__main__":
    unittest.main()
