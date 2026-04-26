import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

if os.name == "nt":
    raise unittest.SkipTest("worker tests require POSIX file locking through fcntl")

from qa_portal.analysis import is_archive
from qa_portal.models import JobOptions
from qa_portal.models import JobRecord
from qa_portal.storage import JobStore, default_steps
from qa_portal.worker import process_one_job, resolve_worker_processes


class WorkerTests(unittest.TestCase):
    def test_process_one_job_claims_and_executes_queued_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            store = JobStore(root / "jobs")
            upload_path = root / "uploads" / "sample.cpp"
            upload_path.parent.mkdir(parents=True, exist_ok=True)
            upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")
            job_id = "workerjob001"
            job_dir = store.job_dir(job_id)
            workspace_path = job_dir / "workspace"
            output_dir = job_dir / "reports"
            workspace_path.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)

            job = JobRecord(
                id=job_id,
                name="Queued job",
                mode="full_scan",
                input_type="archive" if is_archive(upload_path) else "single_file",
                original_filename="sample.cpp",
                upload_path=str(upload_path),
                workspace_path=str(workspace_path),
                output_dir=str(output_dir),
                options=JobOptions(preset="balanced"),
                steps=default_steps("full_scan", JobOptions(preset="balanced")),
            )
            store.save(job)

            with patch("qa_portal.worker.run_job") as run_job:
                worked = process_one_job(store)

            self.assertTrue(worked)
            run_job.assert_called_once()
            claimed = store.load(job.id)
            self.assertEqual(claimed.status, "running")
            self.assertIn("worker_id", claimed.metadata)

    def test_resolve_worker_processes_uses_auto_profile(self):
        with patch("qa_portal.worker.detect_host_hardware") as detect_host_hardware, patch(
            "qa_portal.worker.recommended_worker_processes"
        ) as recommended:
            detect_host_hardware.return_value = object()
            recommended.return_value = 4

            self.assertEqual(resolve_worker_processes("auto"), 4)
            self.assertEqual(resolve_worker_processes("3"), 3)
            self.assertEqual(resolve_worker_processes("invalid"), 1)

    def test_try_claim_respects_queue_position_and_skips_paused_jobs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            store = JobStore(root / "jobs")
            upload_path = root / "uploads" / "sample.cpp"
            upload_path.parent.mkdir(parents=True, exist_ok=True)
            upload_path.write_text("int main() { return 0; }\n", encoding="utf-8")

            jobs = []
            for job_id, name, queue_position, status in (
                ("job1", "First", 2, "queued"),
                ("job2", "Second", 1, "queued"),
                ("job3", "Paused", 3, "paused"),
            ):
                job_dir = store.job_dir(job_id)
                workspace_path = job_dir / "workspace"
                output_dir = job_dir / "reports"
                workspace_path.mkdir(parents=True, exist_ok=True)
                output_dir.mkdir(parents=True, exist_ok=True)
                job = JobRecord(
                    id=job_id,
                    name=name,
                    mode="full_scan",
                    input_type="archive" if is_archive(upload_path) else "single_file",
                    original_filename="sample.cpp",
                    upload_path=str(upload_path),
                    workspace_path=str(workspace_path),
                    output_dir=str(output_dir),
                    queue_position=queue_position,
                    options=JobOptions(preset="balanced"),
                    status=status,  # type: ignore[arg-type]
                    steps=default_steps("full_scan", JobOptions(preset="balanced")),
                )
                store.save(job)
                jobs.append(job)

            claimed = store.try_claim("worker:test")
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.id, "job2")


if __name__ == "__main__":
    unittest.main()
