import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qa_portal import tooling


class ToolingInstallTests(unittest.TestCase):
    def test_install_host_tool_uses_sudo_password_for_apt_packages(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n", stderr="")
        with patch.dict(os.environ, {"SCANFORGE_SUDO_PASSWORD": "secret"}, clear=False):
            with patch("qa_portal.tooling.os.geteuid", return_value=1000):
                with patch("qa_portal.tooling.shutil.which", return_value="/usr/bin/sudo"):
                    with patch("qa_portal.tooling.detect_package_manager", return_value="apt"):
                        with patch("qa_portal.tooling._tool_path", side_effect=[None, "/usr/bin/pytest"]):
                            with patch("qa_portal.tooling.subprocess.run", return_value=completed) as runner:
                                result = tooling.install_host_tool("pytest")

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["packages"], ["python3-pytest"])
        self.assertEqual(runner.call_count, 2)
        update_command = runner.call_args_list[0].args[0]
        install_command = runner.call_args_list[1].args[0]
        self.assertIn("-S", update_command)
        self.assertIn("apt-get", update_command)
        self.assertIn("--no-install-recommends", install_command)
        self.assertEqual(runner.call_args_list[0].kwargs["input"], "secret\n")
        self.assertNotIn("secret", "\n".join(result["logs"]))

    def test_install_host_tool_reports_admin_requirement_without_privilege_runner(self):
        with patch.dict(os.environ, {"SCANFORGE_SUDO_PASSWORD": ""}, clear=False):
            with patch("qa_portal.tooling.os.geteuid", return_value=1000):
                with patch("qa_portal.tooling.shutil.which", return_value=None):
                    with patch("qa_portal.tooling.detect_package_manager", return_value="apt"):
                        with patch("qa_portal.tooling._tool_path", return_value=None):
                            result = tooling.install_host_tool("pytest")

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "requires-admin")
        self.assertEqual(result["packages"], ["python3-pytest"])

    def test_dry_run_host_tool_uses_package_manager_simulation(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="Inst python3-pytest\n", stderr="")
        with patch("qa_portal.tooling.detect_package_manager", return_value="apt"):
            with patch("qa_portal.tooling._tool_path", return_value=None):
                with patch("qa_portal.tooling.tool_install_preflight", return_value={"ok": True, "issues": [], "warnings": []}):
                    with patch("qa_portal.tooling.subprocess.run", return_value=completed) as runner:
                        result = tooling.dry_run_host_tool("pytest")

        self.assertTrue(result["ok"])
        self.assertTrue(result["confirmation_required"])
        self.assertEqual(result["packages"], ["python3-pytest"])
        self.assertIn("-s", runner.call_args.args[0])
        self.assertIn("Inst python3-pytest", "\n".join(result["logs"]))

    def test_tool_install_job_runs_in_background_and_persists_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            jobs_dir = Path(temp_dir)
            with patch("qa_portal.tooling.TOOL_INSTALL_JOBS_DIR", jobs_dir):
                with patch("qa_portal.tooling._install_plan", return_value={
                    "ok": True,
                    "status": "ready",
                    "tool_key": "pytest",
                    "label": "pytest",
                    "package_manager": "apt",
                    "packages": ["python3-pytest"],
                    "commands": [],
                    "dry_run_commands": [],
                }):
                    with patch("qa_portal.tooling.dry_run_host_tool", return_value={
                        "ok": True,
                        "status": "ready",
                        "packages": ["python3-pytest"],
                        "logs": ["dry-run ok"],
                    }):
                        with patch("qa_portal.tooling.install_host_tool", return_value={
                            "ok": True,
                            "status": "installed",
                            "packages": ["python3-pytest"],
                            "message": "pytest installation finished.",
                        }):
                            job = tooling.start_tool_install_job("pytest", confirmed_packages=["python3-pytest"])
                            finished = tooling.wait_for_tool_install_job(job["id"], timeout_seconds=2)

        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["packages"], ["python3-pytest"])
        self.assertEqual(finished["result"]["status"], "installed")

    def test_tool_install_job_requires_confirmed_packages(self):
        with patch("qa_portal.tooling._install_plan", return_value={
            "ok": True,
            "status": "ready",
            "tool_key": "pytest",
            "label": "pytest",
            "package_manager": "apt",
            "packages": ["python3-pytest"],
            "commands": [],
            "dry_run_commands": [],
        }):
            result = tooling.start_tool_install_job("pytest")

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "confirmation-required")

    def test_tool_install_job_rejects_stale_confirmed_packages(self):
        with patch("qa_portal.tooling._install_plan", return_value={
            "ok": True,
            "status": "ready",
            "tool_key": "pytest",
            "label": "pytest",
            "package_manager": "apt",
            "packages": ["python3-pytest"],
            "commands": [],
            "dry_run_commands": [],
        }):
            result = tooling.start_tool_install_job("pytest", confirmed_packages=["pytest"])

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "package-confirmation-mismatch")

    def test_stale_tool_install_jobs_are_recovered(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            jobs_dir = Path(temp_dir)
            with patch("qa_portal.tooling.TOOL_INSTALL_JOBS_DIR", jobs_dir):
                stale_job = {
                    "id": "stale-job",
                    "tool_key": "pytest",
                    "status": "running",
                    "progress": 35,
                    "message": "Installing.",
                    "created_at": "2020-01-01T00:00:00+00:00",
                    "updated_at": "2020-01-01T00:00:00+00:00",
                    "logs": [],
                }
                jobs_dir.mkdir(parents=True, exist_ok=True)
                (jobs_dir / "stale-job.json").write_text(json.dumps(stale_job), encoding="utf-8")

                recovered = tooling.recover_stale_tool_install_jobs(stale_seconds=60)
                status = tooling.tool_install_job_status("stale-job")

        self.assertEqual(len(recovered), 1)
        self.assertEqual(status["status"], "failed")
        self.assertIn("interrupted", status["message"])

    def test_tool_install_job_status_recovers_stale_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            jobs_dir = Path(temp_dir)
            with patch("qa_portal.tooling.TOOL_INSTALL_JOBS_DIR", jobs_dir):
                stale_job = {
                    "id": "stale-status-job",
                    "tool_key": "pytest",
                    "status": "queued",
                    "progress": 0,
                    "message": "Queued.",
                    "created_at": "2020-01-01T00:00:00+00:00",
                    "updated_at": "2020-01-01T00:00:00+00:00",
                    "logs": [],
                }
                jobs_dir.mkdir(parents=True, exist_ok=True)
                (jobs_dir / "stale-status-job.json").write_text(json.dumps(stale_job), encoding="utf-8")

                status = tooling.tool_install_job_status("stale-status-job")

        self.assertEqual(status["status"], "failed")
        self.assertIn("interrupted", status["message"])


if __name__ == "__main__":
    unittest.main()
