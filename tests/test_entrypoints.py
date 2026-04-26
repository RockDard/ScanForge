import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def _working_bash_available() -> bool:
    try:
        subprocess.run(
            ["bash", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


@unittest.skipUnless(_working_bash_available(), "working bash is required for Linux entrypoint tests")
class EntrypointTests(unittest.TestCase):
    def test_scanforge_helper_sets_pythonpath_outside_project_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            command = f"""
source "{ROOT_DIR / 'scripts' / 'scanforge-lib.sh'}"
scanforge_init_python "{ROOT_DIR}"
"$PYTHON_BIN" -c "import qa_portal.runtime; print('ok')"
"""
            result = subprocess.run(
                ["bash", "-lc", command],
                capture_output=True,
                text=True,
                cwd=temp_dir,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ok", result.stdout)

    def test_run_sync_kb_help_works_outside_project_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                ["bash", str(ROOT_DIR / "run-sync-kb.sh"), "--help"],
                capture_output=True,
                text=True,
                cwd=temp_dir,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Sync the local vulnerability intelligence mirror.", result.stdout)
        self.assertNotIn("ModuleNotFoundError", result.stdout + result.stderr)

    def test_preflight_help_works_outside_project_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                ["bash", str(ROOT_DIR / "scripts" / "scanforge-preflight.sh"), "--help"],
                capture_output=True,
                text=True,
                cwd=temp_dir,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ScanForge environment diagnostics.", result.stdout)
        self.assertNotIn("ModuleNotFoundError", result.stdout + result.stderr)

    def test_setup_script_help_is_available(self):
        result = subprocess.run(
            ["bash", str(ROOT_DIR / "scripts" / "setup-scanforge.sh"), "--help"],
            capture_output=True,
            text=True,
            cwd=ROOT_DIR,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("creates the project .venv", result.stdout)
        self.assertIn("creates the desktop shortcut", result.stdout)

    def test_web_smoke_script_help_is_available(self):
        result = subprocess.run(
            ["bash", str(ROOT_DIR / "scripts" / "run-web-smoke.sh"), "--help"],
            capture_output=True,
            text=True,
            cwd=ROOT_DIR,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Run the optional ScanForge web smoke stage.", result.stdout)

    def test_ci_agent_help_is_available(self):
        result = subprocess.run(
            ["bash", str(ROOT_DIR / "scripts" / "scanforge-ci-agent.sh"), "--help"],
            capture_output=True,
            text=True,
            cwd=ROOT_DIR,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertIn("SCANFORGE_REPOSITORY_URL", result.stdout)

    def test_systemd_generator_help_is_available(self):
        result = subprocess.run(
            ["bash", str(ROOT_DIR / "scripts" / "generate-systemd-units.sh"), "--help"],
            capture_output=True,
            text=True,
            cwd=ROOT_DIR,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Generates scanforge-web.service", result.stdout)


if __name__ == "__main__":
    unittest.main()
