import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
