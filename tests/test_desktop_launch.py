import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class DesktopLaunchTests(unittest.TestCase):
    def test_install_shortcut_script_creates_non_terminal_desktop_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            desktop_dir = Path(temp_dir) / "Desktop"
            env = os.environ.copy()
            env["DESKTOP_DIR"] = str(desktop_dir)

            result = subprocess.run(
                ["bash", str(ROOT_DIR / "scripts" / "install-desktop-shortcut.sh")],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            desktop_file = desktop_dir / "ScanForge.desktop"
            self.assertEqual(result.stdout.strip(), str(desktop_file))
            self.assertTrue(desktop_file.exists())

            content = desktop_file.read_text(encoding="utf-8")
            self.assertIn("Name=ScanForge", content)
            self.assertIn("Terminal=false", content)
            self.assertIn("launch-scanforge-desktop.sh", content)
            self.assertIn("scanforge-icon.svg", content)
