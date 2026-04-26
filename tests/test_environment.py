import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qa_portal.environment import build_environment_status


class EnvironmentTests(unittest.TestCase):
    def test_environment_status_reports_satisfied_requirements(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")

            with (
                patch("qa_portal.environment.metadata.version", return_value="1.0"),
                patch("qa_portal.environment._pip_available", return_value=True),
                patch("qa_portal.environment._venv_available", return_value=True),
            ):
                status = build_environment_status(root)

        self.assertTrue(status["current_runtime_ready"])
        self.assertEqual(status["requirements_total"], 1)
        self.assertEqual(status["requirements_satisfied"], 1)
        self.assertFalse(status["missing_requirements"])

    def test_environment_status_reports_missing_requirements(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("missing-demo==1.0\n", encoding="utf-8")

            def _raise_missing(_name: str):
                from importlib.metadata import PackageNotFoundError

                raise PackageNotFoundError

            with (
                patch("qa_portal.environment.metadata.version", side_effect=_raise_missing),
                patch("qa_portal.environment._pip_available", return_value=True),
                patch("qa_portal.environment._venv_available", return_value=True),
            ):
                status = build_environment_status(root)

        self.assertFalse(status["current_runtime_ready"])
        self.assertEqual(status["requirements_total"], 1)
        self.assertEqual(len(status["missing_requirements"]), 1)


if __name__ == "__main__":
    unittest.main()
