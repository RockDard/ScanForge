import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from qa_portal.ubuntu_validation import (
    build_validation_report_template,
    load_matrix,
    main,
    read_json_file,
    release_validation_status,
    run_validation_matrix,
    validate_matrix,
    validate_validation_report,
)


MATRIX_PATH = Path(__file__).resolve().parent / "fixtures" / "ubuntu_2204_test_matrix.json"


class UbuntuValidationTests(unittest.TestCase):
    def setUp(self):
        self.matrix = load_matrix(MATRIX_PATH)
        self.host = {
            "hostname": "ubuntu-2204-validation-host",
            "kernel": "5.15.0",
            "platform": "Linux-5.15.0-x86_64-with-glibc2.35",
            "python": "3.10.12",
            "package_manager": "apt",
            "privilege_mode": "not-run",
            "os_release_id": "ubuntu",
            "os_release_version_id": "22.04",
            "is_target_ubuntu_2204": True,
        }

    def test_matrix_validator_accepts_fixture(self):
        self.assertEqual(validate_matrix(self.matrix), [])

    def test_matrix_validator_rejects_wrong_sudo_password_env(self):
        matrix = copy.deepcopy(self.matrix)
        scenario = next(item for item in matrix["scenarios"] if item["privilege_mode"] == "sudo-password")
        scenario["env"]["QA_PORTAL_SUDO_PASSWORD"] = scenario["env"].pop("SCANFORGE_SUDO_PASSWORD")

        errors = validate_matrix(matrix)

        self.assertTrue(any("SCANFORGE_SUDO_PASSWORD" in item for item in errors))
        self.assertTrue(any("QA_PORTAL_SUDO_PASSWORD" in item for item in errors))

    def test_report_template_covers_matrix_and_validates(self):
        report = build_validation_report_template(
            self.matrix,
            host=self.host,
            generated_at="2026-04-26T00:00:00+00:00",
        )

        self.assertEqual(validate_validation_report(report, self.matrix), [])
        self.assertEqual(report["target_os"], "ubuntu-22.04")
        self.assertEqual(report["summary"]["scenario_count"], len(self.matrix["scenarios"]))
        self.assertEqual(report["summary"]["check_count"], 27)
        self.assertEqual(report["summary"]["not_run"], 27)
        self.assertTrue(
            all(
                check["status"] == "not-run"
                for scenario in report["scenarios"]
                for check in scenario["checks"]
            )
        )

    def test_report_validator_rejects_missing_scenario(self):
        report = build_validation_report_template(
            self.matrix,
            host=self.host,
            generated_at="2026-04-26T00:00:00+00:00",
        )
        report["scenarios"] = report["scenarios"][:-1]

        errors = validate_validation_report(report, self.matrix)

        self.assertTrue(any("missing scenarios" in item for item in errors))

    def test_report_validator_rejects_inconsistent_check_result(self):
        report = build_validation_report_template(
            self.matrix,
            host=self.host,
            generated_at="2026-04-26T00:00:00+00:00",
        )
        check = report["scenarios"][0]["checks"][0]
        check["status"] = "passed"
        check["exit_code"] = 1

        errors = validate_validation_report(report, self.matrix)

        self.assertTrue(any("passed checks must have exit_code 0" in item for item in errors))
        self.assertTrue(any("executed checks must include log_path" in item for item in errors))
        self.assertTrue(any("scenario ubuntu-22.04-root-apt status must be passed" in item for item in errors))

    def test_run_matrix_blocks_on_non_target_host_without_running_commands(self):
        calls = []

        def runner(command, *, env, timeout_seconds):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"
            report = run_validation_matrix(
                self.matrix,
                output_path=output,
                log_dir=Path(temp_dir) / "logs",
                host={
                    **self.host,
                    "package_manager": "unknown",
                    "is_target_ubuntu_2204": False,
                },
                command_runner=runner,
            )

        self.assertEqual(calls, [])
        self.assertEqual(report["summary"]["blocked"], 27)
        self.assertEqual(validate_validation_report(report, self.matrix, require_completed=True), [])

    def test_run_matrix_executes_selected_target_scenario_and_writes_logs(self):
        calls = []

        def runner(command, *, env, timeout_seconds):
            calls.append((command, env, timeout_seconds))
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"
            log_dir = Path(temp_dir) / "logs"
            report = run_validation_matrix(
                self.matrix,
                output_path=output,
                log_dir=log_dir,
                scenario_ids={"ubuntu-22.04-root-apt"},
                host=self.host,
                command_runner=runner,
            )

        self.assertEqual(len(calls), 6)
        self.assertEqual(report["summary"]["passed"], 6)
        self.assertEqual(report["summary"]["skipped"], 21)
        self.assertEqual(report["summary"]["not_run"], 0)
        self.assertEqual(validate_validation_report(report, self.matrix, require_completed=True), [])
        self.assertTrue(all(check["log_path"] for check in report["scenarios"][0]["checks"]))
        self.assertEqual(calls[0][1]["QA_PORTAL_AUTH_AUTO_SETUP"], "1")

    def test_run_matrix_rejects_unknown_scenario_filter(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "Unknown scenario ids"):
                run_validation_matrix(
                    self.matrix,
                    output_path=Path(temp_dir) / "report.json",
                    log_dir=Path(temp_dir) / "logs",
                    scenario_ids={"missing-scenario"},
                    host=self.host,
                )

    def test_cli_writes_report_template(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "ubuntu_2204_validation_report.json"
            code = main(["write-report-template", "--matrix", str(MATRIX_PATH), "--output", str(output)])
            report = read_json_file(output)

        self.assertEqual(code, 0)
        self.assertEqual(validate_validation_report(report, self.matrix), [])

    def test_cli_run_matrix_rejects_unknown_scenario(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "ubuntu_2204_validation_report.json"
            code = main(
                [
                    "run-matrix",
                    "--matrix",
                    str(MATRIX_PATH),
                    "--output",
                    str(output),
                    "--scenario",
                    "missing-scenario",
                ]
            )

        self.assertEqual(code, 1)

    def test_release_validation_status_requires_completed_clean_report(self):
        report = build_validation_report_template(
            self.matrix,
            host=self.host,
            generated_at="2026-04-26T00:00:00+00:00",
        )
        for scenario in report["scenarios"]:
            scenario["status"] = "passed"
            for check in scenario["checks"]:
                check["status"] = "passed"
                check["exit_code"] = 0
                check["duration_seconds"] = 0.1
                check["log_path"] = "data/validation/logs/check.log"
                check["message"] = "Command completed."
        report["summary"] = {
            "scenario_count": len(report["scenarios"]),
            "check_count": sum(len(scenario["checks"]) for scenario in report["scenarios"]),
            "passed": sum(len(scenario["checks"]) for scenario in report["scenarios"]),
            "failed": 0,
            "skipped": 0,
            "blocked": 0,
            "not_run": 0,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            status = release_validation_status(report_path=report_path, matrix_path=MATRIX_PATH)

        self.assertTrue(status["ready"])

    def test_release_validation_status_rejects_missing_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status = release_validation_status(report_path=Path(temp_dir) / "missing.json", matrix_path=MATRIX_PATH)

        self.assertFalse(status["ready"])
        self.assertIn("validation report is missing", status["errors"])


if __name__ == "__main__":
    unittest.main()
