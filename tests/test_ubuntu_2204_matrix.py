import json
import unittest
from pathlib import Path

from qa_portal.ubuntu_validation import validate_matrix


MATRIX_PATH = Path(__file__).resolve().parent / "fixtures" / "ubuntu_2204_test_matrix.json"

REQUIRED_SCENARIOS = {
    "ubuntu-22.04-root-apt",
    "ubuntu-22.04-sudo-passwordless-apt",
    "ubuntu-22.04-sudo-password-apt",
    "ubuntu-22.04-pkexec-apt",
    "ubuntu-22.04-no-privilege-apt",
}
REQUIRED_PRIVILEGE_MODES = {
    "root",
    "sudo-passwordless",
    "sudo-password",
    "pkexec",
    "no-privilege",
}
INSTALL_CAPABLE_PRIVILEGES = {
    "root",
    "sudo-passwordless",
    "sudo-password",
    "pkexec",
}


class Ubuntu2204TestMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
        self.scenarios = self.matrix["scenarios"]
        self.checks = {item["id"]: item for item in self.matrix["check_catalog"]}

    def test_matrix_targets_only_ubuntu_2204_apt(self):
        self.assertEqual(self.matrix["target_os"], "ubuntu-22.04")
        self.assertEqual(self.matrix["package_manager"], "apt")
        self.assertIn("windows", self.matrix["unsupported_direct_targets"])
        self.assertIn("wsl", self.matrix["unsupported_direct_targets"])
        self.assertEqual(validate_matrix(self.matrix), [])

        for scenario in self.scenarios:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(scenario["os"], "ubuntu-22.04")
                self.assertEqual(scenario["package_manager"], "apt")
                self.assertNotIn("debian", scenario["id"].lower())

    def test_required_privilege_scenarios_are_present(self):
        scenario_ids = {scenario["id"] for scenario in self.scenarios}
        privilege_modes = {scenario["privilege_mode"] for scenario in self.scenarios}

        self.assertTrue(REQUIRED_SCENARIOS <= scenario_ids)
        self.assertTrue(REQUIRED_PRIVILEGE_MODES <= privilege_modes)

    def test_scenarios_reference_known_linux_checks_only(self):
        self.assertTrue(self.checks)
        for check in self.checks.values():
            with self.subTest(check=check["id"]):
                command = check["command"].lower()
                self.assertTrue(check["requires_linux_runtime"])
                self.assertNotIn("wsl", command)
                self.assertNotIn("docker", command)
                self.assertFalse(command.startswith("python "))
                self.assertFalse(command.endswith(".ps1"))

        for scenario in self.scenarios:
            with self.subTest(scenario=scenario["id"]):
                for check_id in scenario["check_ids"]:
                    self.assertIn(check_id, self.checks)

    def test_install_capable_scenarios_cover_runtime_smoke_and_auth(self):
        for scenario in self.scenarios:
            if scenario["privilege_mode"] not in INSTALL_CAPABLE_PRIVILEGES:
                continue
            with self.subTest(scenario=scenario["id"]):
                check_ids = set(scenario["check_ids"])
                self.assertIn("setup-scanforge", check_ids)
                self.assertIn("run-tests", check_ids)
                self.assertIn("web-smoke", check_ids)
                self.assertIn("tool-install-unit-tests", check_ids)
                self.assertIn("systemd-unit-render", check_ids)
                self.assertIn("auth-bootstrap-status", check_ids)
                self.assertEqual(scenario["env"]["QA_PORTAL_AUTH_AUTO_SETUP"], "1")
                self.assertNotIn("QA_PORTAL_SUDO_PASSWORD", scenario["env"])
                if scenario["privilege_mode"] == "sudo-password":
                    self.assertIn("SCANFORGE_SUDO_PASSWORD", scenario["env"])

    def test_no_privilege_scenario_is_expected_to_block_installs(self):
        no_privilege = next(
            scenario
            for scenario in self.scenarios
            if scenario["privilege_mode"] == "no-privilege"
        )

        self.assertEqual(no_privilege["expected_install_result"], "blocked-by-preflight")
        self.assertIn("tool-install-preflight", no_privilege["check_ids"])
        self.assertNotIn("setup-scanforge", no_privilege["check_ids"])


if __name__ == "__main__":
    unittest.main()
