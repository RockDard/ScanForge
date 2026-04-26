import json
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
import zipfile

if os.name == "nt":
    raise unittest.SkipTest("portal pipeline tests require the target Linux runtime")

from qa_portal.app import app
from qa_portal.analysis import (
    ExtractionError,
    analyze_fuzzing,
    analyze_functionality,
    analyze_quality,
    analyze_security,
    analyze_style,
    compare_project_versions,
    detect_project,
    extract_input,
    iter_text_files,
    summarize_findings,
)
from qa_portal.compliance import build_compliance_profiles
from qa_portal.dependency_analysis import analyze_dependencies, compare_dependency_inventory
from qa_portal.finding_lifecycle import compare_with_baseline
from qa_portal.models import Finding
from qa_portal.models import JobOptions
from qa_portal.pipeline import run_job
from qa_portal.presets import list_presets
from qa_portal.release_gate import DEFAULT_POLICY, evaluate_release_gate
from qa_portal.runtime_scans import analyze_service_runtime, analyze_vm_runtime
from qa_portal.storage import JobContext, JobStore, default_steps


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "sample_qt_project"


class PortalAnalysisTests(unittest.TestCase):
    def test_app_imports(self):
        self.assertEqual(app.title, "ScanForge")

    def test_default_steps_respect_selected_checks(self):
        options = JobOptions(
            run_functionality=True,
            run_security=False,
            run_style=True,
            run_quality=False,
            run_fuzzing=False,
        )
        steps = {step.key: step for step in default_steps("full_scan", options)}
        self.assertEqual(steps["security"].status, "skipped")
        self.assertEqual(steps["quality"].status, "skipped")
        self.assertEqual(steps["functionality"].status, "pending")
        self.assertEqual(steps["style"].status, "pending")

    def test_project_detection_flags_qt_and_tests(self):
        info = detect_project(FIXTURE_ROOT)
        self.assertTrue(info["is_qt_project"])
        self.assertTrue(info["has_tests"])
        self.assertIn("cmake", info["build_systems"])
        self.assertIn("C/C++", info["programming_languages"])

    def test_static_rules_find_expected_findings(self):
        files = iter_text_files(FIXTURE_ROOT)
        security = analyze_security(FIXTURE_ROOT, files)
        style = analyze_style(FIXTURE_ROOT, files)
        quality = analyze_quality(FIXTURE_ROOT, files, detect_project(FIXTURE_ROOT))

        self.assertTrue(any(item.title == "Potential buffer overflow" for item in security))
        self.assertTrue(any(item.title == "Tab indentation" for item in style))
        self.assertTrue(any(item.title.startswith("Outstanding marker") for item in quality))

    def test_security_analysis_detects_taint_flows_and_cwe_references(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api = root / "api.py"
            api.write_text(
                "\n".join(
                    [
                        "import subprocess",
                        "import yaml",
                        "",
                        "def handle(request, cursor):",
                        "    command = request.args['cmd']",
                        "    subprocess.run(command, shell=True)",
                        "    cursor.execute(f\"SELECT * FROM users WHERE name='{request.args['name']}'\")",
                        "    yaml.load(request.data)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            server = root / "server.js"
            server.write_text(
                "\n".join(
                    [
                        "const child_process = require('child_process');",
                        "function route(req, res) {",
                        "  const cmd = req.query.cmd;",
                        "  child_process.exec(cmd);",
                        "  res.setHeader('Access-Control-Allow-Origin', '*');",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            native = root / "main.cpp"
            native.write_text(
                "\n".join(
                    [
                        "#include <cstdlib>",
                        "#include <string>",
                        "int main(int argc, char** argv) {",
                        "    std::string cmd = argv[1];",
                        "    return system(cmd.c_str());",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(
                "\n".join(
                    [
                        "FROM python:3.12-slim",
                        "COPY . /app",
                        "CMD [\"python\", \"app.py\"]",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_security(root, iter_text_files(root))
            titles = {item.title for item in findings}
            reference_ids = {
                reference["id"]
                for item in findings
                for reference in item.references
            }

            self.assertIn("User-controlled data reaches shell execution", titles)
            self.assertIn("SQL query built with string interpolation", titles)
            self.assertIn("Unsafe YAML deserialization", titles)
            self.assertIn("Permissive CORS policy", titles)
            self.assertIn("Container image uses default root user", titles)
            self.assertIn("CWE-78", reference_ids)
            self.assertIn("CWE-89", reference_ids)
            self.assertIn("CWE-250", reference_ids)
            self.assertIn("OWASP-A03", reference_ids)

    def test_parser_backed_security_engine_detects_python_and_javascript_flows(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api = root / "api.py"
            api.write_text(
                "\n".join(
                    [
                        "import subprocess",
                        "",
                        "def route(request, cursor):",
                        "    code = request.args.get('code')",
                        "    eval(code)",
                        "    query = f\"SELECT * FROM users WHERE name='{code}'\"",
                        "    cursor.execute(query)",
                        "    subprocess.run(code, shell=True)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            server = root / "server.ts"
            server.write_text(
                "\n".join(
                    [
                        "function route(req, db, child_process) {",
                        "  const code = req.query.code;",
                        "  eval(code);",
                        "  db.query(`SELECT * FROM users WHERE name = ${code}`);",
                        "  child_process.exec(code);",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_security(root, iter_text_files(root))
            parser_findings = [item for item in findings if item.source.startswith("parser-security:")]
            titles = {item.title for item in parser_findings}
            traces = [item.trace for item in parser_findings if item.trace]

            self.assertIn("Python eval execution", titles)
            self.assertIn("JavaScript eval execution", titles)
            self.assertIn("Python shell=True", titles)
            self.assertIn("Node child_process exec", titles)
            self.assertIn("SQL query built with string interpolation", titles)
            self.assertIn("User-controlled data reaches dynamic code execution", titles)
            self.assertIn("User-controlled data reaches shell execution", titles)
            self.assertIn("User-controlled data reaches SQL query construction", titles)
            self.assertTrue(any(step.get("kind") == "source" for trace in traces for step in trace))
            self.assertTrue(any(item.confidence == "high" for item in parser_findings))

    def test_quality_rules_detect_redundant_disabled_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "widget.cpp"
            source.write_text(
                "\n".join(
                    [
                        "#include <vector>",
                        "#include <vector>",
                        "int live() { return 0; }",
                        "",
                        "// int disabled() {",
                        "//     return 1;",
                        "// }",
                        "",
                        "/*",
                        "QString legacyName() {",
                        '    return "old";',
                        "}",
                        "*/",
                        "",
                        "#if 0",
                        "int oldPath() {",
                        "    return 2;",
                        "}",
                        "#endif",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_quality(root, [source], detect_project(root))
            titles = {item.title for item in findings}

            self.assertIn("Commented-out code block", titles)
            self.assertIn("Disabled code region", titles)
            self.assertIn("Duplicate include/import directive", titles)

    def test_project_detection_recognizes_polyglot_languages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "tools").mkdir()
            (root / "tools" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "ui").mkdir()
            (root / "ui" / "MainView.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")

            info = detect_project(root)

            self.assertTrue(info["polyglot"])
            self.assertIn("C/C++", info["programming_languages"])
            self.assertIn("Python", info["programming_languages"])
            self.assertIn("QML", info["programming_languages"])
            self.assertGreaterEqual(info["multilinguality"]["programming_language_count"], 3)

    def test_project_detection_recognizes_python_go_and_node_manifests_with_tests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_api.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
            (root / "service").mkdir()
            (root / "service" / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
            (root / "service" / "main_test.go").write_text(
                "package main\n\nimport \"testing\"\n\nfunc TestPing(t *testing.T) {}\n",
                encoding="utf-8",
            )
            (root / "web").mkdir()
            (root / "web" / "package.json").write_text(
                json.dumps({"name": "web", "scripts": {"test": "vitest run"}}),
                encoding="utf-8",
            )
            (root / "web" / "app.spec.ts").write_text("describe('demo', () => test('ok', () => {}));\n", encoding="utf-8")

            info = detect_project(root)

            self.assertIn("python", info["build_systems"])
            self.assertIn("go", info["build_systems"])
            self.assertIn("node", info["build_systems"])
            self.assertTrue(info["has_tests"])
            self.assertIn("python", info["detected_test_frameworks"])
            self.assertIn("go", info["detected_test_frameworks"])
            self.assertIn("node", info["detected_test_frameworks"])

    def test_compare_project_versions_marks_python_node_and_go_manifests_as_build_changes(self):
        with tempfile.TemporaryDirectory() as baseline_dir, tempfile.TemporaryDirectory() as current_dir:
            baseline = Path(baseline_dir)
            current = Path(current_dir)
            (baseline / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            (current / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.2.0'\n", encoding="utf-8")

            summary, changed_files = compare_project_versions(current, baseline)

            self.assertTrue(summary["build_files_changed"])
            self.assertEqual(summary["changed_files"], ["pyproject.toml"])
            self.assertEqual([str(path.relative_to(current)) for path in changed_files], ["pyproject.toml"])

        with tempfile.TemporaryDirectory() as baseline_dir, tempfile.TemporaryDirectory() as current_dir:
            baseline = Path(baseline_dir)
            current = Path(current_dir)
            (baseline / "package.json").write_text(json.dumps({"name": "demo", "scripts": {"test": "vitest run"}}), encoding="utf-8")
            (current / "package.json").write_text(json.dumps({"name": "demo", "scripts": {"test": "vitest run --coverage"}}), encoding="utf-8")

            summary, _changed_files = compare_project_versions(current, baseline)

            self.assertTrue(summary["build_files_changed"])

        with tempfile.TemporaryDirectory() as baseline_dir, tempfile.TemporaryDirectory() as current_dir:
            baseline = Path(baseline_dir)
            current = Path(current_dir)
            (baseline / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
            (current / "go.mod").write_text("module example.com/demo\n\ngo 1.23\n", encoding="utf-8")

            summary, _changed_files = compare_project_versions(current, baseline)

            self.assertTrue(summary["build_files_changed"])

    def test_quality_analysis_adds_multilinguality_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            source = root / "src" / "main.cpp"
            source.write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")

            project_info = detect_project(root)
            findings = analyze_quality(root, iter_text_files(root), project_info)
            titles = {item.title for item in findings}

            self.assertIn("Polyglot project detected", titles)
            self.assertIn("Polyglot project without detected tests", titles)

    def test_analyze_functionality_falls_back_to_unittest_for_python(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_demo.py").write_text(
                "import unittest\n\nclass DemoTests(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )

            project_info = detect_project(root)
            commands: list[list[str]] = []

            def fake_run_command(command, cwd=None, timeout=300, env=None):
                commands.append(list(command))
                if command[:3] == ["/usr/bin/python3", "-m", "compileall"]:
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "compileall ok", "stderr": ""})()
                if command[:4] == ["/usr/bin/python3", "-m", "pytest", "-q"]:
                    return type("Result", (), {"command": command, "returncode": 1, "stdout": "", "stderr": "No module named pytest"})()
                if command[:4] == ["/usr/bin/python3", "-m", "unittest", "discover"]:
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "Ran 1 test in 0.001s\nOK", "stderr": ""})()
                raise AssertionError(f"Unexpected command: {command}")

            with patch("qa_portal.analysis.run_command", side_effect=fake_run_command):
                findings, logs, metadata = analyze_functionality(
                    root,
                    project_info,
                    {"python3": "/usr/bin/python3", "pytest": None},
                    root / "build",
                    None,
                )

            self.assertEqual(metadata["ecosystem_results"]["python"]["test_runner"], "unittest")
            self.assertTrue(metadata["tests_ran"])
            self.assertFalse(any(item.title == "Python tests failed" for item in findings))
            self.assertIn(["/usr/bin/python3", "-m", "pytest", "-q"], commands)
            self.assertIn(["/usr/bin/python3", "-m", "unittest", "discover", "-q"], commands)
            self.assertTrue(any("$ /usr/bin/python3 -m unittest discover -q" in item for item in logs))

    def test_analyze_functionality_runs_python_and_node_checks_for_polyglot_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_demo.py").write_text(
                "import unittest\n\nclass DemoTests(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"name": "web", "scripts": {"test": "vitest run"}}),
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "app.ts").write_text("export const answer: number = 42;\n", encoding="utf-8")
            (root / "src" / "app.spec.ts").write_text("describe('demo', () => test('ok', () => {}));\n", encoding="utf-8")
            node_bin = root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            (node_bin / "tsc").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (node_bin / "vitest").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

            project_info = detect_project(root)
            commands: list[list[str]] = []

            def fake_run_command(command, cwd=None, timeout=300, env=None):
                commands.append(list(command))
                if command[:3] == ["/usr/bin/python3", "-m", "compileall"]:
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "compileall ok", "stderr": ""})()
                if command[:4] == ["/usr/bin/python3", "-m", "pytest", "-q"]:
                    return type("Result", (), {"command": command, "returncode": 1, "stdout": "", "stderr": "No module named pytest"})()
                if command[:4] == ["/usr/bin/python3", "-m", "unittest", "discover"]:
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "Ran 1 test in 0.001s\nOK", "stderr": ""})()
                if command[0] == str(node_bin / "tsc"):
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "tsc ok", "stderr": ""})()
                if command[0] == str(node_bin / "vitest"):
                    return type("Result", (), {"command": command, "returncode": 0, "stdout": "vitest ok", "stderr": ""})()
                raise AssertionError(f"Unexpected command: {command}")

            with patch("qa_portal.analysis.run_command", side_effect=fake_run_command):
                findings, _logs, metadata = analyze_functionality(
                    root,
                    project_info,
                    {"python3": "/usr/bin/python3", "pytest": None, "node": "/usr/bin/node", "npm": "/usr/bin/npm", "tsc": None},
                    root / "build",
                    None,
                )

            self.assertIn("python", metadata["ecosystem_results"])
            self.assertIn("node", metadata["ecosystem_results"])
            self.assertEqual(metadata["ecosystem_results"]["python"]["test_runner"], "unittest")
            self.assertEqual(metadata["ecosystem_results"]["node"]["test_runner"], "vitest")
            self.assertTrue(any(command[0] == str(node_bin / "tsc") for command in commands))
            self.assertTrue(any(command[0] == str(node_bin / "vitest") for command in commands))
            self.assertFalse(any(item.title in {"Python tests failed", "Node.js tests failed"} for item in findings))

    def test_dependency_inventory_collects_manifests_and_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
            (root / "package.json").write_text(
                '{"name":"demo","license":"MIT","dependencies":{"left-pad":"^1.3.0"}}',
                encoding="utf-8",
            )

            findings, sbom = analyze_dependencies(root)

            self.assertEqual(sbom["manifest_count"], 2)
            self.assertGreaterEqual(sbom["component_count"], 2)
            self.assertTrue(any(item.category == "dependency" for item in findings))
            self.assertIn("python", sbom["ecosystem_counts"])
            self.assertIn("node", sbom["ecosystem_counts"])

    def test_dependency_inventory_matches_local_vulnerability_lookup_and_diff(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                '{"name":"demo","dependencies":{"demo-lib":"1.2.3"}}',
                encoding="utf-8",
            )
            lookup = {
                "cve": {
                    "CVE-2026-1000": {
                        "id": "CVE-2026-1000",
                        "summary": "demo-lib vulnerable release",
                        "severity": "9.8 CRITICAL",
                        "products": ["demo-lib"],
                        "vendors": ["demo"],
                        "cpes": ["cpe:2.3:a:demo:demo-lib:1.2.3:*:*:*:*:*:*:*"],
                        "kev": True,
                        "bdu_ids": ["BDU:2026-00001"],
                    }
                }
            }
            baseline_inventory = {
                "components": [
                    {"ecosystem": "node", "name": "stable-lib", "scope": "runtime", "version": "1.0.0", "vulnerabilities": []}
                ]
            }

            findings, sbom = analyze_dependencies(root, knowledge_lookup=lookup, baseline_inventory=baseline_inventory)

            self.assertTrue(any(item.title == "Vulnerable dependency candidate" for item in findings))
            self.assertEqual(sbom["vulnerable_component_count"], 1)
            self.assertEqual(sbom["dependency_diff"]["new_vulnerable_count"], 1)

    def test_dependency_inventory_uses_lockfile_resolved_versions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                '{"name":"demo","dependencies":{"demo-lib":"^1.0.0"}}',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "demo"},
                            "node_modules/demo-lib": {"version": "1.2.3"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            lookup = {
                "cve": {
                    "CVE-2026-1001": {
                        "id": "CVE-2026-1001",
                        "summary": "demo-lib resolved version vulnerable",
                        "severity": "8.0 HIGH",
                        "products": ["demo-lib"],
                        "vendors": ["demo"],
                        "cpes": ["cpe:2.3:a:demo:demo-lib:1.2.3:*:*:*:*:*:*:*"],
                        "kev": False,
                        "bdu_ids": [],
                    }
                }
            }

            findings, sbom = analyze_dependencies(root, knowledge_lookup=lookup)

            self.assertTrue(any(item.title == "Vulnerable dependency candidate" for item in findings))
            self.assertEqual(sbom["lockfile_count"], 1)
            self.assertGreaterEqual(sbom["resolved_component_count"], 1)
            matched = next(item for item in sbom["components"] if item["name"] == "demo-lib")
            self.assertEqual(matched["resolved_version"], "1.2.3")
            self.assertEqual(matched["effective_version"], "1.2.3")
            self.assertEqual(matched["vulnerabilities"][0]["confidence"], "resolved-exact")

    def test_dependency_inventory_matches_version_ranges_without_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("demo-lib>=1.0,<2.0\n", encoding="utf-8")
            lookup = {
                "cve": {
                    "CVE-2026-1002": {
                        "id": "CVE-2026-1002",
                        "summary": "demo-lib vulnerable range example",
                        "severity": "7.5 HIGH",
                        "products": ["demo-lib"],
                        "vendors": ["demo"],
                        "cpes": ["cpe:2.3:a:demo:demo-lib:1.2.3:*:*:*:*:*:*:*"],
                        "kev": False,
                        "bdu_ids": [],
                    }
                }
            }

            findings, sbom = analyze_dependencies(root, knowledge_lookup=lookup)

            self.assertTrue(any(item.title == "Vulnerable dependency candidate" for item in findings))
            matched = next(item for item in sbom["components"] if item["name"] == "demo-lib")
            self.assertEqual(matched["vulnerabilities"][0]["confidence"], "constraint-overlap")

    def test_dependency_diff_uses_effective_version_from_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                '{"name":"demo","dependencies":{"demo-lib":"^1.0.0"}}',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "demo"},
                            "node_modules/demo-lib": {"version": "1.2.4"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            baseline_inventory = {
                "components": [
                    {
                        "ecosystem": "node",
                        "name": "demo-lib",
                        "scope": "runtime",
                        "version": "^1.0.0",
                        "effective_version": "1.2.3",
                        "vulnerabilities": [],
                    }
                ]
            }

            _findings, sbom = analyze_dependencies(root, knowledge_lookup={"cve": {}}, baseline_inventory=baseline_inventory)

            self.assertEqual(len(sbom["dependency_diff"]["version_changed_components"]), 1)
            changed = sbom["dependency_diff"]["version_changed_components"][0]
            self.assertEqual(changed["baseline_version"], "1.2.3")
            self.assertEqual(changed["current_version"], "1.2.4")

    def test_dependency_diff_tracks_reachable_and_worsened_baseline_components(self):
        baseline_inventory = {
            "components": [
                {
                    "ecosystem": "node",
                    "name": "demo-lib",
                    "scope": "runtime",
                    "effective_version": "1.2.3",
                    "reachable": False,
                    "vulnerabilities": [
                        {"id": "CVE-2026-1000", "kev": False, "suppressed": False},
                    ],
                },
                {
                    "ecosystem": "node",
                    "name": "legacy-lib",
                    "scope": "runtime",
                    "effective_version": "0.9.0",
                    "reachable": True,
                    "vulnerabilities": [
                        {"id": "CVE-2025-2000", "kev": False, "suppressed": False},
                    ],
                },
            ]
        }
        current_inventory = {
            "components": [
                {
                    "ecosystem": "node",
                    "name": "demo-lib",
                    "scope": "runtime",
                    "effective_version": "1.2.4",
                    "reachable": True,
                    "vulnerabilities": [
                        {"id": "CVE-2026-1000", "kev": False, "suppressed": False},
                        {"id": "CVE-2026-1001", "kev": True, "suppressed": False},
                    ],
                }
            ]
        }

        diff = compare_dependency_inventory(current_inventory, baseline_inventory)

        self.assertTrue(diff["baseline_available"])
        self.assertEqual(diff["fixed_vulnerable_count"], 1)
        self.assertEqual(diff["new_reachable_vulnerable_count"], 1)
        self.assertEqual(diff["dependency_regression_count"], 1)
        self.assertEqual(diff["vulnerability_count_delta"], -1)
        self.assertEqual(diff["reachable_vulnerability_count_delta"], 0)
        regression = diff["worsened_components"][0]
        self.assertTrue(regression["became_reachable"])
        self.assertTrue(regression["kev_regression"])
        self.assertIn("CVE-2026-1001", regression["new_vulnerability_ids"])

    def test_service_runtime_detects_openapi_and_verifies_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "paths": {
                            "/health": {"get": {}},
                            "/api/items": {"get": {}, "post": {}},
                        },
                    }
                ),
                encoding="utf-8",
            )

            class _Result:
                pass

            def fake_probe(url, method="GET", timeout=3.0, headers=None, data=None):
                return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": "{}"}

            with patch("qa_portal.runtime_scans._http_probe", side_effect=fake_probe):
                findings, artifacts, _logs, metadata = analyze_service_runtime(
                    root,
                    root,
                    ci_context={"target_url": "http://127.0.0.1:9999"},
                )

            self.assertTrue(any(item.title == "OpenAPI description available" for item in findings))
            self.assertGreaterEqual(metadata["source_correlated_paths"], 1)
            self.assertTrue(any(item.filename == "verification_requests.http" for item in artifacts))
            self.assertEqual(metadata["verification_profile"], "passive")
            self.assertEqual(len(metadata["skipped_requests"]), 1)

    def test_service_runtime_safe_active_uses_methods_and_auth(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "paths": {
                            "/health": {"get": {}},
                            "/api/items": {"post": {}},
                        },
                    }
                ),
                encoding="utf-8",
            )

            calls: list[dict[str, object]] = []

            def fake_probe(url, method="GET", timeout=3.0, headers=None, data=None):
                calls.append(
                    {
                        "url": url,
                        "method": method,
                        "headers": headers or {},
                        "data": data.decode("utf-8") if data else "",
                    }
                )
                return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": "{}"}

            with patch("qa_portal.runtime_scans._http_probe", side_effect=fake_probe):
                findings, artifacts, _logs, metadata = analyze_service_runtime(
                    root,
                    root,
                    ci_context={
                        "target_url": "http://127.0.0.1:9999",
                        "service_runtime_profile": "safe-active",
                        "auth_token": "secret-token",
                    },
                )

            methods = {item["method"] for item in calls}
            self.assertIn("GET", methods)
            self.assertIn("POST", methods)
            self.assertTrue(any("Authorization" in item["headers"] for item in calls))
            self.assertTrue(any('"scanforge_probe": true' in item["data"] for item in calls if item["method"] == "POST"))
            self.assertEqual(metadata["verification_profile"], "safe-active")
            self.assertEqual(metadata["auth_mode"], "bearer")
            self.assertFalse(metadata["skipped_requests"])
            self.assertTrue(any(item.filename == "verification_results.json" for item in artifacts))
            self.assertTrue(any(item.title == "Safe active verification profile enabled" for item in findings))
            self.assertTrue(any(item.title == "Authenticated runtime verification enabled" for item in findings))

    def test_service_runtime_deduplicates_documentation_surfaces(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "paths": {
                            "/health": {"get": {}},
                        },
                    }
                ),
                encoding="utf-8",
            )

            def fake_probe(url, method="GET", timeout=3.0, headers=None, data=None):
                if url.endswith("/health"):
                    return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": "{}"}
                if any(url.endswith(item) for item in ("/openapi.json", "/swagger.json", "/swagger", "/docs", "/api-docs")):
                    return {"url": url, "method": method, "status": 200, "content_type": "text/html", "ok": True, "preview": "{}"}
                return {"url": url, "method": method, "status": 404, "content_type": "application/json", "ok": False, "preview": "{}"}

            with patch("qa_portal.runtime_scans._http_probe", side_effect=fake_probe):
                findings, artifacts, _logs, metadata = analyze_service_runtime(
                    root,
                    root,
                    ci_context={"target_url": "http://127.0.0.1:9999"},
                )

            self.assertEqual(metadata["documentation_exposure_count"], 2)
            self.assertEqual(
                metadata["documentation_exposure_paths"],
                ["/openapi.json", "/swagger"],
            )
            self.assertTrue(any(item.filename == "verification_results.json" for item in artifacts))
            self.assertTrue(any(item.title == "OpenAPI or Swagger endpoint exposed without authentication" for item in findings))

    def test_service_runtime_generates_iast_artifacts_and_detects_runtime_security_gaps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "service.py").write_text(
                "\n".join(
                    [
                        "from fastapi import FastAPI",
                        "app = FastAPI()",
                        "",
                        '@app.get("/health")',
                        "def health():",
                        "    return {'ok': True}",
                        "",
                        '@app.post("/admin/items/{item_id}")',
                        "def create_item(item_id: int):",
                        "    return {'id': item_id}",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "security": [{"bearerAuth": []}],
                        "paths": {
                            "/health": {"get": {}},
                            "/admin/items/{item_id}": {
                                "post": {
                                    "security": [{"bearerAuth": []}],
                                    "parameters": [
                                        {"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                                    ],
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            def fake_probe(url, method="GET", timeout=3.0, headers=None, data=None):
                if url.endswith("/health"):
                    return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": "{}"}
                if url.endswith("/admin/items/1") and method == "POST":
                    return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": '{"id":1}'}
                if url.endswith("/openapi.json"):
                    return {"url": url, "method": method, "status": 200, "content_type": "application/json", "ok": True, "preview": "{}"}
                return {"url": url, "method": method, "status": 404, "content_type": "application/json", "ok": False, "preview": "{}"}

            with patch("qa_portal.runtime_scans._http_probe", side_effect=fake_probe):
                findings, artifacts, _logs, metadata = analyze_service_runtime(
                    root,
                    root,
                    ci_context={
                        "target_url": "http://127.0.0.1:9999",
                        "service_runtime_profile": "safe-active",
                    },
                )

            artifact_names = {item.filename for item in artifacts}
            titles = {item.title for item in findings}
            self.assertIn("service_surface.json", artifact_names)
            self.assertIn("verification_requests.http", artifact_names)
            self.assertIn("verification_replay.sh", artifact_names)
            self.assertIn("iast_hints.json", artifact_names)
            self.assertIn("verification_results.json", artifact_names)
            self.assertGreaterEqual(metadata["route_inventory_count"], 2)
            self.assertGreaterEqual(metadata["source_correlated_paths"], 1)
            self.assertEqual(metadata["documentation_exposure_count"], 1)
            self.assertEqual(metadata["unauthenticated_write_count"], 1)
            self.assertEqual(metadata["security_declared_bypass_count"], 2)
            self.assertEqual(metadata["replay_script"], "verification_replay.sh")
            self.assertIn("Route inventory prepared for runtime correlation", titles)
            self.assertIn("IAST-style source correlation produced verified route evidence", titles)
            self.assertIn("OpenAPI or Swagger endpoint exposed without authentication", titles)
            self.assertIn("Mutating endpoints accepted unauthenticated requests", titles)
            self.assertIn("Security-declared API routes responded without supplied authentication", titles)

    def test_vm_runtime_generates_inventory_and_replay_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            build_dir = root / "build"
            build_dir.mkdir()
            binary = build_dir / "demo"
            binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)

            findings, artifacts, _logs, metadata = analyze_vm_runtime(
                root,
                build_dir,
                root,
                functionality_meta={"built": True},
            )

            self.assertTrue(metadata["binary_inventory"])
            self.assertTrue(any(item.filename == "crash_replay.sh" for item in artifacts))
            self.assertTrue(any(item.category == "vm-runtime" for item in findings))

    def test_compliance_profiles_and_release_gate_use_new_artifacts(self):
        report_data = {
            "findings": [
                {
                    "category": "dependency",
                    "severity": "high",
                    "title": "Vulnerable dependency candidate",
                    "description": "demo-lib matched CVE-2026-1000",
                    "path": "package.json",
                    "source": "dependency-sca",
                    "recommendation": "Update the dependency.",
                },
                {
                    "category": "service-runtime",
                    "severity": "medium",
                    "title": "Controlled TLS input verification completed",
                    "description": "Confirmed runtime routes that process input over TLS.",
                    "path": "",
                    "source": "service-runtime",
                    "recommendation": "Replay the verified routes.",
                },
            ],
            "summary": {
                "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
                "risk_score": 68,
            },
            "service_runtime": {
                "frameworks": ["fastapi"],
                "verification_results": [],
            },
            "finding_lifecycle": {
                "new_high_count": 1,
                "new_critical_count": 0,
                "persisting_high_count": 0,
            },
            "dependency_diff": {"new_vulnerable_count": 1},
        }

        compliance = build_compliance_profiles(report_data)
        gate = evaluate_release_gate(report_data)

        self.assertTrue(any(item["matched_rules"] > 0 for item in compliance["profiles"]))
        fstec = compliance["details"]["fstec"]
        self.assertGreaterEqual(fstec["total_rules"], 1)
        self.assertIn(fstec["status"], {"covered", "partial"})
        matched_rule = next(item for item in fstec["rules"] if item["control_id"] == "FSTEC-DEV-SEC-01")
        self.assertGreater(matched_rule["match_count"], 0)
        self.assertTrue(matched_rule["report_sections"])
        self.assertEqual(matched_rule["matches"][0]["report_section"]["key"], "service_runtime")
        self.assertTrue(compliance["profiles"][0]["coverage_percent"] >= 0)
        self.assertEqual(gate["decision"], "block")

    def test_release_gate_detects_baseline_regressions_and_dependency_policy_hits(self):
        policy = dict(DEFAULT_POLICY)
        policy.update(
            {
                "block_on_critical_findings": False,
                "block_on_new_high_findings": False,
                "block_on_new_critical_findings": False,
                "block_on_new_vulnerable_dependencies": False,
                "block_on_new_reachable_vulnerable_dependencies": True,
                "block_on_dependency_baseline_regression": True,
                "review_on_persisting_high_findings": False,
                "review_on_risk_score_regression": True,
                "review_on_net_new_findings": True,
                "review_on_high_severity_regression": True,
                "review_on_risk_score_above": 90,
                "source": "test",
            }
        )
        report_data = {
            "summary": {
                "risk_score": 62,
                "severity_counts": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
            },
            "finding_lifecycle": {
                "new_count": 3,
                "fixed_count": 1,
                "persisting_high_count": 0,
                "new_high_count": 0,
                "new_critical_count": 0,
            },
            "dependencies": {
                "vulnerable_component_count": 2,
                "reachable_vulnerable_component_count": 1,
            },
            "dependency_diff": {
                "new_vulnerable_count": 0,
                "new_reachable_vulnerable_count": 1,
                "dependency_regression_count": 1,
            },
            "baseline_snapshot": {
                "risk_score": 45,
                "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0},
                "vulnerable_component_count": 2,
                "reachable_vulnerable_component_count": 0,
            },
        }

        with patch("qa_portal.release_gate.get_release_gate_policy", return_value=policy):
            gate = evaluate_release_gate(report_data)

        hit_ids = {item["rule_id"] for item in gate["hits"]}
        self.assertEqual(gate["decision"], "block")
        self.assertIn("new-reachable-vulnerable-dependencies", hit_ids)
        self.assertIn("dependency-baseline-regression", hit_ids)
        self.assertIn("risk-score-regression", hit_ids)
        self.assertIn("net-new-findings-regression", hit_ids)
        self.assertIn("high-severity-regression", hit_ids)

    def test_release_gate_does_not_treat_missing_baseline_reference_as_available(self):
        policy = dict(DEFAULT_POLICY)
        policy.update(
            {
                "block_on_critical_findings": False,
                "block_on_new_high_findings": False,
                "block_on_new_critical_findings": False,
                "block_on_new_vulnerable_dependencies": False,
                "block_on_new_reachable_vulnerable_dependencies": False,
                "block_on_dependency_baseline_regression": False,
                "review_on_persisting_high_findings": False,
                "review_on_risk_score_regression": True,
                "review_on_net_new_findings": True,
                "review_on_high_severity_regression": True,
                "review_on_risk_score_above": 95,
                "source": "test",
            }
        )
        report_data = {
            "summary": {
                "risk_score": 44,
                "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            },
            "finding_lifecycle": {
                "new_count": 2,
                "fixed_count": 0,
                "persisting_high_count": 0,
                "new_high_count": 0,
                "new_critical_count": 0,
            },
            "comparison": {
                "baseline_job_id": "missing-baseline",
                "baseline_available": False,
            },
            "dependency_diff": {
                "baseline_available": False,
                "dependency_regression_count": 0,
                "new_reachable_vulnerable_count": 0,
                "new_vulnerable_count": 0,
            },
        }

        with patch("qa_portal.release_gate.get_release_gate_policy", return_value=policy):
            gate = evaluate_release_gate(report_data)

        hit_ids = {item["rule_id"] for item in gate["hits"]}
        self.assertEqual(gate["decision"], "pass")
        self.assertNotIn("net-new-findings-regression", hit_ids)
        self.assertNotIn("risk-score-regression", hit_ids)
        self.assertNotIn("high-severity-regression", hit_ids)

    def test_finding_lifecycle_compares_current_and_baseline(self):
        baseline = [
            Finding(category="security", severity="high", title="Old issue", description="x", path="a.cpp", source="rule"),
            Finding(category="quality", severity="low", title="Removed issue", description="x", path="b.cpp", source="rule"),
        ]
        current = [
            Finding(category="security", severity="high", title="Old issue", description="x", path="a.cpp", source="rule"),
            Finding(category="security", severity="medium", title="New issue", description="x", path="c.cpp", source="rule"),
        ]

        summary = compare_with_baseline(current, baseline)

        self.assertEqual(summary["persisting_count"], 1)
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(summary["fixed_count"], 1)

    def test_fuzzing_generates_artifacts(self):
        files = iter_text_files(FIXTURE_ROOT)
        with tempfile.TemporaryDirectory() as temp_dir:
            findings, artifacts, _ = analyze_fuzzing(
                FIXTURE_ROOT,
                files,
                tools={"afl_fuzz": None, "clangxx": None},
                mode="fuzz_project",
                output_dir=Path(temp_dir),
                duration_seconds=60,
            )
            self.assertGreaterEqual(len(findings), 2)
            self.assertTrue(any(item.filename == "generated_fuzz_harness.cpp" for item in artifacts))
            self.assertTrue((Path(temp_dir) / "generated_fuzz_harness.cpp").exists())

    def test_summary_counts_findings(self):
        files = iter_text_files(FIXTURE_ROOT)
        findings = analyze_security(FIXTURE_ROOT, files)
        summary = summarize_findings(findings)
        self.assertGreater(summary["total_findings"], 0)
        self.assertIn("high", summary["severity_counts"])
        self.assertGreater(summary["risk_score"], 0)
        self.assertTrue(summary["next_actions"])

    def test_presets_catalog_exposes_named_profiles(self):
        presets = {item["key"]: item for item in list_presets()}
        self.assertIn("balanced", presets)
        self.assertIn("deep", presets)
        self.assertTrue(presets["fuzz"]["options"]["run_fuzzing"])

    def test_extract_input_rejects_zip_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            upload = temp_root / "malicious.zip"
            workspace = temp_root / "workspace"
            with zipfile.ZipFile(upload, "w") as archive:
                archive.writestr("../escape.txt", "boom")

            with self.assertRaises(ExtractionError):
                extract_input(upload, workspace)

    def test_pause_and_resume_continue_from_completed_steps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            jobs_dir = temp_root / "jobs"
            uploads_dir = temp_root / "uploads"
            store = JobStore(jobs_dir)
            upload = uploads_dir / "sample_qt_project.zip"
            upload.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(upload, "w") as archive:
                for path in FIXTURE_ROOT.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(FIXTURE_ROOT.parent))

            with patch("qa_portal.app.store", store):
                from qa_portal import app as app_module

                job = app_module.create_job_record(
                    name="Pause pipeline",
                    mode="full_scan",
                    original_name=upload.name,
                    upload_path=upload,
                    options=JobOptions(preset="balanced"),
                )
                store.save(job)
                context = JobContext(store, job.id)
                call_count = {"functionality": 0}

                def pause_after_functionality(*args, **kwargs):
                    call_count["functionality"] += 1
                    store.request_pause(job.id)
                    return [], [], {"configured": False, "built": False, "tests_ran": False}

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=pause_after_functionality):
                    run_job(context)

                paused = store.load(job.id)
                self.assertEqual(paused.status, "paused")
                self.assertEqual(call_count["functionality"], 1)
                self.assertEqual(next(step for step in paused.steps if step.key == "functionality").status, "completed")

                resumed = store.resume_job(job.id)
                self.assertEqual(resumed.status, "queued")

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=AssertionError("should not rerun")):
                    run_job(context)

                completed = store.load(job.id)
                self.assertEqual(completed.status, "completed")
                self.assertTrue(completed.html_report)
                self.assertTrue(completed.pdf_report)
                self.assertTrue(any(artifact.filename == "report.sarif" for artifact in completed.artifacts))
                self.assertTrue((Path(completed.output_dir) / "report.sarif").exists())

    def test_pause_before_reporting_does_not_import_sarif_twice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            jobs_dir = temp_root / "jobs"
            uploads_dir = temp_root / "uploads"
            store = JobStore(jobs_dir)
            upload = uploads_dir / "project.zip"
            upload.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(upload, "w") as archive:
                archive.writestr("project/main.cpp", "int main() { return 0; }\n")
                archive.writestr(
                    "project/external.sarif",
                    json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "External"}}, "results": []}]}),
                )

            with patch("qa_portal.app.store", store):
                from qa_portal import app as app_module
                from qa_portal import pipeline as pipeline_module

                job = app_module.create_job_record(
                    name="Pause before reporting",
                    mode="full_scan",
                    original_name=upload.name,
                    upload_path=upload,
                    options=JobOptions(preset="balanced"),
                )
                store.save(job)
                context = JobContext(store, job.id)
                original_pause = pipeline_module._pause_if_requested

                def pause_after_vm_runtime(current_context):
                    if current_context.is_pause_requested():
                        return original_pause(current_context)
                    current = current_context.get()
                    step_states = {step.key: step.status for step in current.steps}
                    if (
                        step_states.get("vm_runtime") == "completed"
                        and step_states.get("reporting") == "pending"
                        and not current.metadata.get("pause_seeded_before_reporting")
                    ):
                        current_context.set_metadata(
                            {
                                "pause_seeded_before_reporting": True,
                                "pause_requested": True,
                            }
                        )
                        return None
                    return original_pause(current_context)

                with patch("qa_portal.pipeline.analyze_functionality", return_value=([], [], {"configured": False, "built": False, "tests_ran": False})), \
                    patch("qa_portal.pipeline.analyze_security", return_value=[]), \
                    patch("qa_portal.pipeline.analyze_style", return_value=[]), \
                    patch("qa_portal.pipeline.run_clang_tidy", return_value=([], [])), \
                    patch("qa_portal.pipeline.analyze_quality", return_value=[]), \
                    patch("qa_portal.pipeline.run_cppcheck", return_value=([], [])), \
                    patch("qa_portal.pipeline.analyze_dependencies", return_value=([], {})), \
                    patch("qa_portal.pipeline.analyze_service_runtime", return_value=([], [], [], {})), \
                    patch("qa_portal.pipeline.analyze_dynamic", return_value=([], [], [], {"eligible": False})), \
                    patch("qa_portal.pipeline.analyze_vm_runtime", return_value=([], [], [], {})), \
                    patch("qa_portal.pipeline._pause_if_requested", side_effect=pause_after_vm_runtime), \
                    patch("qa_portal.pipeline.import_sarif_tree", return_value=([], {"file_count": 1, "imported_findings": 0, "files": []})) as sarif_import:
                    run_job(context)

                paused = store.load(job.id)
                self.assertEqual(paused.status, "paused")
                self.assertEqual(next(step for step in paused.steps if step.key == "reporting").status, "pending")
                sarif_import.assert_not_called()

    def test_changes_only_retest_limits_file_scoped_checks_to_changed_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            jobs_dir = temp_root / "jobs"
            uploads_dir = temp_root / "uploads"
            store = JobStore(jobs_dir)
            baseline_upload = uploads_dir / "project.zip"
            current_upload = uploads_dir / "project_new.zip"
            uploads_dir.mkdir(parents=True, exist_ok=True)

            baseline_files = {
                "project/src/app.cpp": "int main() { return 0; }\n",
                "project/src/helper.cpp": "int helper() { return 1; }\n",
            }
            current_files = {
                "project/src/app.cpp": "int main() { return 1; }\n",
                "project/src/helper.cpp": "int helper() { return 1; }\n",
            }

            with zipfile.ZipFile(baseline_upload, "w") as archive:
                for relative, content in baseline_files.items():
                    archive.writestr(relative, content)

            with zipfile.ZipFile(current_upload, "w") as archive:
                for relative, content in current_files.items():
                    archive.writestr(relative, content)

            captured: dict[str, object] = {}

            def fake_analyze_functionality(root, project_info, tools, build_dir, plan, changes_only=False, changed_files=None):
                captured["functionality_changes_only"] = changes_only
                captured["functionality_changed_files"] = list(changed_files or [])
                return [], [], {"configured": False, "built": False, "tests_ran": False}

            def fake_analyze_security(root, files, max_workers=1):
                captured["security_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_analyze_style(root, files, max_workers=1):
                captured["style_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_run_clang_tidy(root, build_dir, tools, plan, focus_files=None):
                captured["clang_tidy_files"] = [str(path.relative_to(root)) for path in (focus_files or [])]
                return [], []

            def fake_analyze_quality(root, files, project_info, max_workers=1):
                captured["quality_files"] = [str(path.relative_to(root)) for path in files]
                return []

            def fake_run_cppcheck(root, files, tools, plan):
                captured["cppcheck_files"] = [str(path.relative_to(root)) for path in files]
                return [], []

            def fake_analyze_fuzzing(root, files, tools, mode, output_dir, duration_seconds, plan, focus_files=None):
                captured["fuzzing_files"] = [str(path.relative_to(root)) for path in files]
                captured["fuzzing_focus_files"] = [str(path.relative_to(root)) for path in (focus_files or [])]
                return [], [], []

            with patch("qa_portal.app.store", store):
                from qa_portal import app as app_module

                baseline_job = app_module.create_job_record(
                    name="Baseline",
                    mode="full_scan",
                    original_name="project.zip",
                    upload_path=baseline_upload,
                    options=JobOptions(preset="balanced"),
                )
                store.save(baseline_job)

                options = JobOptions(**asdict(JobOptions(preset="balanced")))
                options.retest_scope = "changes_only"
                options.run_fuzzing = True
                job = app_module.create_job_record(
                    name="Incremental retest",
                    mode="full_scan",
                    original_name="project.zip",
                    upload_path=current_upload,
                    options=options,
                    metadata={
                        "project_key": baseline_job.metadata["project_key"],
                        "repeat_submission": True,
                        "baseline_job_id": baseline_job.id,
                        "baseline_job_name": baseline_job.name,
                        "retest_scope": "changes_only",
                    },
                )
                store.save(job)
                context = JobContext(store, job.id)

                with patch("qa_portal.pipeline.analyze_functionality", side_effect=fake_analyze_functionality), \
                    patch("qa_portal.pipeline.analyze_security", side_effect=fake_analyze_security), \
                    patch("qa_portal.pipeline.analyze_style", side_effect=fake_analyze_style), \
                    patch("qa_portal.pipeline.run_clang_tidy", side_effect=fake_run_clang_tidy), \
                    patch("qa_portal.pipeline.analyze_quality", side_effect=fake_analyze_quality), \
                    patch("qa_portal.pipeline.run_cppcheck", side_effect=fake_run_cppcheck), \
                    patch("qa_portal.pipeline.analyze_fuzzing", side_effect=fake_analyze_fuzzing):
                    run_job(context)

                completed = store.load(job.id)
                self.assertEqual(completed.status, "completed")
                self.assertTrue(completed.metadata["comparison"]["has_changes"])
                self.assertEqual(completed.metadata["comparison"]["changed_files"], ["src/app.cpp"])
                self.assertTrue(captured["functionality_changes_only"])
                self.assertEqual(captured["functionality_changed_files"], ["src/app.cpp"])
                self.assertEqual(captured["security_files"], ["src/app.cpp"])
                self.assertEqual(captured["style_files"], ["src/app.cpp"])
                self.assertEqual(captured["clang_tidy_files"], ["src/app.cpp"])
                self.assertEqual(captured["quality_files"], ["src/app.cpp"])
                self.assertEqual(captured["cppcheck_files"], ["src/app.cpp"])
                self.assertEqual(captured["fuzzing_files"], ["src/app.cpp"])
                self.assertEqual(captured["fuzzing_focus_files"], ["src/app.cpp"])


if __name__ == "__main__":
    unittest.main()
