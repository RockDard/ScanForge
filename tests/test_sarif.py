import json
import tempfile
import unittest
from pathlib import Path

from qa_portal.models import Finding
from qa_portal.sarif import (
    build_sarif_report,
    import_sarif_tree,
    normalize_finding_path,
    normalize_findings,
    write_sarif_report,
)


class SarifTests(unittest.TestCase):
    def test_import_sarif_tree_normalizes_external_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("eval(input())\n", encoding="utf-8")
            sarif_path = root / "semgrep.sarif"
            sarif_path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "Semgrep",
                                        "rules": [
                                            {
                                                "id": "python.lang.security.audit.eval",
                                                "name": "eval-use",
                                                "shortDescription": {"text": "Python eval execution"},
                                                "help": {"text": "Replace eval with explicit dispatch."},
                                                "helpUri": "https://example.test/rules/eval",
                                            }
                                        ],
                                    }
                                },
                                "results": [
                                    {
                                        "ruleId": "python.lang.security.audit.eval",
                                        "level": "error",
                                        "message": {"text": "User input reaches eval."},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/app.py"},
                                                    "region": {"startLine": 1},
                                                }
                                            }
                                        ],
                                        "properties": {
                                            "scanforgeCategory": "security",
                                            "confidence": "high",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            findings, summary = import_sarif_tree(root)

        self.assertEqual(summary["file_count"], 1)
        self.assertEqual(summary["imported_findings"], 1)
        self.assertEqual(findings[0].category, "security")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].path, "src/app.py")
        self.assertEqual(findings[0].line, 1)
        self.assertEqual(findings[0].source, "sarif:Semgrep")
        self.assertEqual(findings[0].rule_id, "python.lang.security.audit.eval")
        self.assertEqual(findings[0].confidence, "high")
        self.assertTrue(findings[0].fingerprint)
        self.assertEqual(findings[0].references[0]["url"], "https://example.test/rules/eval")

    def test_build_sarif_report_exports_normalized_findings(self):
        finding = Finding(
            category="Security",
            severity="critical",
            title="Command injection",
            description="User input reaches shell execution.",
            path="./api.py",
            line=12,
            source="taint-security-rules",
            recommendation="Use allowlists and avoid shell interpretation.",
            references=[{"id": "CWE-78", "title": "OS Command Injection", "url": "https://cwe.mitre.org/data/definitions/78.html"}],
            confidence="high",
        )

        payload = build_sarif_report([finding], root_uri="file:///repo")
        result = payload["runs"][0]["results"][0]
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "api.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 12)
        self.assertEqual(result["properties"]["scanforgeSeverity"], "critical")
        self.assertEqual(result["properties"]["confidence"], "high")
        self.assertEqual(rule["properties"]["references"][0]["id"], "CWE-78")
        self.assertTrue(result["partialFingerprints"]["scanforgeFingerprint"])

    def test_normalize_findings_and_write_sarif_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "service.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            finding = Finding(
                category="Quality",
                severity="warning",  # type: ignore[arg-type]
                title="Generated warning",
                description="External warning.",
                path=str(source),
                line=0,
                source="external",
                confidence="unknown",
            )

            normalized = normalize_findings([finding], source_root=root)
            sarif_path = root / "report.sarif"
            write_sarif_report(normalized, sarif_path, root_uri=root.as_uri())
            payload = json.loads(sarif_path.read_text(encoding="utf-8"))

        self.assertEqual(normalized[0].severity, "medium")
        self.assertEqual(normalized[0].category, "quality")
        self.assertEqual(normalized[0].path, "service.py")
        self.assertIsNone(normalized[0].line)
        self.assertEqual(normalized[0].confidence, "medium")
        self.assertTrue(normalized[0].rule_id)
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "warning")

    def test_normalize_finding_path_handles_windows_absolute_paths(self):
        source_root = Path("C:/repo")

        self.assertEqual(
            normalize_finding_path("C:\\repo\\src\\app.py", source_root=source_root),
            "src/app.py",
        )
        self.assertEqual(
            normalize_finding_path("/C:/repo/src/app.py", source_root=source_root),
            "src/app.py",
        )
        self.assertEqual(
            normalize_finding_path("file:///C:/repo/src/app.py", source_root=source_root),
            "src/app.py",
        )


if __name__ == "__main__":
    unittest.main()
