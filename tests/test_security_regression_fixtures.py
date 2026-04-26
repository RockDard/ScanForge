import json
import tempfile
import unittest
from pathlib import Path

from qa_portal.analysis import analyze_security, iter_text_files


FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "security_regression_cases.json"


class SecurityRegressionFixtureTests(unittest.TestCase):
    def test_security_regression_fixtures_keep_expected_rule_coverage(self):
        cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["name"]):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    for relative, content in case["files"].items():
                        target = root / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(content, encoding="utf-8")

                    findings = analyze_security(root, iter_text_files(root))

                titles = {item.title for item in findings}
                references = {
                    reference["id"]
                    for item in findings
                    for reference in item.references
                }
                self.assertFalse(set(case["expected_titles"]) - titles)
                self.assertFalse(set(case["expected_references"]) - references)


if __name__ == "__main__":
    unittest.main()
