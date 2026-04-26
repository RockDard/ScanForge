import tempfile
import unittest
from pathlib import Path

from qa_portal.analysis import analyze_security, iter_text_files


class ParserSecurityTests(unittest.TestCase):
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

    def test_python_models_resolve_aliases_and_interprocedural_taint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "handlers.py"
            source.write_text(
                "\n".join(
                    [
                        "import subprocess as sp",
                        "from subprocess import run",
                        "from yaml import load",
                        "from shlex import quote",
                        "",
                        "def get_code(request):",
                        "    return request.args.get('code')",
                        "",
                        "def run_command(value):",
                        "    sp.run(value, shell=True)",
                        "",
                        "def handler(request):",
                        "    code = get_code(request)",
                        "    eval(code)",
                        "    run_command(code)",
                        "    run(code, shell=True)",
                        "    load(request.data)",
                        "    safe = quote(code)",
                        "    sp.run(safe, shell=True)",
                        "    eval(safe)",
                        "    cursor.execute(f\"SELECT * FROM users WHERE name='{safe}'\")",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_security(root, iter_text_files(root))
            parser_findings = [item for item in findings if item.source.startswith("parser-security:")]
            titles = {item.title for item in parser_findings}
            shell_findings = [
                item
                for item in parser_findings
                if item.title == "User-controlled data reaches shell execution"
            ]

        self.assertIn("Python shell=True", titles)
        self.assertIn("Python eval execution", titles)
        self.assertIn("Unsafe YAML deserialization", titles)
        self.assertIn("User-controlled data reaches dynamic code execution", titles)
        self.assertTrue(any(any(step.get("kind") == "call" for step in item.trace) for item in shell_findings))
        self.assertTrue(any(item.line == 16 for item in shell_findings))
        self.assertFalse(any(item.line == 19 for item in shell_findings))
        self.assertTrue(
            any(
                item.line == 20 and item.title == "User-controlled data reaches dynamic code execution"
                for item in parser_findings
            )
        )
        self.assertTrue(
            any(
                item.line == 21 and item.title == "User-controlled data reaches SQL query construction"
                for item in parser_findings
            )
        )

    def test_python_taint_state_does_not_leak_between_functions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "handlers.py"
            source.write_text(
                "\n".join(
                    [
                        "def capture(request):",
                        "    code = request.args.get('code')",
                        "",
                        "def unrelated():",
                        "    eval(code)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            findings = analyze_security(root, iter_text_files(root))
            parser_findings = [item for item in findings if item.source.startswith("parser-security:")]
            titles = {item.title for item in parser_findings}

        self.assertIn("Python eval execution", titles)
        self.assertFalse(
            any(item.title == "User-controlled data reaches dynamic code execution" for item in parser_findings)
        )


if __name__ == "__main__":
    unittest.main()
