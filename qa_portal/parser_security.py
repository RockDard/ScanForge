from __future__ import annotations

import ast
from dataclasses import dataclass, field
import re


PYTHON_SUFFIXES = {".py"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
SQL_KEYWORDS = re.compile(r"\b(?:select|insert|update|delete|where|from|join)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ParserSecurityFinding:
    severity: str
    title: str
    description: str
    line: int | None
    source: str
    recommendation: str
    confidence: str = "high"
    evidence: str = ""
    trace: list[dict[str, object]] = field(default_factory=list)


@dataclass(frozen=True)
class SecuritySinkModel:
    names: frozenset[str]
    title: str
    severity: str
    recommendation: str


@dataclass(frozen=True)
class PythonFunctionSummary:
    name: str
    params: tuple[str, ...]
    returns_source: tuple[int, str] | None = None
    returns_tainted_param: str | None = None
    returns_sanitized_param: tuple[str, frozenset[str]] | None = None
    param_sinks: tuple[tuple[str, SecuritySinkModel, int, str], ...] = ()


PYTHON_SOURCE_CALLS = frozenset(
    {
        "input",
        "os.getenv",
        "request.get_json",
    }
)
PYTHON_SOURCE_PREFIXES = (
    "sys.argv",
    "os.environ",
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.headers",
    "request.cookies",
)
PYTHON_SANITIZER_CONTEXTS: dict[str, frozenset[str]] = {
    "shlex.quote": frozenset({"shell"}),
    "re.escape": frozenset({"regex"}),
    "html.escape": frozenset({"html"}),
    "markupsafe.escape": frozenset({"html"}),
    "bleach.clean": frozenset({"html"}),
    "urllib.parse.quote": frozenset({"url"}),
    "urllib.parse.quote_plus": frozenset({"url"}),
    "json.dumps": frozenset({"json"}),
    "int": frozenset({"all"}),
    "float": frozenset({"all"}),
}
PYTHON_SANITIZER_CALLS = frozenset(PYTHON_SANITIZER_CONTEXTS)
PYTHON_SHELL_SINK = SecuritySinkModel(
    names=frozenset({"os.system", "subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output"}),
    title="User-controlled data reaches shell execution",
    severity="critical",
    recommendation="Validate input with an allowlist and invoke processes without shell interpretation.",
)
PYTHON_CODE_SINK = SecuritySinkModel(
    names=frozenset({"eval", "exec"}),
    title="User-controlled data reaches dynamic code execution",
    severity="critical",
    recommendation="Do not execute user-controlled text as code; use explicit allowlisted actions.",
)
PYTHON_SQL_SINK = SecuritySinkModel(
    names=frozenset(),
    title="User-controlled data reaches SQL query construction",
    severity="high",
    recommendation="Use parameterized SQL APIs and keep user data out of query text.",
)


def analyze_parser_security(relative: str, content: str, suffix: str) -> list[ParserSecurityFinding]:
    normalized_suffix = suffix.lower()
    if normalized_suffix in PYTHON_SUFFIXES:
        return _analyze_python_ast(content)
    if normalized_suffix in JAVASCRIPT_SUFFIXES:
        return _analyze_javascript_syntax(content)
    return []


def _qualified_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _qualified_name(node.func)
    if isinstance(node, ast.Subscript):
        return _qualified_name(node.value)
    return ""


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _literal_text_fragments(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _literal_text_fragments(node.left) + _literal_text_fragments(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _literal_text_fragments(node.func.value)
    return []


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def _looks_like_sql(node: ast.AST) -> bool:
    return any(SQL_KEYWORDS.search(fragment or "") for fragment in _literal_text_fragments(node))


def _is_true_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


class PythonAstSecurityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[ParserSecurityFinding] = []
        self.seen: set[tuple[str, int | None, str]] = set()
        self.aliases: dict[str, str] = {}
        self.function_summaries: dict[str, PythonFunctionSummary] = {}
        self.tainted: dict[str, tuple[int, str]] = {}
        self.sanitized: dict[str, tuple[int, str, str, frozenset[str], tuple[int, str] | None]] = {}
        self.dynamic_sql: dict[str, tuple[int, str]] = {}

    def analyze(self, tree: ast.AST) -> list[ParserSecurityFinding]:
        self._collect_import_aliases(tree)
        self._collect_function_summaries(tree)
        self.visit(tree)
        return self.findings

    def _collect_import_aliases(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".", 1)[0]
                    self.aliases[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    self.aliases[local_name] = f"{module}.{alias.name}" if module else alias.name

    def _collect_function_summaries(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = tuple(arg.arg for arg in node.args.args)
            param_set = set(params)
            returns_source: tuple[int, str] | None = None
            returns_tainted_param: str | None = None
            returns_sanitized_param: tuple[str, frozenset[str]] | None = None
            param_sinks: list[tuple[str, SecuritySinkModel, int, str]] = []

            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value is not None:
                    sanitized_param = self._sanitized_param_for_expr(child.value, param_set)
                    if sanitized_param:
                        returns_sanitized_param = sanitized_param
                    elif self._is_source_expression(child.value):
                        returns_source = (getattr(child.value, "lineno", getattr(child, "lineno", 0)) or 0, _node_text(child.value))
                    elif returns_source is None:
                        param_name = self._param_used_in_expr(child.value, param_set)
                        if param_name:
                            returns_tainted_param = param_name
                elif isinstance(child, ast.Call):
                    sink_model = self._sink_model_for_call(child)
                    if sink_model is None:
                        continue
                    inspected = child.args[:1] if sink_model is PYTHON_SQL_SINK and child.args else [child]
                    for expression in inspected:
                        param_name = self._param_used_in_expr(expression, param_set)
                        if param_name and not self._sanitized_param_for_expr(expression, {param_name}, context=self._sink_context(sink_model)):
                            param_sinks.append((param_name, sink_model, getattr(child, "lineno", 0) or 0, _node_text(child)))

            self.function_summaries[node.name] = PythonFunctionSummary(
                name=node.name,
                params=params,
                returns_source=returns_source,
                returns_tainted_param=returns_tainted_param,
                returns_sanitized_param=returns_sanitized_param,
                param_sinks=tuple(param_sinks),
            )

    def _resolved_name(self, node: ast.AST | None) -> str:
        raw_name = _qualified_name(node)
        if not raw_name:
            return ""
        head, separator, tail = raw_name.partition(".")
        resolved_head = self.aliases.get(head, head)
        return f"{resolved_head}.{tail}" if separator else resolved_head

    def _is_sanitizer_call(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        call_name = self._resolved_name(node.func).casefold()
        return call_name if call_name in PYTHON_SANITIZER_CALLS else None

    def _sanitizer_contexts(self, sanitizer_name: str) -> frozenset[str]:
        return PYTHON_SANITIZER_CONTEXTS.get(sanitizer_name, frozenset())

    def _sanitizer_covers(self, sanitizer_name: str, context: str | None) -> bool:
        contexts = self._sanitizer_contexts(sanitizer_name)
        return bool(context and ("all" in contexts or context in contexts))

    def _walk_unsanitized(self, node: ast.AST, *, context: str | None = None):
        sanitizer_name = self._is_sanitizer_call(node)
        if sanitizer_name and self._sanitizer_covers(sanitizer_name, context):
            return
        yield node
        for child in ast.iter_child_nodes(node):
            yield from self._walk_unsanitized(child, context=context)

    def _is_source_expression(self, node: ast.AST) -> bool:
        return self._source_for_expr(node) is not None

    def _source_for_expr(self, node: ast.AST, *, context: str | None = None) -> tuple[int, str] | None:
        sanitizer_name = self._is_sanitizer_call(node)
        if sanitizer_name and self._sanitizer_covers(sanitizer_name, context):
            return None
        for child in self._walk_unsanitized(node, context=context):
            if self._is_user_source(child):
                return (getattr(child, "lineno", getattr(node, "lineno", 0)) or 0, _node_text(child))
        return None

    def _param_used_in_expr(self, node: ast.AST, params: set[str]) -> str | None:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in params:
                return child.id
        return None

    def _sanitized_param_for_expr(
        self,
        node: ast.AST,
        params: set[str],
        *,
        context: str | None = None,
    ) -> tuple[str, frozenset[str]] | None:
        sanitizer_name = self._is_sanitizer_call(node)
        if isinstance(node, ast.Call) and sanitizer_name:
            contexts = self._sanitizer_contexts(sanitizer_name)
            if context and not ("all" in contexts or context in contexts):
                return None
            for arg in node.args:
                param_name = self._param_used_in_expr(arg, params)
                if param_name:
                    return param_name, contexts
        return None

    def _sink_context(self, sink_model: SecuritySinkModel) -> str:
        if sink_model is PYTHON_SHELL_SINK:
            return "shell"
        if sink_model is PYTHON_CODE_SINK:
            return "code"
        if sink_model is PYTHON_SQL_SINK:
            return "sql"
        return "generic"

    def _sink_model_for_call(self, node: ast.Call) -> SecuritySinkModel | None:
        call_name = self._resolved_name(node.func).casefold()
        if call_name in PYTHON_CODE_SINK.names:
            return PYTHON_CODE_SINK
        if call_name in PYTHON_SHELL_SINK.names:
            return PYTHON_SHELL_SINK
        if call_name.endswith(".execute") or call_name.endswith(".executemany"):
            return PYTHON_SQL_SINK
        return None

    def emit(
        self,
        *,
        severity: str,
        title: str,
        description: str,
        line: int | None,
        recommendation: str,
        evidence: str = "",
        trace: list[dict[str, object]] | None = None,
    ) -> None:
        key = (title, line, evidence)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append(
            ParserSecurityFinding(
                severity=severity,
                title=title,
                description=description,
                line=line,
                source="parser-security:python-ast",
                recommendation=recommendation,
                evidence=evidence,
                trace=trace or [],
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            self.aliases[local_name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        tainted = self.tainted.copy()
        sanitized = self.sanitized.copy()
        dynamic_sql = self.dynamic_sql.copy()
        try:
            self.generic_visit(node)
        finally:
            self.tainted = tainted
            self.sanitized = sanitized
            self.dynamic_sql = dynamic_sql

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._record_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._record_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolved_name(node.func)
        lower_name = call_name.casefold()
        line = getattr(node, "lineno", None)
        evidence = _node_text(node)

        self._emit_interprocedural_sink_findings(node, call_name, evidence)

        if lower_name == "eval":
            self.emit(
                severity="high",
                title="Python eval execution",
                description="AST analysis found a call to eval().",
                line=line,
                evidence=evidence,
                recommendation="Avoid eval(); map trusted commands to explicit handlers.",
            )
            self._emit_tainted_code_execution(node, evidence)
        elif lower_name == "exec":
            self.emit(
                severity="high",
                title="Python exec execution",
                description="AST analysis found a call to exec().",
                line=line,
                evidence=evidence,
                recommendation="Avoid exec(); use explicit dispatch or a restricted interpreter boundary.",
            )
            self._emit_tainted_code_execution(node, evidence)

        if lower_name in PYTHON_SHELL_SINK.names:
            shell_keyword = next((keyword for keyword in node.keywords if keyword.arg == "shell"), None)
            if shell_keyword and _is_true_constant(shell_keyword.value):
                self.emit(
                    severity="high",
                    title="Python shell=True",
                    description="AST analysis found subprocess execution with shell=True.",
                    line=line,
                    evidence=evidence,
                    recommendation="Invoke processes without shell=True and pass arguments as a list.",
                )
            self._emit_tainted_shell_execution(node, evidence)

        if lower_name.endswith(".execute") or lower_name.endswith(".executemany"):
            self._emit_sql_findings(node, evidence)

        if lower_name in {"pickle.load", "pickle.loads"}:
            self.emit(
                severity="high",
                title="Unsafe pickle deserialization",
                description="AST analysis found pickle deserialization.",
                line=line,
                evidence=evidence,
                recommendation="Do not deserialize untrusted data with pickle.",
            )

        if lower_name == "yaml.load" and not self._yaml_uses_safe_loader(node):
            self.emit(
                severity="high",
                title="Unsafe YAML deserialization",
                description="AST analysis found yaml.load() without SafeLoader.",
                line=line,
                evidence=evidence,
                recommendation="Use yaml.safe_load() or pass SafeLoader explicitly.",
            )

        self.generic_visit(node)

    def _record_assignment(self, targets: list[ast.AST], value: ast.AST) -> None:
        target_names = self._target_names(targets)
        if not target_names:
            return
        value_text = _node_text(value)
        sanitizer_name = self._is_sanitizer_call(value)
        if sanitizer_name:
            original_source = None
            if isinstance(value, ast.Call):
                for arg in value.args:
                    original_source = self._tainted_source(arg)
                    if original_source:
                        break
            for name in target_names:
                self.tainted.pop(name, None)
                self.dynamic_sql.pop(name, None)
                self.sanitized[name] = (
                    getattr(value, "lineno", 0) or 0,
                    value_text,
                    sanitizer_name,
                    self._sanitizer_contexts(sanitizer_name),
                    original_source,
                )
            return
        tainted_source = self._tainted_source(value)
        if tainted_source:
            for name in target_names:
                self.tainted[name] = tainted_source
                self.sanitized.pop(name, None)
        if _looks_like_sql(value) and (_is_dynamic_string(value) or self._expr_uses_tainted(value, context="sql")):
            for name in target_names:
                self.dynamic_sql[name] = (getattr(value, "lineno", 0) or 0, value_text)

    def _target_names(self, targets: list[ast.AST]) -> list[str]:
        names: list[str] = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(self._target_names(list(target.elts)))
        return names

    def _tainted_source(self, node: ast.AST, *, context: str | None = None) -> tuple[int, str] | None:
        sanitizer_name = self._is_sanitizer_call(node)
        if sanitizer_name and self._sanitizer_covers(sanitizer_name, context):
            return None
        if isinstance(node, ast.Name) and node.id in self.sanitized:
            line, text, name, _contexts, original_source = self.sanitized[node.id]
            if self._sanitizer_covers(name, context):
                return None
            return original_source or (line, text)
        if isinstance(node, ast.Call):
            summary_source = self._source_from_function_summary(node, context=context)
            if summary_source:
                return summary_source
        for child in self._walk_unsanitized(node, context=context):
            if self._is_user_source(child):
                return (getattr(child, "lineno", getattr(node, "lineno", 0)) or 0, _node_text(child))
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return self.tainted[child.id]
            if isinstance(child, ast.Name) and child.id in self.sanitized:
                line, text, name, _contexts, original_source = self.sanitized[child.id]
                if self._sanitizer_covers(name, context):
                    continue
                return original_source or (line, text)
            if isinstance(child, ast.Call):
                summary_source = self._source_from_function_summary(child, context=context)
                if summary_source:
                    return summary_source
        return None

    def _expr_uses_tainted(self, node: ast.AST, *, context: str | None = None) -> bool:
        return self._tainted_source(node, context=context) is not None

    def _is_user_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            name = self._resolved_name(node.func).casefold()
            if name in PYTHON_SOURCE_CALLS:
                return True
            if name.startswith("request.") and any(marker in name for marker in (".get", ".getlist")):
                return True
        name = self._resolved_name(node).casefold()
        return any(name == prefix or name.startswith(f"{prefix}.") for prefix in PYTHON_SOURCE_PREFIXES)

    def _trace_for(self, node: ast.Call, *, context: str | None = None) -> list[dict[str, object]]:
        source = self._tainted_source(node, context=context)
        if not source:
            return []
        source_line, source_text = source
        return [
            {"kind": "source", "line": source_line, "evidence": source_text},
            {"kind": "sink", "line": getattr(node, "lineno", None), "evidence": _node_text(node)},
        ]

    def _summary_for_call(self, node: ast.Call) -> PythonFunctionSummary | None:
        call_name = self._resolved_name(node.func)
        return self.function_summaries.get(call_name.rsplit(".", 1)[-1])

    def _source_from_function_summary(self, node: ast.Call, *, context: str | None = None) -> tuple[int, str] | None:
        summary = self._summary_for_call(node)
        if summary is None:
            return None
        if summary.returns_source:
            return summary.returns_source
        if summary.returns_sanitized_param:
            param_name, contexts = summary.returns_sanitized_param
            if context and ("all" in contexts or context in contexts):
                return None
            if not summary.returns_tainted_param:
                try:
                    param_index = summary.params.index(param_name)
                except ValueError:
                    return None
                if param_index >= len(node.args):
                    return None
                return self._tainted_source(node.args[param_index], context=context)
        if not summary.returns_tainted_param:
            return None
        try:
            param_index = summary.params.index(summary.returns_tainted_param)
        except ValueError:
            return None
        if param_index >= len(node.args):
            return None
        return self._tainted_source(node.args[param_index], context=context)

    def _emit_interprocedural_sink_findings(self, node: ast.Call, call_name: str, evidence: str) -> None:
        summary = self.function_summaries.get(call_name.rsplit(".", 1)[-1])
        if summary is None or not summary.param_sinks:
            return
        for param_name, sink_model, sink_line, sink_evidence in summary.param_sinks:
            try:
                param_index = summary.params.index(param_name)
            except ValueError:
                continue
            if param_index >= len(node.args):
                continue
            source = self._tainted_source(node.args[param_index], context=self._sink_context(sink_model))
            if not source:
                continue
            source_line, source_text = source
            self.emit(
                severity=sink_model.severity,
                title=sink_model.title,
                description=(
                    f"Interprocedural AST dataflow found user-controlled data passed into `{summary.name}` "
                    f"and reaching a sensitive sink inside that function."
                ),
                line=getattr(node, "lineno", None),
                evidence=evidence,
                trace=[
                    {"kind": "source", "line": source_line, "evidence": source_text},
                    {"kind": "call", "line": getattr(node, "lineno", None), "evidence": evidence},
                    {"kind": "sink", "line": sink_line, "evidence": sink_evidence},
                ],
                recommendation=sink_model.recommendation,
            )

    def _emit_tainted_code_execution(self, node: ast.Call, evidence: str) -> None:
        if not self._expr_uses_tainted(node, context="code"):
            return
        self.emit(
            severity="critical",
            title="User-controlled data reaches dynamic code execution",
            description="AST dataflow found user-controlled data reaching eval/exec.",
            line=getattr(node, "lineno", None),
            evidence=evidence,
            trace=self._trace_for(node, context="code"),
            recommendation="Do not execute user-controlled text as code; use explicit allowlisted actions.",
        )

    def _emit_tainted_shell_execution(self, node: ast.Call, evidence: str) -> None:
        if not self._expr_uses_tainted(node, context="shell"):
            return
        self.emit(
            severity="critical",
            title="User-controlled data reaches shell execution",
            description="AST dataflow found user-controlled data reaching process execution.",
            line=getattr(node, "lineno", None),
            evidence=evidence,
            trace=self._trace_for(node, context="shell"),
            recommendation="Validate input with an allowlist and invoke processes without shell interpretation.",
        )

    def _emit_sql_findings(self, node: ast.Call, evidence: str) -> None:
        if not node.args:
            return
        query_arg = node.args[0]
        dynamic_sql_source = None
        if _looks_like_sql(query_arg) and _is_dynamic_string(query_arg):
            dynamic_sql_source = (getattr(query_arg, "lineno", getattr(node, "lineno", 0)) or 0, _node_text(query_arg))
        elif isinstance(query_arg, ast.Name) and query_arg.id in self.dynamic_sql:
            dynamic_sql_source = self.dynamic_sql[query_arg.id]

        if dynamic_sql_source:
            self.emit(
                severity="high",
                title="SQL query built with string interpolation",
                description="AST analysis found dynamically constructed SQL passed to an execute call.",
                line=getattr(node, "lineno", None),
                evidence=evidence,
                recommendation="Use parameterized SQL bindings instead of interpolating values into query text.",
            )

        if self._expr_uses_tainted(query_arg, context="sql"):
            self.emit(
                severity="high",
                title="User-controlled data reaches SQL query construction",
                description="AST dataflow found user-controlled data reaching a SQL execution call.",
                line=getattr(node, "lineno", None),
                evidence=evidence,
                trace=self._trace_for(node, context="sql"),
                recommendation="Use parameterized SQL APIs and keep user data out of query text.",
            )

    def _yaml_uses_safe_loader(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg in {"Loader", "loader"} and "SafeLoader" in self._resolved_name(keyword.value):
                return True
        return any("SafeLoader" in self._resolved_name(arg) for arg in node.args[1:])


def _analyze_python_ast(content: str) -> list[ParserSecurityFinding]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = PythonAstSecurityVisitor()
    return visitor.analyze(tree)


def _iter_js_statements(content: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    current: list[str] = []
    line = 1
    start_line = 1
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False

    index = 0
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""

        if line_comment:
            if char == "\n":
                line_comment = False
                line += 1
            index += 1
            continue

        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
                continue
            if char == "\n":
                line += 1
            index += 1
            continue

        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            if char == "\n":
                line += 1
            index += 1
            continue

        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            index += 1
            continue

        current.append(char)
        if char == "\n":
            line += 1
        if char in {";", "}"}:
            statement = "".join(current).strip()
            if statement:
                statements.append((start_line, statement))
            current = []
            start_line = line
        index += 1

    statement = "".join(current).strip()
    if statement:
        statements.append((start_line, statement))
    return statements


JS_ASSIGNMENT = re.compile(
    r"(?:^|[;{\n]\s*)(?:const|let|var)?\s*(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<expr>[^;\n}]+)",
    re.MULTILINE,
)
JS_SOURCE = re.compile(
    r"\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|"
    r"\blocation\.(?:search|hash)\b|\bdocument\.URL\b|\bprocess\.argv\b",
    re.IGNORECASE,
)
JS_EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE)
JS_EXEC = re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\(", re.IGNORECASE)
JS_SQL_CALL = re.compile(r"\.(?:query|execute)\s*\(", re.IGNORECASE)


def _js_line_for(statement_line: int, statement: str, offset: int) -> int:
    return statement_line + statement[:offset].count("\n")


def _js_uses_tainted(expr: str, tainted: dict[str, tuple[int, str]]) -> tuple[int, str] | None:
    for name, source in tainted.items():
        if re.search(rf"\b{re.escape(name)}\b", expr):
            return source
    return None


def _js_is_dynamic_sql(expr: str, tainted: dict[str, tuple[int, str]]) -> bool:
    return bool(SQL_KEYWORDS.search(expr) and ("${" in expr or "+" in expr or _js_uses_tainted(expr, tainted)))


def _analyze_javascript_syntax(content: str) -> list[ParserSecurityFinding]:
    findings: list[ParserSecurityFinding] = []
    seen: set[tuple[str, int, str]] = set()
    tainted: dict[str, tuple[int, str]] = {}
    dynamic_sql: dict[str, tuple[int, str]] = {}

    def emit(
        *,
        severity: str,
        title: str,
        description: str,
        line: int,
        evidence: str,
        recommendation: str,
        trace: list[dict[str, object]] | None = None,
    ) -> None:
        key = (title, line, evidence)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            ParserSecurityFinding(
                severity=severity,
                title=title,
                description=description,
                line=line,
                source="parser-security:javascript-syntax",
                recommendation=recommendation,
                evidence=evidence.strip(),
                trace=trace or [],
            )
        )

    for statement_line, statement in _iter_js_statements(content):
        for match in JS_ASSIGNMENT.finditer(statement):
            variable = match.group("var")
            expression = match.group("expr").strip()
            assignment_line = _js_line_for(statement_line, statement, match.start("expr"))
            if JS_SOURCE.search(expression) or _js_uses_tainted(expression, tainted):
                tainted[variable] = (assignment_line, expression)
            if _js_is_dynamic_sql(expression, tainted):
                dynamic_sql[variable] = (assignment_line, expression)

        for match in JS_EVAL.finditer(statement):
            line = _js_line_for(statement_line, statement, match.start())
            evidence = statement.strip()
            title = "Dynamic Function constructor" if "Function" in match.group(0) else "JavaScript eval execution"
            emit(
                severity="high",
                title=title,
                description="JavaScript syntax analysis found dynamic code execution.",
                line=line,
                evidence=evidence,
                recommendation="Remove dynamic code execution and use explicit allowlisted handlers.",
            )
            source = _js_uses_tainted(statement, tainted)
            if source:
                emit(
                    severity="critical",
                    title="User-controlled data reaches dynamic code execution",
                    description="JavaScript syntax dataflow found user-controlled data reaching dynamic code execution.",
                    line=line,
                    evidence=evidence,
                    trace=[
                        {"kind": "source", "line": source[0], "evidence": source[1]},
                        {"kind": "sink", "line": line, "evidence": evidence},
                    ],
                    recommendation="Do not execute user-controlled text as code.",
                )

        for match in JS_EXEC.finditer(statement):
            line = _js_line_for(statement_line, statement, match.start())
            evidence = statement.strip()
            emit(
                severity="high",
                title="Node child_process exec",
                description="JavaScript syntax analysis found child_process exec usage.",
                line=line,
                evidence=evidence,
                recommendation="Prefer execFile/spawn with explicit argument arrays.",
            )
            source = _js_uses_tainted(statement, tainted)
            if source:
                emit(
                    severity="critical",
                    title="User-controlled data reaches shell execution",
                    description="JavaScript syntax dataflow found user-controlled data reaching process execution.",
                    line=line,
                    evidence=evidence,
                    trace=[
                        {"kind": "source", "line": source[0], "evidence": source[1]},
                        {"kind": "sink", "line": line, "evidence": evidence},
                    ],
                    recommendation="Validate input with an allowlist and avoid shell interpretation.",
                )

        for match in JS_SQL_CALL.finditer(statement):
            line = _js_line_for(statement_line, statement, match.start())
            evidence = statement.strip()
            source = _js_uses_tainted(statement, tainted)
            query_uses_dynamic_sql_var = any(
                re.search(rf"\b{re.escape(name)}\b", statement)
                for name in dynamic_sql
            )
            if _js_is_dynamic_sql(statement, tainted) or query_uses_dynamic_sql_var:
                emit(
                    severity="high",
                    title="SQL query built with string interpolation",
                    description="JavaScript syntax analysis found dynamically constructed SQL.",
                    line=line,
                    evidence=evidence,
                    recommendation="Use parameterized query APIs and pass values separately.",
                )
            if source:
                emit(
                    severity="high",
                    title="User-controlled data reaches SQL query construction",
                    description="JavaScript syntax dataflow found user-controlled data reaching a SQL query call.",
                    line=line,
                    evidence=evidence,
                    trace=[
                        {"kind": "source", "line": source[0], "evidence": source[1]},
                        {"kind": "sink", "line": line, "evidence": evidence},
                    ],
                    recommendation="Use parameterized SQL APIs and keep user data out of query text.",
                )

    return findings
