import ast
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SASTFinding:
    file: str
    line: int
    issue: str
    severity: str
    code_snippet: str
    param: Optional[str] = None  # request param name when identifiable


class SASTAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source = source.splitlines()
        self.findings: List[SASTFinding] = []

    def visit_Call(self, node: ast.Call):
        # Detect insecure hashing: hashlib.md5(), hashlib.sha1()
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in ("md5", "sha1"):
                    self._add(node, f"Insecure hash function used: hashlib.{node.func.attr}", "CRITICAL")

        # Detect plaintext passwords possibly being stored (heuristic: variable named password hashed with no hashing)
        # In practice, check assignments handled in visit_Assign.

        # Detect unsafe SQL construction: cursor.execute with string concatenation or format
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            # check first arg
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                    self._add(node, "SQL query built via string concat/format", "HIGH")
                elif isinstance(arg, ast.JoinedStr):
                    self._add(node, "SQL query built via f-string", "HIGH")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Heuristic: assignment to a name like 'password' from a Name/Str without hashing
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if any("password" in t.lower() for t in targets):
            # If value is a Name or Constant (string), flag as potential plaintext storage
            if isinstance(node.value, (ast.Name, ast.Constant)):
                self._add(node, "Possible plaintext password storage", "HIGH")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Detect reads from request.args['param'] or request.form['param']
        param_name = None
        if isinstance(node.value, ast.Attribute):
            if isinstance(node.value.value, ast.Name) and node.value.value.id == "request":
                if node.value.attr in ("args", "form"):
                    if isinstance(node.slice, ast.Index):
                        idx = node.slice.value
                    else:
                        idx = node.slice
                    if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                        param_name = idx.value
        if param_name:
            # Record info for correlation; not a finding by itself
            self._add(node, f"Request parameter accessed: {param_name}", "INFO", param=param_name)
        self.generic_visit(node)

    def _add(self, node: ast.AST, issue: str, severity: str, param: Optional[str] = None):
        line = getattr(node, "lineno", 1)
        code = self.source[line - 1] if 0 <= line - 1 < len(self.source) else ""
        self.findings.append(
            SASTFinding(
                file=self.filename,
                line=line,
                issue=issue,
                severity=severity,
                code_snippet=code.strip(),
                param=param,
            )
        )


def analyze_python_file(filename: str, source: str) -> List[SASTFinding]:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [
            SASTFinding(
                file=filename,
                line=e.lineno or 1,
                issue=f"Syntax error: {e}",
                severity="INFO",
                code_snippet="",
            )
        ]
    analyzer = SASTAnalyzer(filename, source)
    analyzer.visit(tree)
    return analyzer.findings