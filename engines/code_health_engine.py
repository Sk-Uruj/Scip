import ast
import os
from typing import List, Dict, Optional
from core.finding import Finding


class CodeHealthVisitor(ast.NodeVisitor):
    def __init__(self):
        self.max_nesting = 0
        self.bare_excepts = 0
        self.long_functions = 0
        self.current_depth = 0

    def _visit_nested(self, node):
        self.current_depth += 1
        if self.current_depth > self.max_nesting:
            self.max_nesting = self.current_depth
        self.generic_visit(node)
        self.current_depth -= 1

    def visit_If(self, node):
        self._visit_nested(node)

    def visit_For(self, node):
        self._visit_nested(node)

    def visit_While(self, node):
        self._visit_nested(node)

    def visit_Try(self, node):
        self._visit_nested(node)

    def visit_ExceptHandler(self, node):
        if node.type is None:
            self.bare_excepts += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        lines = getattr(node, "end_lineno", node.lineno) - node.lineno
        if lines > 80:
            self.long_functions += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        lines = getattr(node, "end_lineno", node.lineno) - node.lineno
        if lines > 80:
            self.long_functions += 1
        self.generic_visit(node)


def calculate_file_health_penalty(file_path: str) -> float:
    """
    Calculate code health penalty score (0.0 to 1.0) for a file.
    0.0 = Very clean, maintainable code.
    1.0 = High technical debt, large file, high complexity.
    """
    if not os.path.exists(file_path):
        return 0.0

    penalty = 0.0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        loc = len(lines)

        # 1. File Length Penalty (LOC)
        if loc > 1000:
            penalty += 0.5
        elif loc > 600:
            penalty += 0.35
        elif loc > 300:
            penalty += 0.2
        elif loc > 150:
            penalty += 0.1

        # 2. AST Code Complexity & Smells (for Python files)
        if file_path.endswith(".py"):
            try:
                tree = ast.parse("".join(lines), filename=file_path)
                visitor = CodeHealthVisitor()
                visitor.visit(tree)

                # Nesting complexity
                if visitor.max_nesting >= 7:
                    penalty += 0.3
                elif visitor.max_nesting >= 4:
                    penalty += 0.15

                # Bare except clauses
                if visitor.bare_excepts > 0:
                    penalty += min(0.2, visitor.bare_excepts * 0.05)

                # Long functions
                if visitor.long_functions > 0:
                    penalty += min(0.2, visitor.long_functions * 0.05)
            except Exception:
                pass

    except Exception:
        return 0.0

    return round(min(1.0, penalty), 2)


def calculate_code_health_penalties(findings: List[Finding], repo_path: str) -> Dict[str, float]:
    """Calculate and assign code health penalties to findings."""
    file_cache: Dict[str, float] = {}

    for f in findings:
        if not f.file:
            continue

        norm_file = f.file.replace("\\", "/")
        full_path = os.path.join(repo_path, norm_file)

        if norm_file not in file_cache:
            file_cache[norm_file] = calculate_file_health_penalty(full_path)

        f.code_health_penalty = file_cache[norm_file]

    return {id(f): f.code_health_penalty for f in findings}
