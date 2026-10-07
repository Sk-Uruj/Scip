import ast
import os
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from core.finding import Finding


class ASTCallGraphVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.current_function: Optional[str] = None
        # Maps function_name -> set of called function/symbol names
        self.calls: Dict[str, Set[str]] = {}
        # List of (start_line, end_line, function_name)
        self.functions: List[Tuple[int, int, str]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_function
        func_name = f"{self.file_path}::{node.name}"
        self.current_function = func_name
        self.functions.append((node.lineno, getattr(node, 'end_lineno', node.lineno), node.name))
        if func_name not in self.calls:
            self.calls[func_name] = set()
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev_func = self.current_function
        func_name = f"{self.file_path}::{node.name}"
        self.current_function = func_name
        self.functions.append((node.lineno, getattr(node, 'end_lineno', node.lineno), node.name))
        if func_name not in self.calls:
            self.calls[func_name] = set()
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node: ast.Call):
        if self.current_function:
            callee_name = None
            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee_name = node.func.attr
            if callee_name:
                self.calls[self.current_function].add(callee_name)
        self.generic_visit(node)


def find_enclosing_function(file_full_path: str, line_number: Optional[int]) -> Optional[str]:
    """Find the function name enclosing a given line number using AST parsing."""
    if not line_number or not os.path.exists(file_full_path):
        return None

    try:
        with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        tree = ast.parse(content, filename=file_full_path)
    except Exception:
        return None

    enclosing_func = None
    smallest_span = float("inf")

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_line = node.lineno
            end_line = getattr(node, "end_lineno", node.lineno)
            if start_line <= line_number <= end_line:
                span = end_line - start_line
                if span < smallest_span:
                    smallest_span = span
                    enclosing_func = node.name

    return enclosing_func


def calculate_blast_radius(findings: List[Finding], repo_path: str) -> Dict[str, int]:
    """
    Calculate function-level transitive call graph blast radius for each finding.
    Returns a dict mapping finding id / index to blast_radius integer.
    """
    repo = Path(repo_path).resolve()
    
    # Map caller_func -> set of callee symbol names
    # Map callee_symbol_name -> set of caller_funcs (reverse call index)
    reverse_calls: Dict[str, Set[str]] = {}
    file_imports: Dict[str, Set[str]] = {} # file -> set of imported files

    # Scan repo python files
    for root, _, files in os.walk(repo):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo).replace("\\", "/")
                
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    tree = ast.parse(content, filename=full_path)
                    visitor = ASTCallGraphVisitor(rel_path)
                    visitor.visit(tree)

                    for caller, callees in visitor.calls.items():
                        for callee in callees:
                            if callee not in reverse_calls:
                                reverse_calls[callee] = set()
                            reverse_calls[callee].add(caller)

                    # Also collect file imports for fallback
                    file_imports[rel_path] = set()
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                file_imports[rel_path].add(alias.name)
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                file_imports[rel_path].add(node.module)
                except Exception:
                    continue

    results = {}
    for idx, f in enumerate(findings):
        if not f.file:
            continue
            
        norm_file = f.file.replace("\\", "/")
        full_file_path = os.path.join(repo_path, norm_file)
        
        target_func = find_enclosing_function(full_file_path, f.line)
        
        if target_func and target_func in reverse_calls:
            # Transitive BFS search to find all functions calling target_func
            visited = set()
            queue = list(reverse_calls[target_func])
            
            while queue:
                caller = queue.pop(0)
                if caller not in visited:
                    visited.add(caller)
                    # Extract raw function name from "file.py::func_name"
                    raw_func_name = caller.split("::")[-1]
                    if raw_func_name in reverse_calls:
                        for next_caller in reverse_calls[raw_func_name]:
                            if next_caller not in visited:
                                queue.append(next_caller)
            
            f.blast_radius = len(visited)
        else:
            # Fallback: Count how many files import this module
            module_name = norm_file.replace("/", ".").rstrip(".py")
            base_name = os.path.basename(norm_file).replace(".py", "")
            importers = 0
            for imp_file, imports in file_imports.items():
                if imp_file != norm_file:
                    if any(module_name in imp or base_name in imp for imp in imports):
                        importers += 1
            f.blast_radius = importers

    return {id(f): f.blast_radius for f in findings}
