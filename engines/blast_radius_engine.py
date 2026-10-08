import ast
import os
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from core.finding import Finding

SKIP_DIRS = {
    ".git", ".hg", ".svn", "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".idea", ".vscode",
}


def _resolve_relative_import(current_file: str, module: Optional[str], level: int) -> str:
    """Resolve a relative import (level >= 1) to a dot-separated module path."""
    cur_parts = Path(current_file).parent.as_posix().split("/")
    if cur_parts == ["."] or cur_parts == [""]:
        cur_parts = []

    if level > 0 and len(cur_parts) >= (level - 1):
        base_parts = cur_parts[:len(cur_parts) - (level - 1)] if (level - 1) > 0 else cur_parts
    else:
        base_parts = cur_parts

    if module:
        base_parts.extend(module.split("."))
    return ".".join([p for p in base_parts if p])


class ASTCallGraphVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, module_to_file: Optional[Dict[str, str]] = None):
        self.file_path = file_path.replace("\\", "/")
        self.module_to_file = module_to_file or {}
        self.current_function: Optional[str] = None
        # Maps qualified caller ("file.py::func") -> set of qualified callee ("target.py::callee")
        self.calls: Dict[str, Set[str]] = {}
        # List of (start_line, end_line, function_name)
        self.functions: List[Tuple[int, int, str]] = []
        self.local_functions: Set[str] = set()
        # Symbol -> (module_name, original_name)
        self.imported_symbols: Dict[str, Tuple[str, str]] = {}
        # Alias -> module_name
        self.imported_modules: Dict[str, str] = {}
        self.file_imports: Set[str] = set()

    def pre_scan_definitions_and_imports(self, tree: ast.AST):
        """First pass: collect all locally defined functions and import mappings."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.local_functions.add(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.file_imports.add(alias.name)
                    as_name = alias.asname or alias.name
                    self.imported_modules[as_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and node.level > 0:
                    mod = _resolve_relative_import(self.file_path, node.module, node.level)
                if mod:
                    self.file_imports.add(mod)
                for alias in node.names:
                    local_symbol = alias.asname or alias.name
                    self.imported_symbols[local_symbol] = (mod, alias.name)
                    # In case of submodule import like from pkg import mod
                    sub_mod = f"{mod}.{alias.name}" if mod else alias.name
                    self.imported_modules[local_symbol] = sub_mod

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
            callee_qualified = self._resolve_callee(node.func)
            if callee_qualified:
                self.calls[self.current_function].add(callee_qualified)
        self.generic_visit(node)

    def _resolve_callee(self, func_node: ast.AST) -> Optional[str]:
        # Case 1: Direct name call, e.g. foo()
        if isinstance(func_node, ast.Name):
            name = func_node.id
            if name in self.imported_symbols:
                mod, orig_name = self.imported_symbols[name]
                target_file = self.module_to_file.get(mod)
                if target_file:
                    return f"{target_file}::{orig_name}"
            elif name in self.local_functions:
                return f"{self.file_path}::{name}"

        # Case 2: Attribute call, e.g. mod.func() or self.func()
        elif isinstance(func_node, ast.Attribute):
            attr = func_node.attr
            if isinstance(func_node.value, ast.Name):
                val_id = func_node.value.id
                if val_id in self.imported_modules:
                    mod = self.imported_modules[val_id]
                    target_file = self.module_to_file.get(mod)
                    if target_file:
                        return f"{target_file}::{attr}"
                elif val_id in ("self", "cls"):
                    if attr in self.local_functions:
                        return f"{self.file_path}::{attr}"

        return None


class _EnclosingFuncVisitor(ast.NodeVisitor):
    def __init__(self, line_no: int):
        self.line_no = line_no
        self.current_class: Optional[str] = None
        self.enclosing: Optional[str] = None
        self.smallest_span: float = float("inf")

    def visit_ClassDef(self, node: ast.ClassDef):
        prev = self.current_class
        self.current_class = f"{prev}.{node.name}" if prev else node.name
        self.generic_visit(node)
        self.current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check(node)

    def _check(self, node: ast.AST):
        start = node.lineno
        end = getattr(node, "end_lineno", node.lineno)
        if start <= self.line_no <= end:
            span = end - start
            if span < self.smallest_span:
                self.smallest_span = span
                self.enclosing = f"{self.current_class}.{node.name}" if self.current_class else node.name
        self.generic_visit(node)


def find_enclosing_function(file_full_path: str, line_number: Optional[int]) -> Optional[str]:
    """Find the function (or Class.method) name enclosing a given line number using AST parsing."""
    if not line_number or not os.path.exists(file_full_path):
        return None

    try:
        with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        tree = ast.parse(content, filename=file_full_path)
    except Exception:
        return None

    visitor = _EnclosingFuncVisitor(line_number)
    visitor.visit(tree)
    return visitor.enclosing


def calculate_blast_radius(findings: List[Finding], repo_path: str) -> Dict[str, int]:
    """
    Calculate function-level transitive call graph blast radius for each finding.
    Returns a dict mapping finding id / index to blast_radius integer.
    """
    repo = Path(repo_path).resolve()

    # Pre-index all python files and build module_to_file mapping
    module_to_file: Dict[str, str] = {}
    ambiguous_modules: Set[str] = set()
    py_files: List[Tuple[str, str]] = []  # (full_path, rel_path)

    for root, dirs, files in os.walk(repo):
        # Prune excluded directories (e.g., .venv, node_modules, .git)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo).replace("\\", "/")
                py_files.append((full_path, rel_path))

                mod_name = rel_path.removesuffix(".py").replace("/", ".")
                module_to_file[mod_name] = rel_path

                # Map bare module name (e.g. "helper" for "utils/helper.py") if unambiguous
                parts = mod_name.split(".")
                base_name = parts[-1]
                if base_name in module_to_file and module_to_file[base_name] != rel_path:
                    ambiguous_modules.add(base_name)
                elif base_name not in ambiguous_modules:
                    module_to_file[base_name] = rel_path

    # Remove ambiguous bare module mappings so they don't produce false links
    for amb in ambiguous_modules:
        if amb in module_to_file and "." not in amb:
            module_to_file.pop(amb, None)

    # Reverse call index: maps callee_qualified ("file.py::func") -> Set[caller_qualified]
    reverse_calls: Dict[str, Set[str]] = {}
    file_imports: Dict[str, Set[str]] = {}

    for full_path, rel_path in py_files:
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=full_path)
            visitor = ASTCallGraphVisitor(rel_path, module_to_file=module_to_file)
            visitor.pre_scan_definitions_and_imports(tree)
            visitor.visit(tree)

            for caller, callees in visitor.calls.items():
                for callee in callees:
                    if callee not in reverse_calls:
                        reverse_calls[callee] = set()
                    reverse_calls[callee].add(caller)

            file_imports[rel_path] = visitor.file_imports
        except Exception:
            continue

    for f in findings:
        if not f.file:
            continue

        norm_file = f.file.replace("\\", "/").removeprefix("./")
        full_file_path = os.path.join(str(repo), norm_file)

        target_func = find_enclosing_function(full_file_path, f.line)
        target_qualified = f"{norm_file}::{target_func}" if target_func else None

        if target_qualified and target_qualified in reverse_calls:
            # Transitive BFS search starting from target_qualified callers
            visited = set()
            queue = list(reverse_calls[target_qualified])

            while queue:
                caller = queue.pop(0)
                if caller not in visited:
                    visited.add(caller)
                    if caller in reverse_calls:
                        for next_caller in reverse_calls[caller]:
                            if next_caller not in visited:
                                queue.append(next_caller)

            f.blast_radius = len(visited)
        else:
            # Fallback: Count how many files import this module
            norm_file_no_ext = norm_file.removesuffix(".py")
            module_name = norm_file_no_ext.replace("/", ".")
            base_name = os.path.basename(norm_file_no_ext)
            importers = 0
            for imp_file, imports in file_imports.items():
                if imp_file != norm_file:
                    if any(module_name == imp or module_name in imp or base_name in imp for imp in imports):
                        importers += 1
            f.blast_radius = importers

    return {id(f): f.blast_radius for f in findings}
