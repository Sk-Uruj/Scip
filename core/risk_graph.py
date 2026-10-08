"""Unified Code & Risk Graph Engine for SCIP.

Implements Roadmap Steps 6 & 7:
  - Models repository structure as a Directed Graph (networkx.DiGraph)
  - Detects external attack-surface entrypoints (FastAPI, Flask, Django, CLI, Celery)
  - Performs automated Reachability Analysis for both code and dependency findings
  - Traces shortest attack paths from entrypoints to vulnerabilities
  - Computes production blast radius excluding unit tests
  - Persists and incrementally loads graph state via SQLiteGraphStore
"""
from __future__ import annotations

import ast
import hashlib
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

import networkx as nx

from core.finding import Finding
from core.graph_store import SQLiteGraphStore
from engines.blast_radius_engine import find_enclosing_function

log = logging.getLogger("scip.risk_graph")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".idea", ".vscode",
}


def is_test_path(path: str) -> bool:
    """Check if a path belongs to test suites."""
    norm = path.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in ("tests", "test", "testing") for p in parts):
        return True
    base = os.path.basename(norm)
    return base.startswith("test_") or base.endswith("_test.py")


def compute_file_sha256(full_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    try:
        with open(full_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


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


class RiskGraphASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, module_to_file: Dict[str, str], graph: nx.DiGraph):
        self.file_path = file_path.replace("\\", "/")
        self.module_to_file = module_to_file
        self.graph = graph
        self.is_test = is_test_path(self.file_path)

        self.module_node_id = f"module::{self.file_path}"
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None

        self.local_functions: Set[str] = set()
        self.imported_symbols: Dict[str, Tuple[str, str]] = {}  # symbol -> (module_or_pkg, orig_name)
        self.imported_modules: Dict[str, str] = {}              # alias -> module_or_pkg

    def pre_scan(self, tree: ast.AST):
        """First pass: collect definitions and import mappings."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.local_functions.add(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    pkg_or_mod = alias.name
                    as_name = alias.asname or alias.name
                    self.imported_modules[as_name] = pkg_or_mod

                    # Add package or module node & edge
                    top_pkg = pkg_or_mod.split(".")[0]
                    if top_pkg not in self.module_to_file:
                        pkg_id = f"pkg::{top_pkg.lower()}"
                        self.graph.add_node(pkg_id, kind="PACKAGE", label=top_pkg, is_test=self.is_test)
                        self.graph.add_edge(self.module_node_id, pkg_id, kind="IMPORTS")
                    else:
                        target_mod_id = f"module::{self.module_to_file[top_pkg]}"
                        self.graph.add_edge(self.module_node_id, target_mod_id, kind="IMPORTS")

            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and node.level > 0:
                    mod = _resolve_relative_import(self.file_path, node.module, node.level)

                top_pkg = mod.split(".")[0] if mod else ""
                if top_pkg and top_pkg not in self.module_to_file:
                    pkg_id = f"pkg::{top_pkg.lower()}"
                    self.graph.add_node(pkg_id, kind="PACKAGE", label=top_pkg, is_test=self.is_test)
                    self.graph.add_edge(self.module_node_id, pkg_id, kind="IMPORTS")

                for alias in node.names:
                    local_symbol = alias.asname or alias.name
                    self.imported_symbols[local_symbol] = (mod, alias.name)
                    sub_mod = f"{mod}.{alias.name}" if mod else alias.name
                    self.imported_modules[local_symbol] = sub_mod

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_class = self.current_class
        self.current_class = node.name

        # Detect Django Class-Based Views (inherits from View, APIView, etc.)
        is_django_view = False
        for base in node.bases:
            b_name = getattr(base, "id", None) or getattr(base, "attr", None)
            if b_name and any(v in str(b_name) for v in ("View", "APIView", "ViewSet", "GenericAPIView")):
                is_django_view = True
                break

        if is_django_view:
            ep_id = f"entrypoint::django::{self.file_path}::{node.name}"
            self.graph.add_node(
                ep_id,
                kind="ENTRYPOINT",
                label=f"Django CBV: {node.name}",
                file=self.file_path,
                line=node.lineno,
                framework="django",
                is_test=self.is_test,
            )

        self.generic_visit(node)
        self.current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_function(node)

    def _process_function(self, node: ast.AST):
        func_base = node.name
        if self.current_class:
            qualified_name = f"{self.current_class}.{func_base}"
        else:
            qualified_name = func_base

        func_id = f"{self.file_path}::{qualified_name}"
        self.graph.add_node(
            func_id,
            kind="FUNCTION",
            label=qualified_name,
            file=self.file_path,
            line=node.lineno,
            is_test=self.is_test,
        )
        self.graph.add_edge(self.module_node_id, func_id, kind="CONTAINS")

        # Detect entrypoint decorators
        self._detect_entrypoint(node, func_id, qualified_name)

        prev_func = self.current_function
        self.current_function = func_id
        self.generic_visit(node)
        self.current_function = prev_func

    def _detect_entrypoint(self, node: ast.AST, func_id: str, qualified_name: str):
        decorators = getattr(node, "decorator_list", [])
        entrypoint_type = None
        route_path = None
        http_method = None

        for dec in decorators:
            dec_str = ""
            # Handle @app.get('/path')
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute):
                    dec_str = f"{getattr(dec.func.value, 'id', '')}.{dec.func.attr}"
                    method_candidate = dec.func.attr.upper()
                    if method_candidate in ("GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE", "API_ROUTE"):
                        http_method = method_candidate
                elif isinstance(dec.func, ast.Name):
                    dec_str = dec.func.id

                # Try extracting route argument
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    route_path = dec.args[0].value
            elif isinstance(dec, ast.Attribute):
                dec_str = f"{getattr(dec.value, 'id', '')}.{dec.attr}"
            elif isinstance(dec, ast.Name):
                dec_str = dec.id

            dec_lower = dec_str.lower()
            if any(k in dec_lower for k in ("app.get", "app.post", "app.put", "app.delete", "app.route", "router.", "bp.route")):
                entrypoint_type = "fastapi_or_flask"
                break
            elif "click.command" in dec_lower or "app.command" in dec_lower:
                entrypoint_type = "cli"
                break
            elif "celery.task" in dec_lower or "shared_task" in dec_lower:
                entrypoint_type = "worker"
                break

        # Also detect Django function view (def foo(request, ...)) in views.py
        if not entrypoint_type and "views" in self.file_path.lower():
            args = getattr(getattr(node, "args", None), "args", [])
            if args and args[0].arg in ("request", "req"):
                entrypoint_type = "django_view"

        if entrypoint_type:
            label = f"{entrypoint_type.upper()}"
            if http_method:
                label += f" {http_method}"
            if route_path:
                label += f" {route_path}"
            else:
                label += f" {qualified_name}"

            ep_id = f"entrypoint::{entrypoint_type}::{self.file_path}::{qualified_name}"
            self.graph.add_node(
                ep_id,
                kind="ENTRYPOINT",
                label=label,
                file=self.file_path,
                line=node.lineno,
                route=route_path,
                method=http_method,
                framework=entrypoint_type,
                is_test=self.is_test,
            )
            self.graph.add_edge(ep_id, func_id, kind="EXPOSES")

    def visit_Call(self, node: ast.Call):
        if self.current_function:
            callee_id = self._resolve_callee(node.func)
            if callee_id:
                self.graph.add_edge(self.current_function, callee_id, kind="CALLS")
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        if self._is_main_check(node):
            self._process_main_block(node)
        self.generic_visit(node)

    def _is_main_check(self, node: ast.If) -> bool:
        if isinstance(node.test, ast.Compare):
            left = node.test.left
            ops = node.test.ops
            comparators = node.test.comparators
            if len(comparators) == 1 and any(isinstance(op, ast.Eq) for op in ops):
                right = comparators[0]
                if isinstance(left, ast.Name) and left.id == "__name__":
                    if isinstance(right, ast.Constant) and right.value == "__main__":
                        return True
                if isinstance(right, ast.Name) and right.id == "__name__":
                    if isinstance(left, ast.Constant) and left.value == "__main__":
                        return True
        return False

    def _process_main_block(self, node: ast.If):
        is_worker = any(w in self.file_path.lower() for w in ("worker", "daemon", "engine", "consumer", "cron"))
        framework = "worker" if is_worker else "cli_script"

        found_callee = False
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                callee_name = None
                if isinstance(stmt.func, ast.Name):
                    callee_name = stmt.func.id
                elif isinstance(stmt.func, ast.Attribute) and isinstance(stmt.func.value, ast.Name):
                    callee_name = f"{stmt.func.value.id}.{stmt.func.attr}"

                if callee_name and not callee_name.startswith(("print", "log", "logging", "sys.", "time.", "os.")):
                    target_func_id = f"{self.file_path}::{callee_name}"
                    ep_id = f"entrypoint::{framework}::{self.file_path}::{callee_name}"
                    label = f"WORKER {self.file_path}::{callee_name}" if is_worker else f"CLI {self.file_path}::{callee_name}"
                    self.graph.add_node(
                        ep_id,
                        kind="ENTRYPOINT",
                        label=label,
                        file=self.file_path,
                        line=node.lineno,
                        framework=framework,
                        is_test=self.is_test,
                    )
                    self.graph.add_edge(ep_id, target_func_id, kind="EXPOSES")
                    found_callee = True

        if not found_callee:
            ep_id = f"entrypoint::{framework}::{self.file_path}::__main__"
            label = f"WORKER {self.file_path}" if is_worker else f"CLI {self.file_path}"
            self.graph.add_node(
                ep_id,
                kind="ENTRYPOINT",
                label=label,
                file=self.file_path,
                line=node.lineno,
                framework=framework,
                is_test=self.is_test,
            )
            self.graph.add_edge(ep_id, self.module_node_id, kind="EXPOSES")

    def _resolve_callee(self, func_node: ast.AST) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            name = func_node.id
            if name in self.imported_symbols:
                mod, orig_name = self.imported_symbols[name]
                if mod in self.module_to_file:
                    target_file = self.module_to_file[mod]
                    return f"{target_file}::{orig_name}"
                else:
                    top_pkg = mod.split(".")[0].lower() if mod else name.lower()
                    return f"pkg::{top_pkg}"
            elif name in self.local_functions:
                return f"{self.file_path}::{name}"

        elif isinstance(func_node, ast.Attribute):
            attr = func_node.attr
            if isinstance(func_node.value, ast.Name):
                val_id = func_node.value.id
                if val_id in self.imported_modules:
                    mod = self.imported_modules[val_id]
                    if mod in self.module_to_file:
                        target_file = self.module_to_file[mod]
                        return f"{target_file}::{attr}"
                    else:
                        top_pkg = mod.split(".")[0].lower()
                        return f"pkg::{top_pkg}"
                elif val_id in ("self", "cls"):
                    if self.current_class:
                        return f"{self.file_path}::{self.current_class}.{attr}"
                    return f"{self.file_path}::{attr}"

        return None


class RiskGraph:
    """Directed graph representing codebase topology, attack surface, and security findings."""

    def __init__(self, repo_path: str, store: Optional[SQLiteGraphStore] = None):
        self.repo_path = Path(repo_path).resolve()
        self.graph = nx.DiGraph()
        self.store = store or SQLiteGraphStore.for_repo(str(self.repo_path))
        self.module_to_file: Dict[str, str] = {}
        self.file_hashes: Dict[str, str] = {}

    def build(self, force_rebuild: bool = False) -> "RiskGraph":
        """Build or load graph from SQLite cache with file-hash validation."""
        # 1. Collect current repo files and SHA-256 hashes
        py_files: List[Tuple[str, str]] = []  # (full_path, rel_path)
        current_hashes: Dict[str, str] = {}

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path).replace("\\", "/")
                    py_files.append((full_path, rel_path))
                    h = compute_file_sha256(full_path)
                    current_hashes[rel_path] = h

                    mod_name = rel_path.removesuffix(".py").replace("/", ".")
                    self.module_to_file[mod_name] = rel_path
                    parts = mod_name.split(".")
                    if parts[-1] not in self.module_to_file:
                        self.module_to_file[parts[-1]] = rel_path

        self.file_hashes = current_hashes

        # 2. Check if cached graph in SQLite is valid
        if not force_rebuild and self.store and self.store.is_cache_valid(current_hashes):
            cached_graph = self.store.load()
            if cached_graph is not None:
                log.info("Loaded Code & Risk Graph from SQLite cache (%d nodes, %d edges)",
                         cached_graph.number_of_nodes(), cached_graph.number_of_edges())
                self.graph = cached_graph
                return self

        # 3. Construct graph from AST
        self.graph.clear()

        # Add Module nodes
        for full_path, rel_path in py_files:
            mod_id = f"module::{rel_path}"
            self.graph.add_node(
                mod_id,
                kind="MODULE",
                label=rel_path,
                file=rel_path,
                is_test=is_test_path(rel_path),
            )

        # Parse ASTs and extract functions, entrypoints, calls, imports
        for full_path, rel_path in py_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content, filename=full_path)
                visitor = RiskGraphASTVisitor(rel_path, self.module_to_file, self.graph)
                visitor.pre_scan(tree)
                visitor.visit(tree)
            except Exception as e:
                log.debug("Error AST parsing %s: %s", rel_path, e)

        # 4. Save constructed graph to SQLite
        if self.store:
            self.store.save(self.graph, current_hashes)

        return self

    def analyze_reachability(self, findings: List[Finding]) -> List[Finding]:
        """Perform graph reachability analysis on findings, assigning reachable, blast_radius, and attack_path."""
        entrypoints = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == "ENTRYPOINT"]
        exposure_rank = {
            "fastapi_or_flask": 4, "django_view": 4, "django": 4,
            "worker": 3, "celery": 3,
            "cli": 2, "cli_script": 2,
        }

        for f in findings:
            if not f.file:
                continue

            norm_file = f.file.replace("\\", "/").lstrip("./")

            # Case A: Dependency finding
            if f.engine == "dependency":
                pkg_name = (f.extra.get("package") or "").lower()
                pkg_node = f"pkg::{pkg_name}"

                if not self.graph.has_node(pkg_node):
                    # Package is in requirements.txt but NEVER imported anywhere in application code
                    f.reachable = False
                    f.exposure = "DEAD"
                    f.blast_radius = 0
                    f.extra["exposure"] = f.exposure
                    f.extra["attack_path"] = []
                    continue

                # Check if any entrypoint can reach pkg_node
                reachable_paths = []
                for ep in entrypoints:
                    if nx.has_path(self.graph, ep, pkg_node):
                        path = nx.shortest_path(self.graph, ep, pkg_node)
                        reachable_paths.append((ep, path))

                if reachable_paths:
                    reachable_paths.sort(key=lambda item: (-exposure_rank.get(self.graph.nodes[item[0]].get("framework", ""), 0), len(item[1])))
                    best_ep, shortest = reachable_paths[0]
                    fw = self.graph.nodes[best_ep].get("framework", "")
                    if fw in ("fastapi_or_flask", "django_view", "django"):
                        f.reachable = True
                        f.exposure = "HTTP"
                    elif fw in ("worker", "celery"):
                        f.reachable = True
                        f.exposure = "WORKER"
                    elif fw in ("cli", "cli_script"):
                        f.reachable = True
                        f.exposure = "CLI"
                    else:
                        f.reachable = True
                        f.exposure = "HTTP"

                    f.extra["exposure"] = f.exposure
                    f.extra["attack_path"] = self._format_path(shortest)
                else:
                    if is_test_path(norm_file):
                        f.reachable = False
                        f.exposure = "TEST"
                    else:
                        f.reachable = False
                        f.exposure = "INTNL"
                    f.extra["exposure"] = f.exposure
                    f.extra["attack_path"] = []

                # Upstream blast radius (modules/functions importing or calling this package)
                ancestors = nx.ancestors(self.graph, pkg_node)
                prod_callers = {a for a in ancestors if not self.graph.nodes[a].get("is_test") and "entrypoint::" not in a}
                f.blast_radius = len(prod_callers)
                continue

            # Case B: Code finding (SAST, Secrets, Crypto)
            full_path = os.path.join(str(self.repo_path), norm_file)
            target_func = find_enclosing_function(full_path, f.line)
            target_node = f"{norm_file}::{target_func}" if target_func else f"module::{norm_file}"

            if not self.graph.has_node(target_node):
                target_node = f"module::{norm_file}"

            if not self.graph.has_node(target_node):
                # Analysis could not determine target node in graph (unresolved AST / file)
                f.reachable = None
                f.exposure = "UNKNOWN"
                f.extra["exposure"] = f.exposure
                f.extra["attack_path"] = []
                continue

            # Calculate production blast radius (ancestors that are non-test functions)
            ancestors = nx.ancestors(self.graph, target_node)
            prod_callers = {
                a for a in ancestors
                if self.graph.nodes[a].get("kind") == "FUNCTION"
                and not self.graph.nodes[a].get("is_test")
            }
            f.blast_radius = len(prod_callers)

            # Check if reachable from ANY entrypoint
            reachable_paths = []
            for ep in entrypoints:
                if nx.has_path(self.graph, ep, target_node):
                    path = nx.shortest_path(self.graph, ep, target_node)
                    reachable_paths.append((ep, path))

            if reachable_paths:
                reachable_paths.sort(key=lambda item: (-exposure_rank.get(self.graph.nodes[item[0]].get("framework", ""), 0), len(item[1])))
                best_ep, shortest = reachable_paths[0]
                fw = self.graph.nodes[best_ep].get("framework", "")
                if fw in ("fastapi_or_flask", "django_view", "django"):
                    f.reachable = True
                    f.exposure = "HTTP"
                elif fw in ("worker", "celery"):
                    f.reachable = True
                    f.exposure = "WORKER"
                elif fw in ("cli", "cli_script"):
                    f.reachable = True
                    f.exposure = "CLI"
                else:
                    f.reachable = True
                    f.exposure = "HTTP"

                f.extra["exposure"] = f.exposure
                f.extra["attack_path"] = self._format_path(shortest)
                f.extra["entrypoints"] = [self.graph.nodes[ep].get("label", ep) for ep, _ in reachable_paths]
            else:
                is_ep = any(self.graph.has_edge(ep, target_node) for ep in entrypoints)
                if is_test_path(norm_file):
                    f.reachable = False
                    f.exposure = "TEST"
                elif len(prod_callers) == 0 and not is_ep:
                    f.reachable = False
                    f.exposure = "DEAD"
                else:
                    # Proven analyzed: internal callers exist, but zero entrypoint ingress paths
                    f.reachable = False
                    f.exposure = "INTNL"

                f.extra["exposure"] = f.exposure
                f.extra["attack_path"] = []

        return findings

    def _format_path(self, path: List[str]) -> List[str]:
        """Format node IDs into clean human-readable path strings with file and line references."""
        formatted = []
        for node_id in path:
            data = self.graph.nodes.get(node_id, {})
            label = data.get("label", node_id)
            kind = data.get("kind", "")
            file_name = data.get("file", "")
            line = data.get("line")
            loc = f" [{file_name}:{line}]" if file_name and line else ""
            if kind == "ENTRYPOINT":
                formatted.append(f"Entrypoint: {label}{loc}")
            elif kind == "PACKAGE":
                formatted.append(f"Package: {label}")
            else:
                formatted.append(f"{label}{loc}")
        return formatted


    def get_statistics(self) -> Dict[str, Any]:
        """Return summary metrics of the code graph."""
        nodes = self.graph.number_of_nodes()
        edges = self.graph.number_of_edges()
        entrypoints = sum(1 for _, d in self.graph.nodes(data=True) if d.get("kind") == "ENTRYPOINT")
        modules = sum(1 for _, d in self.graph.nodes(data=True) if d.get("kind") == "MODULE")
        packages = sum(1 for _, d in self.graph.nodes(data=True) if d.get("kind") == "PACKAGE")
        functions = sum(1 for _, d in self.graph.nodes(data=True) if d.get("kind") == "FUNCTION")
        return {
            "total_nodes": nodes,
            "total_edges": edges,
            "entrypoints": entrypoints,
            "modules": modules,
            "functions": functions,
            "packages": packages,
        }
