"""SQLite persistence and incremental caching for SCIP Code & Risk Graph."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

import networkx as nx

log = logging.getLogger("scip.graph_store")

DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"


class SQLiteGraphStore:
    """Stores and loads NetworkX graphs in SQLite with SHA-256 file hash validation."""

    def __init__(self, db_path: Optional[Path] = None, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path

    @classmethod
    def for_repo(cls, repo_path: str, cache_dir: Optional[Path] = None) -> "SQLiteGraphStore":
        canonical_path = str(Path(repo_path).resolve())
        repo_hash = hashlib.sha256(canonical_path.encode("utf-8")).hexdigest()[:16]
        c_dir = cache_dir or DEFAULT_CACHE_DIR
        db_path = c_dir / f"graph_{repo_hash}.sqlite"
        return cls(db_path=db_path, cache_dir=c_dir)

    def _init_db(self, conn: sqlite3.Connection):
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_hashes (
                    file_path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    label TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    is_test INTEGER DEFAULT 0,
                    metadata_json TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    metadata_json TEXT,
                    PRIMARY KEY (source_id, target_id, kind)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_kind ON graph_nodes(kind);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id);")

    def get_stored_file_hashes(self) -> Dict[str, str]:
        """Return dict of file_path -> sha256 stored in SQLite."""
        if not self.db_path or not self.db_path.exists():
            return {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                self._init_db(conn)
                cur = conn.cursor()
                cur.execute("SELECT file_path, sha256 FROM file_hashes")
                return dict(cur.fetchall())
        except Exception as e:
            log.debug("Failed reading file_hashes from %s: %s", self.db_path, e)
            return {}

    def is_cache_valid(self, current_file_hashes: Dict[str, str]) -> bool:
        """Check if all current files match the stored hashes without additions or modifications."""
        stored = self.get_stored_file_hashes()
        if not stored:
            return False
        return stored == current_file_hashes

    def save(self, graph: nx.DiGraph, file_hashes: Dict[str, str]) -> None:
        """Persist NetworkX directed graph and file hashes to SQLite."""
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                self._init_db(conn)
                with conn:
                    # Clear previous tables
                    conn.execute("DELETE FROM file_hashes;")
                    conn.execute("DELETE FROM graph_nodes;")
                    conn.execute("DELETE FROM graph_edges;")

                    # Save file hashes
                    conn.executemany(
                        "INSERT INTO file_hashes (file_path, sha256) VALUES (?, ?);",
                        file_hashes.items(),
                    )

                    # Save nodes
                    node_rows = []
                    for node_id, data in graph.nodes(data=True):
                        kind = data.get("kind", "UNKNOWN")
                        label = data.get("label", str(node_id))
                        file_path = data.get("file")
                        line_number = data.get("line")
                        is_test = 1 if data.get("is_test") else 0
                        meta = {k: v for k, v in data.items() if k not in ("kind", "label", "file", "line", "is_test")}
                        node_rows.append((node_id, kind, label, file_path, line_number, is_test, json.dumps(meta)))

                    conn.executemany(
                        "INSERT INTO graph_nodes (node_id, kind, label, file_path, line_number, is_test, metadata_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        node_rows,
                    )

                    # Save edges
                    edge_rows = []
                    for src, tgt, data in graph.edges(data=True):
                        kind = data.get("kind", "CONNECTS")
                        meta = {k: v for k, v in data.items() if k != "kind"}
                        edge_rows.append((src, tgt, kind, json.dumps(meta)))

                    conn.executemany(
                        "INSERT INTO graph_edges (source_id, target_id, kind, metadata_json) VALUES (?, ?, ?, ?);",
                        edge_rows,
                    )
        except Exception as e:
            log.warning("Failed saving graph to SQLite %s: %s", self.db_path, e)

    def load(self) -> Optional[nx.DiGraph]:
        """Load NetworkX directed graph from SQLite."""
        if not self.db_path or not self.db_path.exists():
            return None
        try:
            with sqlite3.connect(self.db_path) as conn:
                self._init_db(conn)
                graph = nx.DiGraph()
                cur = conn.cursor()

                cur.execute("SELECT node_id, kind, label, file_path, line_number, is_test, metadata_json FROM graph_nodes")
                for node_id, kind, label, file_path, line_number, is_test, meta_str in cur.fetchall():
                    attrs = {"kind": kind, "label": label, "is_test": bool(is_test)}
                    if file_path:
                        attrs["file"] = file_path
                    if line_number is not None:
                        attrs["line"] = line_number
                    if meta_str:
                        try:
                            attrs.update(json.loads(meta_str))
                        except Exception:
                            pass
                    graph.add_node(node_id, **attrs)

                cur.execute("SELECT source_id, target_id, kind, metadata_json FROM graph_edges")
                for src, tgt, kind, meta_str in cur.fetchall():
                    attrs = {"kind": kind}
                    if meta_str:
                        try:
                            attrs.update(json.loads(meta_str))
                        except Exception:
                            pass
                    graph.add_edge(src, tgt, **attrs)

                return graph
        except Exception as e:
            log.warning("Failed loading graph from SQLite %s: %s", self.db_path, e)
            return None
