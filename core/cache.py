"""Tiny JSON file cache so we don't hammer OSV / EPSS / CISA on every run.

Each entry is stored as data/cache/<namespace>_<hash>.json with a timestamp.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"


class Cache:
    def __init__(self, directory=None, enabled: bool = True):
        self.dir = Path(directory) if directory else DEFAULT_DIR
        self.enabled = enabled
        if self.enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.dir / f"{namespace}_{digest}.json"
        
    def get(self, namespace: str, key: str, ttl: Optional[float] = None) -> Optional[Any]:
        """Return cached value, or None on miss. ttl=None means 'any age is fine'."""
        if not self.enabled:
            return None
        path = self._path(namespace, key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if ttl is not None and time.time() - payload.get("ts", 0) > ttl:
            return None
        return payload.get("value")

    def set(self, namespace: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._path(namespace, key)
        tmp = path.with_suffix(".tmp" + str(os.getpid()) + str(id(value)))
        try:
            tmp.write_text(json.dumps({"ts": time.time(), "key": key, "value": value}),
                           encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass
