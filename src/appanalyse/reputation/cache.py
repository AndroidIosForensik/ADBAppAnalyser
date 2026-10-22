"""Persistenter Cache fuer Online-Abfragen (SQLite).

Liegt in ``%LOCALAPPDATA%\\appanalyse`` (Windows) bzw. ``~/.cache/appanalyse``.
Jeder Eintrag hat eine Quelle, einen Schluessel (Paketname oder Hash), einen
JSON-Wert und einen Zeitstempel. Abgelaufene Eintraege gelten als nicht
vorhanden. So bleiben wiederholte Laeufe schnell und schonen die Dienste.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path


def default_cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "appanalyse"
    return Path.home() / ".cache" / "appanalyse"


class Cache:
    def __init__(self, path: Path | None = None):
        self.dir = path or default_cache_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.dir / "cache.db")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS entries ("
            " source TEXT, key TEXT, value TEXT, ts REAL,"
            " PRIMARY KEY (source, key))"
        )
        self.db.commit()

    def get(self, source: str, key: str, max_age: float) -> dict | None:
        row = self.db.execute(
            "SELECT value, ts FROM entries WHERE source=? AND key=?", (source, key)
        ).fetchone()
        if not row:
            return None
        value, ts = row
        if max_age >= 0 and (time.time() - ts) > max_age:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def put(self, source: str, key: str, value: dict) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO entries (source, key, value, ts) VALUES (?,?,?,?)",
            (source, key, json.dumps(value), time.time()),
        )
        self.db.commit()

    def close(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass
