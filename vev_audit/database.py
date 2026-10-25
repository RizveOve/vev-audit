"""SQLite persistence for scans, scanned pages and findings."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    status          TEXT NOT NULL,               -- queued | running | completed | failed
    options         TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    pages_total     INTEGER NOT NULL DEFAULT 0,
    pages_done      INTEGER NOT NULL DEFAULT 0,
    current_url     TEXT,
    error           TEXT,
    engine          TEXT,
    summary         TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS pages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    final_url       TEXT,
    title           TEXT,
    status_code     INTEGER,
    depth           INTEGER NOT NULL DEFAULT 0,
    load_time_ms    INTEGER,
    error           TEXT,
    scanned_at      TEXT NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    review_count    INTEGER NOT NULL DEFAULT 0,
    passes_count    INTEGER NOT NULL DEFAULT 0,
    screenshot      TEXT,
    legend          TEXT
);
CREATE INDEX IF NOT EXISTS idx_pages_scan ON pages(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    page_id         INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,               -- violation | needs_review
    rule_id         TEXT NOT NULL,
    impact          TEXT,
    help            TEXT NOT NULL,
    description     TEXT NOT NULL,
    help_url        TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',
    wcag            TEXT NOT NULL DEFAULT '[]',
    nodes           TEXT NOT NULL DEFAULT '[]',
    node_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""

JSON_COLUMNS = {"options", "summary", "tags", "wcag", "nodes", "legend"}

# Columns added after the first release; applied to existing databases on startup.
MIGRATIONS = {"pages": {"screenshot": "TEXT", "legend": "TEXT"}}
UPDATABLE_SCAN_COLUMNS = {
    "status",
    "started_at",
    "finished_at",
    "pages_total",
    "pages_done",
    "current_url",
    "error",
    "engine",
    "summary",
}


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for key in JSON_COLUMNS & data.keys():
        if data[key] is not None:
            data[key] = json.loads(data[key])
    return data


class Database:
    """Thread-safe wrapper around a single SQLite connection (WAL mode)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path) if str(path) != ":memory:" else path
        if isinstance(self.path, Path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if str(path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        for table, columns in MIGRATIONS.items():
            existing = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            for name, ddl in columns.items():
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [_row(r) for r in self._conn.execute(sql, params).fetchall()]

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    # -- scans ---------------------------------------------------------------
    def create_scan(self, url: str, options: dict[str, Any]) -> dict[str, Any]:
        scan_id = uuid.uuid4().hex
        self._execute(
            "INSERT INTO scans (id, url, status, options, created_at) VALUES (?, ?, 'queued', ?, ?)",
            (scan_id, url, json.dumps(options), utcnow()),
        )
        return self.get_scan(scan_id)  # type: ignore[return-value]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return rows[0] if rows else None

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?", (limit, offset))

    def count_scans(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        if not fields:
            return
        unknown = fields.keys() - UPDATABLE_SCAN_COLUMNS
        if unknown:
            raise ValueError(f"Cannot update scan columns: {sorted(unknown)}")
        cols, values = [], []
        for key, value in fields.items():
            cols.append(f"{key} = ?")
            values.append(json.dumps(value) if key in JSON_COLUMNS and value is not None else value)
        self._execute(f"UPDATE scans SET {', '.join(cols)} WHERE id = ?", (*values, scan_id))

    def delete_scan(self, scan_id: str) -> bool:
        return self._execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0

    def mark_interrupted_scans(self) -> int:
        """Scans left running by a previous process can never finish; fail them."""
        cur = self._execute(
            "UPDATE scans SET status = 'failed', error = 'Scan interrupted by a server restart.', finished_at = ? "
            "WHERE status IN ('queued', 'running')",
            (utcnow(),),
        )
        return cur.rowcount

    # -- pages & findings ----------------------------------------------------
    def add_page(self, scan_id: str, page: dict[str, Any], findings: list[dict[str, Any]]) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO pages (scan_id, url, final_url, title, status_code, depth, load_time_ms, error,"
                " scanned_at, violation_count, review_count, passes_count, screenshot, legend)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id,
                    page["url"],
                    page.get("final_url"),
                    page.get("title"),
                    page.get("status_code"),
                    page.get("depth", 0),
                    page.get("load_time_ms"),
                    page.get("error"),
                    utcnow(),
                    sum(1 for f in findings if f["kind"] == "violation"),
                    sum(1 for f in findings if f["kind"] == "needs_review"),
                    page.get("passes_count", 0),
                    page.get("screenshot"),
                    json.dumps(page["legend"]) if page.get("legend") is not None else None,
                ),
            )
            page_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (scan_id, page_id, kind, rule_id, impact, help, description, help_url,"
                " tags, wcag, nodes, node_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id,
                        page_id,
                        f["kind"],
                        f["rule_id"],
                        f.get("impact"),
                        f["help"],
                        f["description"],
                        f.get("help_url"),
                        json.dumps(f.get("tags", [])),
                        json.dumps(f.get("wcag", [])),
                        json.dumps(f.get("nodes", [])),
                        f.get("node_count", len(f.get("nodes", []))),
                    )
                    for f in findings
                ],
            )
        return page_id  # type: ignore[return-value]

    def get_pages(self, scan_id: str) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM pages WHERE scan_id = ? ORDER BY id", (scan_id,))

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))
