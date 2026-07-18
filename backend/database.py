"""
RedShell :: Database Module
------------------------------
Simple SQLite persistence layer for scan history, so the dashboard can
show past assessments and the report generator has something to pull
from. No external DB server required — keeps the project "just run it"
simple on Windows.
"""

import sqlite3
import json
import datetime
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "data", "redshell.db")
DB_PATH = os.path.abspath(DB_PATH)


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                result_json TEXT NOT NULL,
                ai_summary_json TEXT
            )
        """)
        conn.commit()


@contextmanager
def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_scan(scan_type: str, target: str, result: dict, ai_summary: dict = None) -> int:
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (scan_type, target, timestamp, result_json, ai_summary_json) VALUES (?, ?, ?, ?, ?)",
            (
                scan_type,
                target,
                datetime.datetime.now().isoformat(),
                json.dumps(result),
                json.dumps(ai_summary) if ai_summary else None,
            ),
        )
        conn.commit()
        return cur.lastrowid


def get_scan_history(limit: int = 50) -> list:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, scan_type, target, timestamp FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["result"] = json.loads(d.pop("result_json"))
        ai_raw = d.pop("ai_summary_json")
        d["ai_summary"] = json.loads(ai_raw) if ai_raw else None
        return d


def delete_scan(scan_id: int):
    with _get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
