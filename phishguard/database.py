"""
Persistent storage — new in the restructured version.

The original notebook only ever held results in memory for the current
Colab session; nothing survived a restart. This module logs every analysis
to a local SQLite file so the tool accumulates its own history over time —
which domains/senders it's seen before, trends in scores, etc.

SQLite is the right default for a single install (zero setup, one file).
If this becomes a multi-user service, swap this module for a Postgres-backed
version — the function signatures below are written so callers don't need
to change either way.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".phishguard" / "phishguard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzed_at   TEXT NOT NULL,
    filename      TEXT,
    sender        TEXT,
    subject       TEXT,
    score         INTEGER NOT NULL,
    verdict       TEXT NOT NULL,
    ips_json      TEXT,
    keywords_json TEXT,
    reasons_json  TEXT,
    feed_matches_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_analyses_score ON analyses(score);
CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at ON analyses(analyzed_at);
"""


@contextmanager
def _connect(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def save_analysis(result: dict, db_path: Path = DEFAULT_DB_PATH) -> int:
    """
    Persists one analyze_single()-style result dict. Returns the new row id.
    Safe to call repeatedly — each call is one new history row, so re-running
    the same file twice records two data points (useful for tracking re-checks).
    """
    init_db(db_path)
    headers = result.get("headers", {}) or {}
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO analyses
                (analyzed_at, filename, sender, subject, score, verdict,
                 ips_json, keywords_json, reasons_json, feed_matches_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                result.get("file"),
                headers.get("from", result.get("from")),
                headers.get("subject", result.get("subject")),
                result.get("score", 0),
                result.get("verdict", ""),
                json.dumps(result.get("ip_analysis", [])),
                json.dumps(result.get("keyword_findings", {})),
                json.dumps(result.get("reasons", [])),
                json.dumps(result.get("feed_matches", [])),
            ),
        )
        return cur.lastrowid


def get_history(limit: int = 50, db_path: Path = DEFAULT_DB_PATH) -> list:
    """Most recent analyses first."""
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY analyzed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_stats(db_path: Path = DEFAULT_DB_PATH) -> dict:
    """Aggregate stats across everything ever analyzed."""
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*)                                   AS total,
                COALESCE(AVG(score), 0)                    AS avg_score,
                COALESCE(MAX(score), 0)                    AS max_score,
                SUM(CASE WHEN score >= 70 THEN 1 ELSE 0 END) AS high_risk_count
            FROM analyses
            """
        ).fetchone()
        return dict(row)


def find_by_sender(sender_fragment: str, db_path: Path = DEFAULT_DB_PATH) -> list:
    """Look up past analyses from a sender/domain we may have seen before."""
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses WHERE sender LIKE ? ORDER BY analyzed_at DESC",
            (f"%{sender_fragment}%",),
        ).fetchall()
        return [dict(r) for r in rows]
