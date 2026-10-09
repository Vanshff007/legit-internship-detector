"""User feedback on results (FR-8), kept for retraining.

Only the analysis id, the user's label and an optional comment are stored; the
submitted offer is never stored here (NFR-4). Email addresses and phone numbers in
comments are masked before saving.

Storage is SQLite until the PostgreSQL database exists. Set LID_FEEDBACK_DB to
choose the file.
"""

import os
import sqlite3
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path

from app.extractor import EMAIL_RE, PHONE_RE

FEEDBACK_DB_ENV = "LID_FEEDBACK_DB"
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "feedback.sqlite3"
MAX_RECENT = 5000

_lock = threading.Lock()
# analysis_id -> (verdict, score) for recent analyses, so feedback records what the
# user disagreed with. Lost on restart; feedback is still accepted without it.
_recent: OrderedDict[str, tuple[str, int]] = OrderedDict()


def remember(analysis_id: str, verdict: str, score: int) -> None:
    with _lock:
        _recent[analysis_id] = (verdict, score)
        while len(_recent) > MAX_RECENT:
            _recent.popitem(last=False)


def mask_contacts(text: str) -> str:
    return PHONE_RE.sub("[PHONE]", EMAIL_RE.sub("[EMAIL]", text))


def _db_path() -> Path:
    return Path(os.environ.get(FEEDBACK_DB_ENV) or DEFAULT_DB)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            label TEXT NOT NULL,
            comment TEXT,
            verdict TEXT,
            score INTEGER,
            created_at TEXT NOT NULL
        )"""
    )
    return conn


def save(analysis_id: str, label: str, comment: str | None) -> None:
    with _lock:
        verdict, score = _recent.get(analysis_id, (None, None))
        conn = _connect()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO feedback (analysis_id, label, comment, verdict, score, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        analysis_id,
                        label,
                        mask_contacts(comment) if comment else None,
                        verdict,
                        score,
                        datetime.now(UTC).isoformat(timespec="seconds"),
                    ),
                )
        finally:
            conn.close()


def all_rows() -> list[dict[str, object]]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM feedback ORDER BY id")]
    finally:
        conn.close()
