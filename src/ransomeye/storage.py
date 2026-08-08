"""Local SQLite storage for RansomEye cases and evidence."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    host TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    severity TEXT NOT NULL DEFAULT 'SAFE',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    process_name TEXT,
    pid TEXT,
    parent_pid TEXT,
    process_guid TEXT,
    parent_process_guid TEXT,
    parent_image TEXT,
    parent_command_line TEXT,
    command_line TEXT,
    file_path TEXT,
    file_count INTEGER,
    network_json TEXT,
    confidence REAL,
    metadata_json TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence REAL,
    technique TEXT,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    techniques_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_dict(event: Any) -> dict[str, Any]:
    if is_dataclass(event):
        return asdict(event)

    if isinstance(event, dict):
        return event

    raise TypeError("Event must be a dictionary or dataclass object.")


class EvidenceStore:
    """SQLite-backed local evidence store."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA)

        existing_columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(events)")
        }

        for column in (
            "parent_process_guid",
            "parent_image",
            "parent_command_line",
        ):
            if column not in existing_columns:
                self.connection.execute(
                    f"ALTER TABLE events ADD COLUMN {column} TEXT"
                )

        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def create_case(
        self,
        case_id: str,
        case_name: str,
        host: str = "",
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO cases
                (case_id, case_name, host, status, severity, created_at)
            VALUES (?, ?, ?, 'Open', 'SAFE', ?)
            """,
            (case_id, case_name, host, _now()),
        )
        self.connection.commit()

    def save_event(self, case_id: str, event: Any) -> None:
        item = _event_dict(event)

        timestamp = item.get("timestamp")
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()

        self.connection.execute(
            """
            INSERT OR REPLACE INTO events (
                event_id,
                case_id,
                timestamp,
                source,
                event_type,
                process_name,
                pid,
                parent_pid,
                process_guid,
                parent_process_guid,
                parent_image,
                parent_command_line,
                command_line,
                file_path,
                file_count,
                network_json,
                confidence,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.get("event_id"),
                case_id,
                timestamp,
                item.get("source"),
                item.get("event_type"),
                item.get("process_name"),
                str(item.get("pid", "")),
                str(item.get("parent_pid", "")),
                item.get("process_guid"),
                item.get("parent_process_guid"),
                item.get("parent_image"),
                item.get("parent_command_line"),
                item.get("command_line"),
                item.get("file_path"),
                item.get("file_count"),
                json.dumps(item.get("network")),
                item.get("confidence"),
                json.dumps(item.get("metadata")),
            ),
        )
        self.connection.commit()

    def save_finding(self, case_id: str, finding: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO findings (
                case_id,
                finding_type,
                score,
                confidence,
                technique,
                reason,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                finding.get("type", "unknown"),
                finding.get("score", 0),
                finding.get("confidence"),
                finding.get("technique"),
                finding.get("reason", ""),
                _now(),
            ),
        )
        self.connection.commit()

    def save_assessment(
        self,
        case_id: str,
        assessment: dict[str, Any],
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO assessments (
                case_id,
                score,
                severity,
                confidence,
                reasons_json,
                techniques_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                assessment["score"],
                assessment["severity"],
                assessment["confidence"],
                json.dumps(assessment.get("reasons", [])),
                json.dumps(assessment.get("techniques", [])),
                _now(),
            ),
        )

        self.connection.execute(
            """
            UPDATE cases
            SET severity = ?
            WHERE case_id = ?
            """,
            (assessment["severity"], case_id),
        )

        self.connection.commit()

    def get_case_events(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT *
            FROM events
            WHERE case_id = ?
            ORDER BY timestamp ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT *
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        return dict(row) if row else None
