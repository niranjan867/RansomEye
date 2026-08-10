"""Local SQLite storage for RansomEye cases and evidence."""

from __future__ import annotations

import json
import os
import sqlite3
import string

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ransomeye.logging import try_write_audit_event



CURRENT_SCHEMA_VERSION = 6

CASE_STATUSES = {"OPEN", "TRIAGED", "CONTAINED", "CLOSED", "REOPENED"}
CUSTODY_ACTIONS = {"created", "verified", "exported", "reviewed"}

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    host TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
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

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (finding_id, event_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding_id
ON finding_evidence(finding_id);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_event_id
ON finding_evidence(event_id);

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    techniques_json TEXT NOT NULL,
    correlations_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS case_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    note TEXT,
    changed_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE INDEX IF NOT EXISTS idx_case_history_case_id
ON case_history(case_id);

CREATE TABLE IF NOT EXISTS case_custody (
    custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('created', 'verified', 'exported', 'reviewed')
    ),
    analyst TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    verification_result INTEGER,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE INDEX IF NOT EXISTS idx_case_custody_case_id
ON case_custody(case_id);

CREATE INDEX IF NOT EXISTS idx_case_custody_artifact
ON case_custody(artifact_path);

CREATE TRIGGER IF NOT EXISTS prevent_custody_update
BEFORE UPDATE ON case_custody
BEGIN
    SELECT RAISE(ABORT, 'case custody records are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_custody_delete
BEFORE DELETE ON case_custody
BEGIN
    SELECT RAISE(ABORT, 'case custody records are append-only');
END;
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
        self._initialize_schema()

    def _get_schema_version(self) -> int:
        row = self.connection.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    def _set_schema_version(self, version: int) -> None:
        self.connection.execute(f"PRAGMA user_version = {version}")
        self.connection.commit()

    def _initialize_schema(self) -> None:
        version = self._get_schema_version()

        if version < 1:
            self._create_base_schema()
            self._set_schema_version(CURRENT_SCHEMA_VERSION)
            version = CURRENT_SCHEMA_VERSION
        elif version == 1:
            self._upgrade_schema_v1_to_v2()
            version = 2

        if version == 2:
            self._upgrade_schema_v2_to_v3()
            version = 3

        if version == 3:
            self._upgrade_schema_v3_to_v4()
            version = 4

        if version == 4:
            self._upgrade_schema_v4_to_v5()
            version = 5

        if version == 5:
            self._upgrade_schema_v5_to_v6()
            version = CURRENT_SCHEMA_VERSION

        if version != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported database schema version: {version}"
            )

    def _create_base_schema(self) -> None:
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def _upgrade_schema_v1_to_v2(self) -> None:
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
        self._set_schema_version(2)

    def _upgrade_schema_v2_to_v3(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS case_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                note TEXT,
                changed_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
            """
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_history_case_id ON case_history(case_id)"
        )
        self.connection.execute(
            "UPDATE cases SET status = 'OPEN' WHERE status IS NULL OR status = '' OR status = 'Open' OR status = 'open'"
        )
        self.connection.commit()
        self._set_schema_version(3)

    def _upgrade_schema_v3_to_v4(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS case_custody (
                custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                action TEXT NOT NULL CHECK (
                    action IN ('created', 'verified', 'exported', 'reviewed')
                ),
                analyst TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                verification_result INTEGER,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
            """)
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_custody_case_id ON case_custody(case_id)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_custody_artifact ON case_custody(artifact_path)"
        )
        self.connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_custody_update
            BEFORE UPDATE ON case_custody
            BEGIN
                SELECT RAISE(ABORT, 'case custody records are append-only');
            END;
            """)
        self.connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_custody_delete
            BEFORE DELETE ON case_custody
            BEGIN
                SELECT RAISE(ABORT, 'case custody records are append-only');
            END;
            """)
        self.connection.commit()
        self._set_schema_version(4)

    def _upgrade_schema_v4_to_v5(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_evidence (
                finding_id INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (finding_id, event_id),
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
                FOREIGN KEY (event_id) REFERENCES events(event_id)
            )
            """
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding_id ON finding_evidence(finding_id)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_evidence_event_id ON finding_evidence(event_id)"
        )
        self.connection.commit()
        self._set_schema_version(5)

    def _upgrade_schema_v5_to_v6(self) -> None:
        existing_columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(assessments)")
        }
        if "correlations_json" not in existing_columns:
            self.connection.execute(
                "ALTER TABLE assessments ADD COLUMN correlations_json TEXT NOT NULL DEFAULT '[]'"
            )
        self.connection.commit()
        self._set_schema_version(6)


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
            VALUES (?, ?, ?, 'OPEN', 'SAFE', ?)
            """,
            (case_id, case_name, host, _now()),
        )
        self.connection.commit()

    def update_case_status(
        self,
        case_id: str,
        status: str,
        note: str = "",
    ) -> None:
        normalized_status = status.upper()
        if normalized_status not in CASE_STATUSES:
            raise ValueError(
                f"Unsupported case status: {status}. Expected one of {sorted(CASE_STATUSES)}"
            )

        case_row = self.connection.execute(
            "SELECT status FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case_row is None:
            raise KeyError(f"Case not found: {case_id}")

        old_status = case_row[0] or "OPEN"

        with self.connection:
            self.connection.execute(
                "UPDATE cases SET status = ? WHERE case_id = ?",
                (normalized_status, case_id),
            )
            self.connection.execute(
                """
                INSERT INTO case_history (
                    case_id,
                    old_status,
                    new_status,
                    note,
                    changed_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (case_id, old_status, normalized_status, note, _now()),
            )

    def get_case_history(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT case_id, old_status, new_status, note, changed_at
            FROM case_history
            WHERE case_id = ?
            ORDER BY changed_at ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    def record_custody_event(
        self,
        case_id: str,
        artifact_path: str,
        sha256: str,
        action: str,
        analyst: str,
        note: str = "",
        verification_result: bool | None = None,
    ) -> None:
        if action not in CUSTODY_ACTIONS:
            raise ValueError("Invalid custody action")

        if not analyst or not analyst.strip():
            raise ValueError("Analyst name must not be empty")

        if not artifact_path or not artifact_path.strip():
            raise ValueError("Artifact path must not be empty")

        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError("Invalid SHA-256 digest")

        if any(c not in string.hexdigits for c in sha256):
            raise ValueError("Invalid SHA-256 digest")

        case_row = self.connection.execute(
            "SELECT case_id FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case_row is None:
            raise KeyError(f"Case not found: {case_id}")

        if verification_result is not None and not isinstance(verification_result, bool):
            raise ValueError("Verification result must be True, False, or None")

        self.connection.execute(
            """
            INSERT INTO case_custody (
                case_id,
                artifact_path,
                sha256,
                action,
                analyst,
                recorded_at,
                note,
                verification_result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                artifact_path,
                sha256.lower(),
                action,
                analyst,
                _now(),
                note or "",
                None if verification_result is None else int(verification_result),
            ),
        )
        self.connection.commit()

    def get_custody_events(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT custody_id,
                   case_id,
                   artifact_path,
                   sha256,
                   action,
                   analyst,
                   recorded_at,
                   note,
                   verification_result
            FROM case_custody
            WHERE case_id = ?
            ORDER BY recorded_at ASC, custody_id ASC
            """,
            (case_id,),
        ).fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            event = dict(row)
            if event["verification_result"] is not None:
                event["verification_result"] = bool(event["verification_result"])
            events.append(event)

        return events

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

    def link_finding_evidence(
        self,
        finding_id: int,
        event_ids: str | Iterable[str],
    ) -> None:
        """Link one or more evidence events to a finding."""
        if isinstance(event_ids, str):
            ids = [event_ids]
        else:
            ids = list(event_ids)

        for event_id in ids:
            if event_id:
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO finding_evidence (finding_id, event_id)
                    VALUES (?, ?)
                    """,
                    (finding_id, event_id),
                )
        self.connection.commit()

    def get_finding_event_ids(self, finding_id: int) -> list[str]:
        """Return all event IDs linked to a finding."""
        rows = self.connection.execute(
            """
            SELECT event_id
            FROM finding_evidence
            WHERE finding_id = ?
            ORDER BY event_id ASC
            """,
            (finding_id,),
        ).fetchall()
        return [row[0] for row in rows]

    def get_finding_events(self, finding_id: int) -> list[dict[str, Any]]:
        """Return full event records linked to a finding."""
        rows = self.connection.execute(
            """
            SELECT e.*
            FROM events e
            JOIN finding_evidence fe ON e.event_id = fe.event_id
            WHERE fe.finding_id = ?
            ORDER BY e.timestamp ASC
            """,
            (finding_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def save_finding(
        self,
        case_id: str,
        finding: dict[str, Any],
        event_ids: str | Iterable[str] | None = None,
    ) -> int:
        cursor = self.connection.execute(
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
        finding_id = cursor.lastrowid

        target_ids: list[str] = []
        if event_ids is not None:
            if isinstance(event_ids, str):
                target_ids.append(event_ids)
            else:
                target_ids.extend(event_ids)
        else:
            fid = finding.get("event_id")
            if fid:
                target_ids.append(str(fid))
            fids = finding.get("event_ids")
            if fids and isinstance(fids, (list, tuple, set)):
                target_ids.extend(str(i) for i in fids)

        if target_ids:
            for eid in target_ids:
                if eid:
                    self.connection.execute(
                        """
                        INSERT OR IGNORE INTO finding_evidence (finding_id, event_id)
                        VALUES (?, ?)
                        """,
                        (finding_id, eid),
                    )

        self.connection.commit()
        return finding_id

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
                correlations_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                assessment["score"],
                assessment["severity"],
                assessment["confidence"],
                json.dumps(assessment.get("reasons", [])),
                json.dumps(assessment.get("techniques", [])),
                json.dumps(assessment.get("correlations", [])),
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

    def get_case_findings(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT finding_id, case_id, finding_type, score, confidence, technique, reason, created_at
            FROM findings
            WHERE case_id = ?
            ORDER BY finding_id ASC
            """,
            (case_id,),
        ).fetchall()

        findings = []
        for row in rows:
            item = dict(row)
            item["event_ids"] = self.get_finding_event_ids(item["finding_id"])
            findings.append(item)
        return findings


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


def check_database_integrity(database_path: Path | str) -> bool:
    database_path = Path(database_path)
    log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")

    if not database_path.is_file():
        try_write_audit_event(
            log_path,
            "database_integrity_check",
            "failure",
            database=str(database_path),
            error=f"Database not found: {database_path}",
        )
        raise FileNotFoundError(
            f"Database not found: {database_path}"
        )

    uri = f"{database_path.resolve().as_uri()}?mode=ro"

    try:
        with sqlite3.connect(uri, uri=True) as connection:
            result = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()
        is_ok = result == ("ok",)
        try_write_audit_event(
            log_path,
            "database_integrity_check",
            "success" if is_ok else "failure",
            database=str(database_path),
        )
        return is_ok
    except sqlite3.Error as exc:
        try_write_audit_event(
            log_path,
            "database_integrity_check",
            "failure",
            database=str(database_path),
            error=str(exc),
        )
        raise sqlite3.DatabaseError(
            f"Database integrity check failed: {exc}"
        ) from exc


def backup_database(
    database_path: Path | str,
    output_path: Path | str,
) -> Path:
    database_path = Path(database_path)
    output_path = Path(output_path)
    log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")

    if not database_path.is_file():
        try_write_audit_event(
            log_path,
            "database_backup",
            "failure",
            database=str(database_path),
            output=str(output_path),
            error=f"Database not found: {database_path}",
        )
        raise FileNotFoundError(
            f"Database not found: {database_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(
            output_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
        os.close(fd)
    except FileExistsError as exc:
        try_write_audit_event(
            log_path,
            "database_backup",
            "rejected",
            database=str(database_path),
            output=str(output_path),
            error=str(exc),
        )
        raise FileExistsError(
            f"Backup destination already exists: {output_path}"
        ) from exc

    try:
        source_uri = f"{database_path.resolve().as_uri()}?mode=ro"

        source = sqlite3.connect(source_uri, uri=True)
        try:
            destination = sqlite3.connect(output_path)
            try:
                source.backup(destination)
            finally:
                destination.close()
        finally:
            source.close()

        if not check_database_integrity(output_path):
            raise sqlite3.DatabaseError(
                f"Backup integrity check failed: {output_path}"
            )

        try_write_audit_event(
            log_path,
            "database_backup",
            "success",
            database=str(database_path),
            output=str(output_path),
        )
        return output_path

    except Exception as exc:
        output_path.unlink(missing_ok=True)
        try_write_audit_event(
            log_path,
            "database_backup",
            "failure",
            database=str(database_path),
            output=str(output_path),
            error=str(exc),
        )
        raise


def restore_database(
    backup_path: Path | str,
    output_path: Path | str,
) -> Path:
    backup_path = Path(backup_path)
    output_path = Path(output_path)
    log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")

    if not backup_path.is_file():
        try_write_audit_event(
            log_path,
            "database_restore",
            "failure",
            backup=str(backup_path),
            output=str(output_path),
            error=f"Backup not found: {backup_path}",
        )
        raise FileNotFoundError(
            f"Backup not found: {backup_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(
            output_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
        os.close(fd)
    except FileExistsError as exc:
        try_write_audit_event(
            log_path,
            "database_restore",
            "rejected",
            backup=str(backup_path),
            output=str(output_path),
            error=str(exc),
        )
        raise FileExistsError(
            f"Restore destination already exists: {output_path}"
        ) from exc

    try:
        source_uri = f"{backup_path.resolve().as_uri()}?mode=ro"

        source = sqlite3.connect(source_uri, uri=True)
        try:
            destination = sqlite3.connect(output_path)
            try:
                source.backup(destination)
            finally:
                destination.close()
        finally:
            source.close()

        if not check_database_integrity(output_path):
            raise sqlite3.DatabaseError(
                f"Restored database integrity check failed: {output_path}"
            )

        try_write_audit_event(
            log_path,
            "database_restore",
            "success",
            backup=str(backup_path),
            output=str(output_path),
        )
        return output_path

    except Exception as exc:
        output_path.unlink(missing_ok=True)
        try_write_audit_event(
            log_path,
            "database_restore",
            "failure",
            backup=str(backup_path),
            output=str(output_path),
            error=str(exc),
        )
        raise
