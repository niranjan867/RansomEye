"""Timeline and process-tree reconstruction from stored case events."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def get_case_timeline(
    database_path: str | Path,
    case_id: str,
) -> list[dict[str, Any]]:
    """Return stored case events sorted by timestamp for analyst review."""
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
            """
            SELECT
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
                confidence
            FROM events
            WHERE case_id = ?
            ORDER BY timestamp ASC, event_id ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def build_process_tree(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Build a parent-child process tree keyed by parent process GUID."""
    tree: dict[str, list[str]] = {}

    for event in events:
        parent_guid = event.get("parent_process_guid")
        child_guid = event.get("process_guid")

        if not child_guid:
            continue

        if parent_guid:
            tree.setdefault(parent_guid, []).append(child_guid)
        else:
            tree.setdefault("root", []).append(child_guid)

    return tree
