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
            SELECT *
            FROM events
            WHERE case_id = ?
            ORDER BY timestamp ASC, event_id ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def build_process_tree(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a PID-based process tree from timeline events."""
    nodes: dict[str, dict[str, Any]] = {}
    children: dict[str, list[str]] = {}
    roots: list[str] = []

    for event in events:
        pid = event.get("pid")
        if pid is None:
            continue

        pid = str(pid)

        nodes[pid] = {
            "pid": pid,
            "process_name": event.get("process_name") or "",
            "parent_pid": (
                str(event["parent_pid"])
                if event.get("parent_pid") is not None
                else None
            ),
            "timestamp": event.get("timestamp") or "",
            "command_line": event.get("command_line") or "",
        }

    for pid, node in nodes.items():
        parent_pid = node["parent_pid"]

        if parent_pid and parent_pid in nodes:
            children.setdefault(parent_pid, []).append(pid)
        else:
            roots.append(pid)

    return {
        "nodes": nodes,
        "children": children,
        "roots": roots,
    }
