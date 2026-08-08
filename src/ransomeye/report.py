"""Generate analyst-readable RansomEye case reports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ransomeye.storage import EvidenceStore
from ransomeye.timeline import build_process_tree, get_case_timeline


def _json_list(value: str | None) -> list:
    if not value:
        return []
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except json.JSONDecodeError:
        return []


def generate_case_report(
    database_path: str | Path,
    case_id: str,
) -> str:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    try:
        schema_version = connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        case = connection.execute(
            """
            SELECT case_id, case_name, host, status, severity, created_at
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if case is None:
            raise ValueError(f"Case not found: {case_id}")

        assessment = connection.execute(
            """
            SELECT score, severity, confidence, reasons_json, techniques_json
            FROM assessments
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()

        findings = connection.execute(
            """
            SELECT finding_type, score, confidence, technique, reason
            FROM findings
            WHERE case_id = ?
            ORDER BY created_at ASC
            """,
            (case_id,),
        ).fetchall()

        history_rows = connection.execute(
            """
            SELECT old_status, new_status, note, changed_at
            FROM case_history
            WHERE case_id = ?
            ORDER BY changed_at ASC
            """,
            (case_id,),
        ).fetchall()

        timeline = get_case_timeline(database_path, case_id)
        tree = build_process_tree(timeline)

        lines = [
            "RANSOMEYE CASE REPORT",
            "=" * 72,
            "",
            "CASE",
            "----",
            f"Case ID:    {case['case_id']}",
            f"Name:       {case['case_name']}",
            f"Host:       {case['host'] or ''}",
            f"Status:     {case['status'] or ''}",
            f"Severity:   {case['severity'] or ''}",
            f"Schema:     {schema_version}",
            f"Created:    {case['created_at'] or ''}",
            "",
            "ASSESSMENT",
            "----------",
        ]

        if assessment is None:
            lines.append("No assessment available.")
        else:
            lines.extend(
                [
                    f"Score:      {assessment['score']}",
                    f"Severity:   {assessment['severity']}",
                    f"Confidence: {assessment['confidence']}",
                    "Reasons:",
                ]
            )
            lines.extend(
                f"- {reason}"
                for reason in _json_list(assessment["reasons_json"])
            )
            lines.append("Techniques:")
            lines.extend(
                f"- {technique}"
                for technique in _json_list(assessment["techniques_json"])
            )

        lines.extend(["", "FINDINGS", "--------"])

        if not findings:
            lines.append("No findings.")
        else:
            for finding in findings:
                lines.extend(
                    [
                        f"Type:       {finding['finding_type']}",
                        f"Score:      {finding['score']}",
                        f"Confidence: {finding['confidence']}",
                        f"Technique:  {finding['technique'] or ''}",
                        f"Reason:     {finding['reason']}",
                        "",
                    ]
                )

        lines.extend(["Case lifecycle", "--------------"])
        lines.append(f"Current status: {case['status'] or 'OPEN'}")
        lines.append("")

        if not history_rows:
            lines.append("No status changes recorded.")
        else:
            lines.append("History:")
            for row in history_rows:
                note = row["note"] or ""
                status_text = f"{row['old_status'] or '-'} -> {row['new_status']}"
                if note:
                    lines.append(f"{row['changed_at']} {status_text} :: {note}")
                else:
                    lines.append(f"{row['changed_at']} {status_text}")

        lines.extend(["", "TIMELINE", "--------"])

        if not timeline:
            lines.append("No events.")
        else:
            for event in timeline:
                lines.extend(
                    [
                        f"Time:              {event.get('timestamp', '')}",
                        f"Process:           {event.get('process_name', '')}",
                        f"Image:             {event.get('file_path') or 'N/A'}",
                        f"Command line:      {event.get('command_line') or 'N/A'}",
                        f"PID:               {event.get('pid') or 'N/A'}",
                        f"Parent PID:        {event.get('parent_pid') or 'N/A'}",
                        f"Process GUID:      {event.get('process_guid') or 'N/A'}",
                        f"Parent GUID:       {event.get('parent_process_guid') or 'N/A'}",
                        f"Parent image:      {event.get('parent_image') or 'N/A'}",
                        f"Parent command:    {event.get('parent_command_line') or 'N/A'}",
                        "",
                    ]
                )

        lines.extend(["", "PROCESS TREE", "------------"])

        nodes = tree.get("nodes", {})
        children = tree.get("children", {})
        child_ids = {
            child
            for child_list in children.values()
            for child in child_list
        }
        roots = [
            process_id
            for process_id in nodes
            if process_id not in child_ids
        ]

        if not roots:
            lines.append("No process tree available.")
        else:
            def render(process_id: str, prefix: str = "", connector: str = ""):
                node = nodes[process_id]
                name = node.get("process_name") or "[unknown]"
                pid = node.get("pid") or process_id
                lines.append(
                    f"{prefix}{connector}{name} [PID {pid}]"
                )

                if connector == "├── ":
                    child_prefix = prefix + "│   "
                elif connector == "└── ":
                    child_prefix = prefix + "    "
                else:
                    child_prefix = prefix

                child_list = children.get(process_id, [])

                for index, child_id in enumerate(child_list):
                    last = index == len(child_list) - 1
                    render(
                        child_id,
                        child_prefix,
                        "└── " if last else "├── ",
                    )

            for root_id in roots:
                render(root_id)
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    finally:
        connection.close()


def write_case_report(
    database_path: str | Path,
    case_id: str,
    output_path: str | Path,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        generate_case_report(database_path, case_id),
        encoding="utf-8",
    )
    return output
