from datetime import datetime
import json
import sqlite3
from pathlib import Path
from typing import Any

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
    assessment: dict[str, Any] | None = None,
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

        db_assessment = connection.execute(
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
            SELECT finding_id, finding_type, score, confidence, technique, reason
            FROM findings
            WHERE case_id = ?
            ORDER BY created_at ASC, finding_id ASC
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

        if assessment is None and timeline:
            from ransomeye.threat_assessment import assess_threat

            assessment = assess_threat(timeline)

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

        if assessment is not None:
            lines.extend(
                [
                    f"Score:      {assessment['score']}",
                    f"Severity:   {assessment['severity']}",
                    f"Confidence: {assessment['confidence']}",
                    "Reasons:",
                ]
            )
            reasons_list = assessment.get("reasons", [])
            lines.extend(f"- {reason}" for reason in reasons_list)
            lines.append("Techniques:")
            tech_list = assessment.get("techniques", [])
            lines.extend(f"- {technique}" for technique in tech_list)
        elif db_assessment is None:
            lines.append("No assessment available.")
        else:
            lines.extend(
                [
                    f"Score:      {db_assessment['score']}",
                    f"Severity:   {db_assessment['severity']}",
                    f"Confidence: {db_assessment['confidence']}",
                    "Reasons:",
                ]
            )
            lines.extend(
                f"- {reason}"
                for reason in _json_list(db_assessment["reasons_json"])
            )
            lines.append("Techniques:")
            lines.extend(
                f"- {technique}"
                for technique in _json_list(db_assessment["techniques_json"])
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

        traceability_rows = connection.execute(
            """
            SELECT
                fe.finding_id,
                f.finding_type,
                e.event_id,
                e.timestamp,
                e.source,
                e.event_type,
                e.process_name,
                e.pid,
                e.file_path,
                e.command_line
            FROM finding_evidence fe
            JOIN findings f ON fe.finding_id = f.finding_id
            JOIN events e ON fe.event_id = e.event_id
            WHERE f.case_id = ?
            ORDER BY fe.finding_id ASC, e.timestamp ASC, e.event_id ASC
            """,
            (case_id,),
        ).fetchall()

        lines.extend(["", "EVIDENCE TRACEABILITY", "---------------------"])

        if not traceability_rows:
            lines.append("No evidence links.")
        else:
            findings_by_id: dict[int, list[sqlite3.Row]] = {}
            for row in traceability_rows:
                findings_by_id.setdefault(row["finding_id"], []).append(row)

            for finding_id, rows in findings_by_id.items():
                finding_type = rows[0]["finding_type"]
                lines.append(f"Finding #{finding_id}: {finding_type}")

                seen_event_ids: set[str] = set()
                for row in rows:
                    eid = row["event_id"]
                    if eid in seen_event_ids:
                        continue
                    seen_event_ids.add(eid)

                    lines.extend(
                        [
                            f"  Evidence Event ID: {eid}",
                            f"  Time:              {row['timestamp'] or 'N/A'}",
                            f"  Source:            {row['source'] or 'N/A'}",
                            f"  Event Type:        {row['event_type'] or 'N/A'}",
                            f"  Process:           {row['process_name'] or 'N/A'}",
                            f"  PID:               {row['pid'] or 'N/A'}",
                            "",
                        ]
                    )

        lines.extend(["", "CORRELATIONS", "------------"])

        correlations = (
            assessment.get("correlations", [])
            if isinstance(assessment, dict)
            else []
        )

        if not correlations:
            lines.append("No correlations.")
        else:
            for corr in correlations:
                incident_id = corr.get("incident_id", "N/A")
                process_key = corr.get("process_key", "N/A")
                start_time = corr.get("start_time", "N/A")
                end_time = corr.get("end_time", "N/A")
                duration = corr.get("duration", 0.0)
                ev_ids = corr.get("evidence_event_ids", [])
                events_str = (
                    ", ".join(str(i) for i in ev_ids) if ev_ids else "N/A"
                )

                lines.extend(
                    [
                        f"Incident:    {incident_id}",
                        f"Process Key: {process_key}",
                        f"Start Time:  {start_time}",
                        f"End Time:    {end_time}",
                        f"Duration:    {duration}s",
                        f"Events:      {events_str}",
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

        lines.extend(["", "CHAIN OF CUSTODY", "----------------"])

        custody_rows = connection.execute(
            """
            SELECT artifact_path,
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

        if not custody_rows:
            lines.append("No custody records.")
        else:
            for row in custody_rows:
                verification = "N/A"
                if row["verification_result"] is not None:
                    verification = "Yes" if row["verification_result"] else "FAILED"

                lines.extend(
                    [
                        f"{row['recorded_at']} {row['action']}",
                        f"Artifact: {row['artifact_path']}",
                        f"Action: {row['action']}",
                        f"Analyst: {row['analyst']}",
                        f"SHA-256: {row['sha256']}",
                        f"Note: {row['note'] or 'N/A'}",
                        f"Verification: {verification}",
                        "",
                    ]
                )

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
    assessment: dict[str, Any] | None = None,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        generate_case_report(database_path, case_id, assessment=assessment),
        encoding="utf-8",
    )
    return output
