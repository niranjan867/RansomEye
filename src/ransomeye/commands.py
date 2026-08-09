"""Command-line helpers for inspecting stored RansomEye cases."""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path



from ransomeye.integrity import sha256_file, verify_manifest
from ransomeye.report import write_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import (
    build_process_tree,
    get_case_timeline,
)


def print_case_timeline(database_path: str | Path, case_id: str) -> None:
    """Print a simple analyst-friendly timeline for a stored case."""
    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        print(f"Case: {case['case_id']}")
        print(f"Host: {case.get('host', '')}")
        print()
        print("Time                  Process             Parent")

        timeline = get_case_timeline(database_path, case_id)

        process_names_by_pid = {
            str(entry.get("pid")): str(entry.get("process_name") or "")
            for entry in timeline
            if entry.get("pid") is not None
        }

        for entry in timeline:
            timestamp = str(entry.get("timestamp", ""))

            if timestamp and "T" in timestamp:
                timestamp = timestamp.replace("T", " ")
                if "." in timestamp:
                    timestamp = timestamp.split(".")[0]
                if timestamp.endswith("Z"):
                    timestamp = timestamp[:-1]

            process_name = str(entry.get("process_name") or "")
            parent_name = ""

            if entry.get("parent_image"):
                parent_name = str(entry["parent_image"]).split("\\")[-1]
            elif entry.get("parent_pid") is not None:
                parent_pid_text = str(entry["parent_pid"])
                parent_name = process_names_by_pid.get(
                    parent_pid_text,
                    f"PID {parent_pid_text}",
                )
            else:
                parent_name = ""

            print(f"{timestamp:<20} {process_name:<18} {parent_name}")
    finally:
        store.close()


def print_case_tree(database_path: str | Path, case_id: str) -> None:
    """Print a process tree for a stored case."""
    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        timeline = get_case_timeline(database_path, case_id)
        tree = build_process_tree(timeline)

        print(f"Case: {case['case_id']}")
        print(f"Host: {case.get('host', '')}")
        print()

        nodes = tree.get("nodes", {})
        children = tree.get("children", {})

        child_ids = {
            child_id
            for child_list in children.values()
            for child_id in child_list
        }

        roots = [
            process_id
            for process_id in nodes
            if process_id not in child_ids
        ]

        def render(
            process_id: str,
            prefix: str = "",
            connector: str = "",
        ) -> None:
            node = nodes[process_id]
            name = node.get("process_name") or "[unknown]"
            pid = node.get("pid") or process_id

            print(f"{prefix}{connector}{name} [PID {pid}]")

            child_list = children.get(process_id, [])

            if connector == "├── ":
                child_prefix = prefix + "│   "
            elif connector == "└── ":
                child_prefix = prefix + "    "
            else:
                child_prefix = prefix

            for index, child_id in enumerate(child_list):
                last = index == len(child_list) - 1
                branch = "└── " if last else "├── "

                render(
                    child_id,
                    prefix=child_prefix,
                    connector=branch,
                )

        for root_id in roots:
            render(root_id)
            print()
    finally:
        store.close()


def show_case_status(database_path: str | Path, case_id: str) -> None:
    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        print(f"Case: {case['case_id']}")
        print(f"Status: {case.get('status', 'OPEN')}")
    finally:
        store.close()


def update_case_status(
    database_path: str | Path,
    case_id: str,
    status: str,
    note: str = "",
) -> None:
    store = EvidenceStore(database_path)

    try:
        store.update_case_status(case_id, status, note=note)
        print(f"Updated case {case_id} to {status.upper()}")
    finally:
        store.close()


def print_case_history(database_path: str | Path, case_id: str) -> None:
    store = EvidenceStore(database_path)

    try:
        history = store.get_case_history(case_id)
        if not history:
            print(f"No history found for case {case_id}")
            return

        print(f"Case history: {case_id}")
        for entry in history:
            note = entry.get("note") or ""
            print(
                f"{entry['changed_at']} {entry['old_status'] or '-'} -> {entry['new_status']}"
                + (f" :: {note}" if note else "")
            )
    finally:
        store.close()


def write_integrity_manifest(input_path: str | Path, output_path: str | Path) -> Path:
    input_file = Path(input_path)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    digest = sha256_file(input_file)
    output_file.write_text(
        f"SHA256  {input_file.name}\n{digest}\n",
        encoding="utf-8",
    )
    return output_file


def verify_integrity_manifest(artifact_path: str | Path, manifest_path: str | Path) -> bool:
    return verify_manifest(Path(artifact_path), Path(manifest_path))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ransomeye",
        description="Inspect stored RansomEye cases.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    timeline_parser = subparsers.add_parser(
        "timeline",
        help="Print a case timeline.",
    )
    timeline_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    timeline_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    tree_parser = subparsers.add_parser(
        "tree",
        help="Print a process tree.",
    )
    tree_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    tree_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Write a case report to disk.",
    )
    report_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    report_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    report_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write the report text file.",
    )

    case_parser = subparsers.add_parser(
        "case",
        help="Manage case lifecycle state.",
    )
    case_subparsers = case_parser.add_subparsers(dest="case_command", required=True)

    case_status_parser = case_subparsers.add_parser(
        "status",
        help="Show the current case status.",
    )
    case_status_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_status_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    case_update_parser = case_subparsers.add_parser(
        "update",
        help="Update the case status and record a note.",
    )
    case_update_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_update_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    case_update_parser.add_argument(
        "--status",
        required=True,
        help="New case status.",
    )
    case_update_parser.add_argument(
        "--note",
        default="",
        help="Analyst note to record with the status change.",
    )

    case_history_parser = case_subparsers.add_parser(
        "history",
        help="Show the lifecycle history for a case.",
    )
    case_history_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_history_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    custody_parser = subparsers.add_parser(
        "custody",
        help="Record or inspect case chain-of-custody events.",
    )
    custody_subparsers = custody_parser.add_subparsers(dest="custody_command", required=True)

    custody_record_parser = custody_subparsers.add_parser(
        "record",
        help="Record a custody event for a case.",
    )
    custody_record_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    custody_record_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    custody_record_parser.add_argument(
        "--artifact",
        required=True,
        dest="artifact_path",
        help="Path to the artifact within the case.",
    )
    custody_record_parser.add_argument(
        "--hash",
        required=True,
        dest="sha256",
        help="SHA-256 digest of the artifact.",
    )
    custody_record_parser.add_argument(
        "--action",
        required=True,
        help="Custody action: created, verified, exported, reviewed.",
    )
    custody_record_parser.add_argument(
        "--analyst",
        required=True,
        help="Analyst name or email recording the event.",
    )
    custody_record_parser.add_argument(
        "--note",
        default="",
        help="Optional note about the custody event.",
    )

    custody_list_parser = custody_subparsers.add_parser(
        "list",
        help="List custody history for a case.",
    )
    custody_list_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    custody_list_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Create integrity manifests for evidence and reports.",
    )
    integrity_subparsers = integrity_parser.add_subparsers(dest="integrity_command", required=True)

    integrity_hash_parser = integrity_subparsers.add_parser(
        "hash",
        help="Write a SHA-256 manifest for a file.",
    )
    integrity_hash_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the evidence or report file to hash.",
    )
    integrity_hash_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write the SHA-256 manifest.",
    )

    verify_parser = integrity_subparsers.add_parser(
        "verify",
        help="Verify an artifact against a SHA-256 manifest.",
    )
    verify_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Artifact to verify.",
    )
    verify_parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="SHA-256 manifest file.",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Export case evidence package.",
    )
    export_subparsers = export_parser.add_subparsers(dest="export_command")

    # Standard export arguments when no subcommand (lock-info / unlock) is passed
    export_parser.add_argument(
        "--database",
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    export_parser.add_argument(
        "--case",
        dest="case_id",
        help="Case identifier.",
    )
    export_parser.add_argument(
        "--output",
        type=Path,
        help="Output directory path for the export package.",
    )

    lock_info_parser = export_subparsers.add_parser(
        "lock-info",
        help="Inspect export lock file metadata.",
    )
    lock_info_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )

    lock_status_parser = export_subparsers.add_parser(
        "lock-status",
        help="Inspect export lock file status and owner PID.",
    )
    lock_status_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )

    unlock_parser = export_subparsers.add_parser(
        "unlock",
        help="Remove export lock file.",
    )
    unlock_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )
    unlock_parser.add_argument(
        "--force",
        action="store_true",
        help="Force removal of the lock file.",
    )
    unlock_parser.add_argument(
        "--break-lock",
        action="store_true",
        help="Override active or unknown lock-owner status.",
    )

    database_parser = subparsers.add_parser(
        "database",
        help="Database management operations.",
    )
    database_subparsers = database_parser.add_subparsers(dest="database_command", required=True)

    db_check_parser = database_subparsers.add_parser(
        "check",
        help="Check SQLite database integrity.",
    )
    db_check_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )

    db_backup_parser = database_subparsers.add_parser(
        "backup",
        help="Create a safe SQLite database backup.",
    )
    db_backup_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the source SQLite database.",
    )
    db_backup_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination path for the backup.",
    )


    args = parser.parse_args()



    if args.command == "timeline":

        print_case_timeline(
            database_path=args.database,
            case_id=args.case_id,
        )
    elif args.command == "tree":
        print_case_tree(
            database_path=args.database,
            case_id=args.case_id,
        )
    elif args.command == "report":
        output_path = write_case_report(
            database_path=args.database,
            case_id=args.case_id,
            output_path=args.output,
        )
        print(f"Report written to {output_path}")
    elif args.command == "case":
        if args.case_command == "status":
            show_case_status(
                database_path=args.database,
                case_id=args.case_id,
            )
        elif args.case_command == "update":
            update_case_status(
                database_path=args.database,
                case_id=args.case_id,
                status=args.status,
                note=args.note,
            )
        elif args.case_command == "history":
            print_case_history(
                database_path=args.database,
                case_id=args.case_id,
            )
    elif args.command == "custody":
        if args.custody_command == "record":
            try:
                store = EvidenceStore(args.database)
                try:
                    store.record_custody_event(
                        case_id=args.case_id,
                        artifact_path=args.artifact_path,
                        sha256=args.sha256,
                        action=args.action,
                        analyst=args.analyst,
                        note=args.note,
                    )
                    print(
                        f"Recorded custody event for case {args.case_id}"
                    )
                finally:
                    store.close()
            except (ValueError, KeyError) as exc:
                parser.exit(1, f"{exc}\n")
        elif args.custody_command == "list":
            try:
                store = EvidenceStore(args.database)
                try:
                    case = store.get_case(args.case_id)
                    if case is None:
                        parser.exit(1, f"Case not found: {args.case_id}\n")

                    events = store.get_custody_events(args.case_id)
                    if not events:
                        print(f"No custody records for case {args.case_id}")
                        return

                    for event in events:
                        verification = "N/A"
                        if event["verification_result"] is not None:
                            verification = "Yes" if event["verification_result"] else "FAILED"

                        print(f"{event['recorded_at']} {event['action']}")
                        print(f"Artifact: {event['artifact_path']}")
                        print(f"Action: {event['action']}")
                        print(f"Analyst: {event['analyst']}")
                        print(f"SHA-256: {event['sha256']}")
                        print(f"Note: {event['note'] or 'N/A'}")
                        print(f"Verification: {verification}")
                        print()
                finally:
                    store.close()
            except (ValueError, KeyError) as exc:
                parser.exit(1, f"{exc}\n")
    elif args.command == "integrity":
        if args.integrity_command == "hash":
            manifest_path = write_integrity_manifest(
                input_path=args.input,
                output_path=args.output,
            )
            print(f"Manifest written to {manifest_path}")
        elif args.integrity_command == "verify":
            verified = verify_integrity_manifest(
                artifact_path=args.input,
                manifest_path=args.manifest,
            )
            if not verified:
                parser.exit(1, "Integrity verification failed\n")
            print("Integrity verified")
    elif args.command == "export":
        from ransomeye.export import (
            export_case,
            read_export_lock,
            remove_export_lock,
        )

        if args.export_command == "lock-info":
            try:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                metadata = read_export_lock(args.output)
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "success",
                    output=str(args.output),
                    case_id=metadata.get("case_id"),
                )
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
            except (FileNotFoundError, ValueError, OSError) as exc:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "failure",
                    output=str(args.output),
                    error=str(exc),
                )
                parser.exit(1, f"{exc}\n")
        elif args.export_command == "lock-status":
            try:
                from ransomeye.export import get_lock_owner_status
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                metadata = read_export_lock(args.output)
                owner_status = get_lock_owner_status(metadata)
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "success",
                    output=str(args.output),
                    case_id=metadata.get("case_id"),
                    owner_status=owner_status.value,
                )
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
                print(f"  Owner status: {owner_status.value}")

            except (FileNotFoundError, ValueError, OSError) as exc:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "failure",
                    output=str(args.output),
                    error=str(exc),
                )
                parser.exit(1, f"{exc}\n")



        elif args.export_command == "unlock":
            try:
                metadata = read_export_lock(args.output)
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
                removed_lock = remove_export_lock(
                    args.output,
                    force=args.force,
                    break_lock=args.break_lock,
                )
                print(f"Removed export lock: {removed_lock}")

            except (FileNotFoundError, ValueError, PermissionError, OSError) as exc:
                parser.exit(1, f"{exc}\n")
        else:
            if not args.database or not args.case_id or not args.output:
                parser.exit(2, "export requires --database, --case, and --output\n")
            try:
                exported_path = export_case(
                    database_path=args.database,
                    case_id=args.case_id,
                    output_path=args.output,
                )
                print(f"Exported case package to {exported_path}")
            except FileExistsError as exc:
                parser.exit(1, f"{exc}\n")
            except (OSError, sqlite3.Error, ValueError) as exc:
                parser.exit(1, f"Operation failed: {exc}\n")
    elif args.command == "database":
        if args.database_command == "check":
            try:
                from ransomeye.storage import check_database_integrity

                is_ok = check_database_integrity(args.database)
                if is_ok:
                    print("Database integrity: OK")
                else:
                    parser.exit(1, "Database integrity check failed: Integrity check returned non-ok result\n")
            except (FileNotFoundError, sqlite3.DatabaseError, sqlite3.Error, OSError) as exc:
                parser.exit(1, f"Database integrity check failed: {exc}\n")
        elif args.database_command == "backup":
            try:
                from ransomeye.storage import backup_database

                backup_path = backup_database(
                    args.database,
                    args.output,
                )
                print(f"Database backup created: {backup_path}")
            except (FileExistsError, FileNotFoundError, OSError, sqlite3.Error) as exc:
                parser.exit(1, f"Database backup failed: {exc}\n")







if __name__ == "__main__":
    main()
