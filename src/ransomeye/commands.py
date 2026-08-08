"""Command-line helpers for inspecting stored RansomEye cases."""

from __future__ import annotations

import argparse
from pathlib import Path

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


if __name__ == "__main__":
    main()
