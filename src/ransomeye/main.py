"""CLI entry point for safe simulation detection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ransomeye.rules import analyze_events


def load_events(json_path: Path) -> list[dict]:
    """Load synthetic events from a JSON file."""
    with json_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    events = payload.get("events", payload)
    if not isinstance(events, list):
        raise ValueError("JSON must contain an 'events' list.")

    return events


def format_result(result: dict) -> str:
    """Render a human-readable analysis summary."""
    lines = [
        f"Score: {result['score']}",
        f"Severity: {result['severity']}",
        f"Confidence: {result['confidence']}",
        "Reasons:",
    ]
    lines.extend(f"  - {reason}" for reason in result["reasons"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if len(args) != 1:
        print("Usage: python -m ransomeye.main <events.json>", file=sys.stderr)
        return 1

    json_path = Path(args[0])
    if not json_path.is_file():
        print(f"File not found: {json_path}", file=sys.stderr)
        return 1

    events = load_events(json_path)
    result = analyze_events(events)
    print(format_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
