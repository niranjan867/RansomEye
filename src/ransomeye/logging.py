"""Structured audit logging for RansomEye operational and security events."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "private_key",
    "content",
    "evidence",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else _sanitize(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_sanitize(item) for item in value]

    return value


def write_audit_event(
    log_path: Path | str,
    event: str,
    outcome: str,
    **fields: Any,
) -> None:
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "outcome": outcome,
        "pid": os.getpid(),
        **_sanitize(fields),
    }

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")


def try_write_audit_event(
    log_path: Path | str,
    event: str,
    outcome: str,
    **fields: Any,
) -> None:
    try:
        write_audit_event(
            log_path,
            event,
            outcome,
            **fields,
        )
    except Exception:
        return
