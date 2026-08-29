"""Tests for ransomeye collect live CLI command and handler."""

import os
import subprocess
import sys
from pathlib import Path
import pytest
from ransomeye.commands import run_collect_live_command
from ransomeye.storage import EvidenceStore


def _run_command(args, cwd=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "ransomeye.commands", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return result


def test_collect_live_command_case_not_found(tmp_path):
    db_path = tmp_path / "test_missing_case.db"
    store = EvidenceStore(db_path)
    store.close()

    with pytest.raises(KeyError, match="Case not found"):
        run_collect_live_command(
            database_path=db_path,
            case_id="NON_EXISTENT_CASE",
            run_duration=0.1,
        )


def test_collect_live_command_execution(tmp_path):
    db_path = tmp_path / "test_live_exec.db"
    store = EvidenceStore(db_path)
    store.create_case("LIVE-TEST-001", "Live Test Case")
    store.close()

    watch_dir = tmp_path / "watch_dir"
    canary_dir = tmp_path / "canary_dir"

    # Run for 0.5s to test clean startup and deterministic shutdown
    summary = run_collect_live_command(
        database_path=db_path,
        case_id="LIVE-TEST-001",
        watch_dir=watch_dir,
        canary_dir=canary_dir,
        flush_interval=0.2,
        poll_interval=0.2,
        run_duration=0.5,
    )

    assert summary["case_id"] == "LIVE-TEST-001"
    assert summary["pipeline_state"] == "STOPPED"
    assert watch_dir.is_dir()
    assert canary_dir.is_dir()


def test_collect_live_cli_subprocess(tmp_path):
    db_path = tmp_path / "test_live_cli.db"
    store = EvidenceStore(db_path)
    store.create_case("LIVE-CLI-001", "CLI Live Case")
    store.close()

    # Verify invalid case via CLI exits with code 1
    cli_fail = _run_command([
        "collect", "live",
        "--database", str(db_path),
        "--case", "INVALID-CASE",
    ])
    assert cli_fail.returncode == 1
    assert "Live collection failed" in cli_fail.stderr or "Live collection failed" in cli_fail.stdout
