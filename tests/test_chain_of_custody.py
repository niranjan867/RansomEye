import pytest

from ransomeye.storage import EvidenceStore


def make_store(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Test")
    store.create_case(case_id="CASE-002", case_name="Custody Test 2")
    return store


def test_records_artifact_creation(tmp_path):
    store = make_store(tmp_path)

    store.record_custody_event(
        case_id="CASE-001",
        artifact_path="reports/case-report.txt",
        sha256="a" * 64,
        action="created",
        analyst="analyst@example.com",
        note="Initial report generated",
        verification_result=None,
    )

    events = store.get_custody_events("CASE-001")

    assert len(events) == 1
    assert events[0]["action"] == "created"
    assert events[0]["analyst"] == "analyst@example.com"
    assert events[0]["sha256"] == "a" * 64


def test_records_verification_result(tmp_path):
    store = make_store(tmp_path)

    store.record_custody_event(
        case_id="CASE-001",
        artifact_path="reports/case-report.txt",
        sha256="b" * 64,
        action="verified",
        analyst="analyst@example.com",
        note="Manifest verification completed",
        verification_result=True,
    )

    event = store.get_custody_events("CASE-001")[0]

    assert event["action"] == "verified"
    assert event["verification_result"] is True


def test_invalid_custody_action_is_rejected(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(ValueError, match="Invalid custody action"):
        store.record_custody_event(
            case_id="CASE-001",
            artifact_path="artifact.txt",
            sha256="c" * 64,
            action="deleted",
            analyst="analyst@example.com",
            note="",
            verification_result=None,
        )


def test_custody_history_is_chronological(tmp_path):
    store = make_store(tmp_path)

    for action in ("created", "verified", "reviewed"):
        store.record_custody_event(
            case_id="CASE-001",
            artifact_path="artifact.txt",
            sha256="d" * 64,
            action=action,
            analyst="analyst@example.com",
            note="",
            verification_result=True if action == "verified" else None,
        )

    events = store.get_custody_events("CASE-001")

    assert [event["action"] for event in events] == [
        "created",
        "verified",
        "reviewed",
    ]


def test_custody_history_is_scoped_to_case(tmp_path):
    store = make_store(tmp_path)

    store.record_custody_event(
        case_id="CASE-001",
        artifact_path="artifact.txt",
        sha256="e" * 64,
        action="created",
        analyst="analyst@example.com",
        note="",
        verification_result=None,
    )

    store.record_custody_event(
        case_id="CASE-002",
        artifact_path="artifact.txt",
        sha256="f" * 64,
        action="created",
        analyst="analyst@example.com",
        note="",
        verification_result=None,
    )

    events_case_001 = store.get_custody_events("CASE-001")
    events_case_002 = store.get_custody_events("CASE-002")

    assert len(events_case_001) == 1
    assert len(events_case_002) == 1
    assert events_case_001[0]["sha256"] == "e" * 64
    assert events_case_002[0]["sha256"] == "f" * 64
