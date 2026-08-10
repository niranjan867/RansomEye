from datetime import datetime, timedelta, timezone

from ransomeye.correlation import (
    CORRELATION_WINDOW_SECONDS,
    CorrelatedIncident,
    correlate_events,
    correlate_findings,
    generate_incident_id,
)
from ransomeye.evidence import EvidenceEvent


def make_event(
    event_id: str,
    timestamp_second: int | float,
    process_name: str,
    pid: str,
    parent_pid: str | None = None,
    process_guid: str | None = None,
    parent_process_guid: str | None = None,
    host: str = "TEST-HOST",
    destination_ip: str | None = None,
):
    base_time = datetime(2026, 8, 8, 15, 0, 0, tzinfo=timezone.utc)
    ts = base_time + timedelta(seconds=timestamp_second)
    data = {
        "event_id": event_id,
        "timestamp": ts,
        "source": "simulation",
        "event_type": "process_create",
        "process_name": process_name,
        "pid": pid,
        "parent_pid": parent_pid,
        "process_guid": process_guid,
        "parent_process_guid": parent_process_guid,
        "host": host,
    }
    if destination_ip:
        data["destination_ip"] = destination_ip
    return EvidenceEvent.from_dict(data)


# -------------------------------------------------------------------------
# Legacy Tests (Backward Compatibility)
# -------------------------------------------------------------------------

def test_events_with_same_process_guid_are_correlated():
    events = [
        make_event(
            "event-1",
            1,
            "powershell.exe",
            "4532",
            process_guid="{GUID-1}",
        ),
        make_event(
            "event-2",
            2,
            "powershell.exe",
            "4532",
            process_guid="{GUID-1}",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1
    assert incidents[0].process_key == "guid:{GUID-1}"
    assert len(incidents[0].events) == 2


def test_events_with_different_processes_create_separate_incidents():
    events = [
        make_event("event-1", 1, "powershell.exe", "4532"),
        make_event("event-2", 2, "cmd.exe", "6000"),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 2


def test_parent_child_relationship_is_preserved():
    events = [
        make_event(
            "event-1",
            1,
            "powershell.exe",
            "4532",
            parent_pid="1200",
        )
    ]

    incidents = correlate_events(events)

    relationship = incidents[0].parent_relationships[0]

    assert relationship["parent_pid"] == "1200"
    assert relationship["child_pid"] == "4532"
    assert relationship["child_process"] == "powershell.exe"


def test_incident_events_are_sorted_by_timestamp():
    events = [
        make_event("event-2", 5, "powershell.exe", "4532"),
        make_event("event-1", 1, "powershell.exe", "4532"),
    ]

    incidents = correlate_events(events)

    assert incidents[0].events[0]["event_id"] == "event-1"
    assert incidents[0].events[1]["event_id"] == "event-2"
    assert incidents[0].duration_seconds == 4


# -------------------------------------------------------------------------
# Milestone 19 Cross-Behavior Correlation Engine Tests
# -------------------------------------------------------------------------

def test_1_same_process_guid_correlates_findings():
    """F-001 and F-002 sharing same ProcessGuid correlate into 1 incident."""
    ev1 = make_event("EVT-1", 10, "powershell.exe", "1000", process_guid="{GUID-P1}")
    ev2 = make_event("EVT-2", 20, "powershell.exe", "1000", process_guid="{GUID-P1}")
    findings = [
        {"finding_id": "F-001", "type": "powershell", "event_ids": ["EVT-1"]},
        {"finding_id": "F-002", "type": "network", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 1
    assert incidents[0].finding_ids == ("F-001", "F-002")
    assert "same_process_guid" in incidents[0].correlation_reasons


def test_2_different_process_guid_separate_incidents():
    """F-001 -> P1, F-002 -> P2 with no other relationship produce 2 incidents."""
    ev1 = make_event("EVT-1", 10, "powershell.exe", "1000", process_guid="{GUID-P1}")
    ev2 = make_event("EVT-2", 20, "cmd.exe", "2000", process_guid="{GUID-P2}")
    findings = [
        {"finding_id": "F-001", "type": "powershell", "event_ids": ["EVT-1"]},
        {"finding_id": "F-002", "type": "cmd", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_3_parent_child_within_and_beyond_window():
    """Parent and child within 60s correlate; beyond 60s remain separate."""
    # Within 60 seconds (delta = 30s)
    ev_p = make_event("EVT-P", 10, "parent.exe", "1000", process_guid="{GUID-P}")
    ev_c = make_event("EVT-C", 40, "child.exe", "2000", process_guid="{GUID-C}", parent_process_guid="{GUID-P}")
    findings = [
        {"finding_id": "F-P", "event_ids": ["EVT-P"]},
        {"finding_id": "F-C", "event_ids": ["EVT-C"]},
    ]
    inc_within = correlate_findings(findings, [ev_p, ev_c])
    assert len(inc_within) == 1
    assert "parent_child_within_window" in inc_within[0].correlation_reasons

    # Beyond 60 seconds (delta = 70s)
    ev_c_late = make_event("EVT-C2", 80, "child.exe", "2000", process_guid="{GUID-C2}", parent_process_guid="{GUID-P}")
    findings_late = [
        {"finding_id": "F-P", "event_ids": ["EVT-P"]},
        {"finding_id": "F-C2", "event_ids": ["EVT-C2"]},
    ]
    inc_late = correlate_findings(findings_late, [ev_p, ev_c_late])
    assert len(inc_late) == 2


def test_4_exact_boundary_window():
    """delta = 60s correlates; delta = 60.001s does not correlate."""
    ev_p = make_event("EVT-P", 0.0, "parent.exe", "1000", process_guid="{GUID-P}")
    ev_c_exact = make_event("EVT-C-EXACT", 60.0, "child.exe", "2000", process_guid="{GUID-C}", parent_process_guid="{GUID-P}")
    findings_exact = [
        {"finding_id": "F-P", "event_ids": ["EVT-P"]},
        {"finding_id": "F-C", "event_ids": ["EVT-C-EXACT"]},
    ]
    inc_exact = correlate_findings(findings_exact, [ev_p, ev_c_exact])
    assert len(inc_exact) == 1

    ev_c_over = make_event("EVT-C-OVER", 60.001, "child.exe", "3000", process_guid="{GUID-C3}", parent_process_guid="{GUID-P}")
    findings_over = [
        {"finding_id": "F-P", "event_ids": ["EVT-P"]},
        {"finding_id": "F-C-OVER", "event_ids": ["EVT-C-OVER"]},
    ]
    inc_over = correlate_findings(findings_over, [ev_p, ev_c_over])
    assert len(inc_over) == 2


def test_5_pid_fallback_within_and_beyond_window():
    """PID fallback correlates when within 60s and no GUID; separates when beyond."""
    ev1 = make_event("EVT-1", 10, "app.exe", "4000", process_guid=None)
    ev2 = make_event("EVT-2", 50, "app.exe", "4000", process_guid=None)
    findings_within = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
    ]
    inc_within = correlate_findings(findings_within, [ev1, ev2])
    assert len(inc_within) == 1
    assert "pid_fallback_within_window" in inc_within[0].correlation_reasons

    # Beyond window (PID reuse)
    ev3 = make_event("EVT-3", 80, "app.exe", "4000", process_guid=None)
    findings_late = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-3", "event_ids": ["EVT-3"]},
    ]
    inc_late = correlate_findings(findings_late, [ev1, ev3])
    assert len(inc_late) == 2


def test_6_shared_evidence_correlates():
    """Two findings sharing supporting evidence correlate into 1 incident."""
    ev1 = make_event("EVT-1", 10, "app1.exe", "1000", process_guid="{GUID-1}")
    ev2 = make_event("EVT-2", 20, "app2.exe", "2000", process_guid="{GUID-2}")
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1", "EVT-2"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 1
    assert "shared_evidence" in incidents[0].correlation_reasons


def test_7_same_host_alone_does_not_correlate():
    """Same host and time without process or evidence relationship MUST NOT correlate."""
    ev1 = make_event("EVT-1", 10, "app1.exe", "1000", process_guid="{GUID-1}", host="SRV-01")
    ev2 = make_event("EVT-2", 15, "app2.exe", "2000", process_guid="{GUID-2}", host="SRV-01")
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_8_same_destination_alone_does_not_correlate():
    """Two unrelated processes connecting to same IP MUST NOT correlate."""
    ev1 = make_event("EVT-1", 10, "app1.exe", "1000", process_guid="{GUID-1}", destination_ip="198.51.100.5")
    ev2 = make_event("EVT-2", 15, "app2.exe", "2000", process_guid="{GUID-2}", destination_ip="198.51.100.5")
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_9_same_process_name_alone_does_not_correlate():
    """Same process name (powershell.exe) on distinct process identities MUST NOT correlate."""
    ev1 = make_event("EVT-1", 10, "powershell.exe", "1000", process_guid="{GUID-A}")
    ev2 = make_event("EVT-2", 15, "powershell.exe", "2000", process_guid="{GUID-B}")
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_10_missing_timestamp_does_not_invent_relationship():
    """Events with missing timestamps do not create temporal relationships."""
    ev1 = {
        "event_id": "EVT-NO-TS-1",
        "timestamp": None,
        "source": "simulation",
        "event_type": "process_create",
        "process_name": "app.exe",
        "pid": "5000",
    }
    ev2 = {
        "event_id": "EVT-NO-TS-2",
        "timestamp": None,
        "source": "simulation",
        "event_type": "process_create",
        "process_name": "app.exe",
        "pid": "5000",
    }
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-NO-TS-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-NO-TS-2"]},
    ]
    # Without timestamps, PID fallback cannot verify temporal window
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_11_invalid_timestamp_handled_gracefully():
    """Malformed timestamps are ignored for temporal correlation without crashing."""
    ev1 = {
        "event_id": "EVT-INV-1",
        "timestamp": "INVALID-DATE-STRING",
        "source": "simulation",
        "event_type": "process_create",
        "process_name": "app.exe",
        "pid": "6000",
    }
    ev2 = {
        "event_id": "EVT-INV-2",
        "timestamp": "MALFORMED-DATE",
        "source": "simulation",
        "event_type": "process_create",
        "process_name": "app.exe",
        "pid": "6000",
    }
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-INV-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-INV-2"]},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 2


def test_12_deterministic_incident_id_order_independent():
    """Same content in different input orders produces the exact same incident_id."""
    ev1 = make_event("EVT-1", 10, "app.exe", "1000", process_guid="{GUID-P}")
    ev2 = make_event("EVT-2", 20, "app.exe", "1000", process_guid="{GUID-P}")
    f1 = {"finding_id": "F-1", "event_ids": ["EVT-1"], "case_id": "CASE-1"}
    f2 = {"finding_id": "F-2", "event_ids": ["EVT-2"], "case_id": "CASE-1"}

    inc1 = correlate_findings([f1, f2], [ev1, ev2])
    inc2 = correlate_findings([f2, f1], [ev2, ev1])

    assert len(inc1) == 1
    assert len(inc2) == 1
    assert inc1[0].incident_id == inc2[0].incident_id
    assert inc1[0].incident_id.startswith("INC-")


def test_13_different_content_produces_different_id():
    """Different evidence or findings produce distinct incident IDs."""
    ev1 = make_event("EVT-1", 10, "app.exe", "1000", process_guid="{GUID-P}")
    ev2 = make_event("EVT-2", 20, "app.exe", "1000", process_guid="{GUID-P}")
    f1 = {"finding_id": "F-1", "event_ids": ["EVT-1"], "case_id": "CASE-1"}
    f2 = {"finding_id": "F-2", "event_ids": ["EVT-2"], "case_id": "CASE-1"}
    f3 = {"finding_id": "F-3", "event_ids": ["EVT-2"], "case_id": "CASE-1"}

    inc_a = correlate_findings([f1, f2], [ev1, ev2])
    inc_b = correlate_findings([f1, f3], [ev1, ev2])

    assert inc_a[0].incident_id != inc_b[0].incident_id


def test_14_multiple_independent_incidents():
    """Two distinct finding groups form two independent incidents."""
    ev1 = make_event("EVT-1", 10, "p1.exe", "100", process_guid="{GUID-1}")
    ev2 = make_event("EVT-2", 15, "p1.exe", "100", process_guid="{GUID-1}")
    ev3 = make_event("EVT-3", 20, "p2.exe", "200", process_guid="{GUID-2}")
    ev4 = make_event("EVT-4", 25, "p2.exe", "200", process_guid="{GUID-2}")

    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"]},
        {"finding_id": "F-2", "event_ids": ["EVT-2"]},
        {"finding_id": "F-3", "event_ids": ["EVT-3"]},
        {"finding_id": "F-4", "event_ids": ["EVT-4"]},
    ]

    incidents = correlate_findings(findings, [ev1, ev2, ev3, ev4])
    assert len(incidents) == 2
    assert incidents[0].finding_ids == ("F-1", "F-2")
    assert incidents[1].finding_ids == ("F-3", "F-4")


def test_15_incident_traceability_preserved():
    """Verify all traceability fields are preserved on CorrelatedIncident."""
    ev1 = make_event("EVT-1", 10, "p1.exe", "100", process_guid="{GUID-1}")
    ev2 = make_event("EVT-2", 20, "p1.exe", "100", process_guid="{GUID-1}")
    findings = [
        {"finding_id": "F-1", "event_ids": ["EVT-1"], "case_id": "CASE-TRACE"},
        {"finding_id": "F-2", "event_ids": ["EVT-2"], "case_id": "CASE-TRACE"},
    ]
    incidents = correlate_findings(findings, [ev1, ev2])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.case_id == "CASE-TRACE"
    assert inc.finding_ids == ("F-1", "F-2")
    assert inc.evidence_ids == ("EVT-1", "EVT-2")
    assert inc.process_ids == ("guid:{GUID-1}", "pid:100")
    assert inc.start_time is not None
    assert inc.end_time is not None
    assert "same_process_guid" in inc.correlation_reasons


def test_16_empty_inputs_return_empty_list():
    """Empty inputs return empty list without error."""
    assert correlate_findings([], [], {}) == []
    assert correlate_findings([], []) == []
    assert correlate_events([]) == []
