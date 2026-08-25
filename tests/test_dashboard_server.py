"""Integration tests for RansomEye Dashboard HTTP Server (M23.9 Product Integration)."""

import json
import socket
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
import pytest

from ransomeye import dashboard_server
from ransomeye.commands import ingest_evidence
from ransomeye.storage import EvidenceStore


def find_free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def test_db_path(tmp_path):
    """Fixture providing a temporary SQLite database path."""
    return tmp_path / "test-dashboard.db"


@pytest.fixture
def running_server(test_db_path):
    """Fixture running the Dashboard server in a background thread."""
    port = find_free_port()
    dashboard_server.DB_PATH = test_db_path

    server_address = ("127.0.0.1", port)
    httpd = dashboard_server.HTTPServer(server_address, dashboard_server.DashboardHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.2)  # Allow server to bind and start

    yield f"http://127.0.0.1:{port}"

    httpd.shutdown()
    httpd.server_close()


def test_dashboard_static_files(running_server):
    """Verify static files (index.html, styles.css, app.js, logo.png) serve correctly."""
    req = urllib.request.urlopen(f"{running_server}/")
    assert req.status == 200
    assert "text/html" in req.headers["Content-Type"]
    body = req.read().decode("utf-8")
    assert "<title>RansomEye - Analyst Console</title>" in body

    req_css = urllib.request.urlopen(f"{running_server}/styles.css")
    assert req_css.status == 200
    assert "text/css" in req_css.headers["Content-Type"]

    req_js = urllib.request.urlopen(f"{running_server}/app.js")
    assert req_js.status == 200
    assert "application/javascript" in req_js.headers["Content-Type"]

    req_logo = urllib.request.urlopen(f"{running_server}/logo.png")
    assert req_logo.status == 200
    assert "image/png" in req_logo.headers["Content-Type"]


def test_dashboard_no_db_and_missing_db(tmp_path):
    """Verify behavior when DB_PATH is None or points to a non-existent file."""
    port = find_free_port()
    dashboard_server.DB_PATH = tmp_path / "nonexistent.db"

    httpd = dashboard_server.HTTPServer(("127.0.0.1", port), dashboard_server.DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)

    try:
        url = f"http://127.0.0.1:{port}"

        # GET /api/cases returns empty list when DB missing
        req = urllib.request.urlopen(f"{url}/api/cases")
        assert json.loads(req.read().decode("utf-8")) == {"cases": []}

        # Case endpoints return 400 Database not configured
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{url}/api/case/CASE-01")
        assert exc_info.value.code == 400

        # POST /api/collect returns 400
        payload = json.dumps({"case_id": "C1", "file_path": "foo.xml"}).encode("utf-8")
        post_req = urllib.request.Request(f"{url}/api/collect", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(post_req)
        assert exc_info.value.code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_dashboard_api_cases_empty(running_server, test_db_path):
    """Verify GET /api/cases returns empty list when DB has no cases."""
    store = EvidenceStore(test_db_path)
    store.close()

    req = urllib.request.urlopen(f"{running_server}/api/cases")
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert "cases" in data
    assert data["cases"] == []


def test_dashboard_unassessed_case(running_server, test_db_path):
    """Verify handling of a case with no threat assessment."""
    store = EvidenceStore(test_db_path)
    store.create_case("UNASSESSED-01")
    store.close()

    req = urllib.request.urlopen(f"{running_server}/api/case/UNASSESSED-01")
    data = json.loads(req.read().decode("utf-8"))
    assert data["case"]["case_id"] == "UNASSESSED-01"
    assert data["assessment"] is None
    assert data["stats"]["events"] == 0
    assert data["stats"]["findings"] == 0
    assert data["stats"]["incidents"] == 0


def test_dashboard_full_analyst_workflow(running_server, test_db_path):
    """Test full analyst API workflow against ingested evidence."""
    sample_file = Path("samples/sysmon/realistic_ransomware_sequence.xml")
    assert sample_file.exists(), "Test fixture sample file must exist"

    summary = ingest_evidence(
        database_path=test_db_path,
        case_id="WORKFLOW-CASE-01",
        file_path=sample_file,
        format_type="sysmon-xml",
        case_name="Workflow Demo",
        host="TEST-HOST-01",
    )
    assert summary["events_accepted"] == 7

    req = urllib.request.urlopen(f"{running_server}/api/cases")
    cases_data = json.loads(req.read().decode("utf-8"))
    assert len(cases_data["cases"]) == 1
    assert cases_data["cases"][0]["case_id"] == "WORKFLOW-CASE-01"

    req = urllib.request.urlopen(f"{running_server}/api/case/WORKFLOW-CASE-01")
    case_data = json.loads(req.read().decode("utf-8"))
    assert case_data["case"]["case_id"] == "WORKFLOW-CASE-01"
    assert case_data["stats"]["events"] == 7
    assert case_data["stats"]["findings"] == 3
    assert case_data["stats"]["incidents"] == 1
    assert case_data["assessment"]["score"] == 50
    assert case_data["assessment"]["severity"] == "MEDIUM"

    req = urllib.request.urlopen(f"{running_server}/api/incidents/WORKFLOW-CASE-01")
    inc_data = json.loads(req.read().decode("utf-8"))
    assert len(inc_data["incidents"]) == 1
    assert "incident_id" in inc_data["incidents"][0]

    req = urllib.request.urlopen(f"{running_server}/api/findings/WORKFLOW-CASE-01")
    find_data = json.loads(req.read().decode("utf-8"))
    assert len(find_data["findings"]) == 3

    req = urllib.request.urlopen(f"{running_server}/api/recent_activity/WORKFLOW-CASE-01")
    act_data = json.loads(req.read().decode("utf-8"))
    assert len(act_data["activity"]) == 7

    req = urllib.request.urlopen(f"{running_server}/api/search/WORKFLOW-CASE-01?q=vssadmin")
    search_data = json.loads(req.read().decode("utf-8"))
    assert len(search_data["results"]) >= 1

    event_id = search_data["results"][0]["event_id"]

    # 8. GET /api/inspect/WORKFLOW-CASE-01?event_id=<encoded>
    enc_id = urllib.parse.quote(event_id)
    req = urllib.request.urlopen(f"{running_server}/api/inspect/WORKFLOW-CASE-01?event_id={enc_id}")
    inspect_data = json.loads(req.read().decode("utf-8"))
    assert inspect_data["event"]["event_id"] == event_id
    assert "trace" in inspect_data

    pid = search_data["results"][0]["pid"]
    req = urllib.request.urlopen(f"{running_server}/api/process/WORKFLOW-CASE-01/{pid}")
    proc_data = json.loads(req.read().decode("utf-8"))
    assert proc_data["process"]["pid"] == pid

    req = urllib.request.urlopen(f"{running_server}/api/timeline/WORKFLOW-CASE-01")
    tl_data = json.loads(req.read().decode("utf-8"))
    assert len(tl_data["timeline"]) > 0
    untimed = [t for t in tl_data["timeline"] if not t["timestamp"] or t["timestamp"] == "Unknown Time" or t["description"].startswith("Threat Score:")]
    timed = [t for t in tl_data["timeline"] if t["timestamp"] and t["timestamp"] != "Unknown Time" and not t["description"].startswith("Threat Score:")]
    assert len(untimed) >= 1
    assert "Threat Score:" in untimed[0]["description"]
    assert len(timed) >= 1

    req = urllib.request.urlopen(f"{running_server}/api/reconstruction/WORKFLOW-CASE-01")
    rec_data = json.loads(req.read().decode("utf-8"))
    assert rec_data["status"] in ("OK", "UNAVAILABLE")

    req = urllib.request.urlopen(f"{running_server}/api/validation/WORKFLOW-CASE-01")
    val_data = json.loads(req.read().decode("utf-8"))
    assert val_data["passed"] is True
    assert "RANSOMEYE INVESTIGATION VALIDATION" in val_data["rendered"]

    post_req = urllib.request.Request(
        f"{running_server}/api/report/WORKFLOW-CASE-01",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(post_req) as resp:
        report_data = json.loads(resp.read().decode("utf-8"))
        assert report_data["message"] == "Report generated"
        assert "RANSOMEYE CASE REPORT" in report_data["content"]


def test_dashboard_empty_search_and_invalid_inspect(running_server, test_db_path):
    """Verify empty search results and invalid inspect/process 404 handling."""
    store = EvidenceStore(test_db_path)
    store.create_case("EMPTY-SEARCH-CASE")
    store.close()

    # Empty search
    req = urllib.request.urlopen(f"{running_server}/api/search/EMPTY-SEARCH-CASE?q=nonexistentterm123")
    data = json.loads(req.read().decode("utf-8"))
    assert data["results"] == []

    # Invalid event ID
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/inspect/EMPTY-SEARCH-CASE?event_id=INVALID-EVENT-ID")
    assert exc_info.value.code == 404

    # Invalid process PID
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/EMPTY-SEARCH-CASE/999999")
    assert exc_info.value.code == 404


def test_dashboard_inspect_windows_path_event_id(running_server, test_db_path):
    """Regression test for evidence inspection with Windows paths, GUIDs, spaces, missing events, and case isolation."""
    from ransomeye.evidence import EvidenceEvent

    win_path_event_id = r"sysmon-11-C:\Users\Analyst\Documents\README_DECRYPT.txt"
    guid_event_id = "sysmon-1-{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
    spaces_event_id = r"sysmon-11-C:\Users\Analyst\Documents\My Documents\README.txt"

    store = EvidenceStore(test_db_path)
    store.create_case("WIN-PATH-CASE")
    store.create_case("OTHER-CASE-99")

    ev_win = EvidenceEvent(
        event_id=win_path_event_id,
        timestamp="2026-08-25T22:00:00Z",
        source="sysmon",
        event_type="file_create",
        process_name="ransomware.exe",
        pid=4096,
        command_line=r"C:\ransomware.exe",
        image_path=r"C:\ransomware.exe",
        file_path=r"C:\Users\Analyst\Documents\README_DECRYPT.txt",
    )
    ev_guid = EvidenceEvent(
        event_id=guid_event_id,
        timestamp="2026-08-25T22:01:00Z",
        source="sysmon",
        event_type="process_create",
        process_name="cmd.exe",
        pid=1024,
    )
    ev_spaces = EvidenceEvent(
        event_id=spaces_event_id,
        timestamp="2026-08-25T22:02:00Z",
        source="sysmon",
        event_type="file_create",
        file_path=r"C:\Users\Analyst\Documents\My Documents\README.txt",
    )
    store.save_event("WIN-PATH-CASE", ev_win)
    store.save_event("WIN-PATH-CASE", ev_guid)
    store.save_event("WIN-PATH-CASE", ev_spaces)
    store.close()

    # 1. Windows path event ID
    enc_win = urllib.parse.quote(win_path_event_id)
    req = urllib.request.urlopen(f"{running_server}/api/inspect/WIN-PATH-CASE?event_id={enc_win}")
    assert req.status == 200
    data_win = json.loads(req.read().decode("utf-8"))
    assert data_win["event"]["event_id"] == win_path_event_id
    assert data_win["event"]["file_path"] == r"C:\Users\Analyst\Documents\README_DECRYPT.txt"

    # 2. GUID event ID
    enc_guid = urllib.parse.quote(guid_event_id)
    req = urllib.request.urlopen(f"{running_server}/api/inspect/WIN-PATH-CASE?event_id={enc_guid}")
    assert req.status == 200
    data_guid = json.loads(req.read().decode("utf-8"))
    assert data_guid["event"]["event_id"] == guid_event_id

    # 3. Spaces in path event ID
    enc_spaces = urllib.parse.quote(spaces_event_id)
    req = urllib.request.urlopen(f"{running_server}/api/inspect/WIN-PATH-CASE?event_id={enc_spaces}")
    assert req.status == 200
    data_spaces = json.loads(req.read().decode("utf-8"))
    assert data_spaces["event"]["event_id"] == spaces_event_id

    # 4. Missing event returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/inspect/WIN-PATH-CASE?event_id=NONEXISTENT_EV")
    assert exc_info.value.code == 404

    # 5. Case isolation: Event from WIN-PATH-CASE requested under OTHER-CASE-99 returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/inspect/OTHER-CASE-99?event_id={enc_win}")
    assert exc_info.value.code == 404


def test_dashboard_inspect_event_process_pivot_and_empty_state(running_server, test_db_path):
    """Test evidence inspection API returning process context and handling events with no process identity."""
    from ransomeye.evidence import EvidenceEvent

    store = EvidenceStore(test_db_path)
    store.create_case("PIVOT-CASE-01")

    # Event with process identity
    ev1 = EvidenceEvent(
        event_id="EV-WITH-PROC",
        timestamp="2026-08-25T22:30:00Z",
        source="sysmon",
        event_type="file_create",
        process_name="cmd.exe",
        pid=1234,
        process_guid="{AAAA-BBBB-CCCC-DDDD}",
    )
    store.save_event("PIVOT-CASE-01", ev1)

    # Event without process identity
    ev2 = EvidenceEvent(
        event_id="EV-NO-PROC",
        timestamp="2026-08-25T22:31:00Z",
        source="file_behavior",
        event_type="file_modify",
        file_path=r"C:\temp\file.txt",
    )
    store.save_event("PIVOT-CASE-01", ev2)
    store.close()

    # 1. Event with process identity returns process attributes in inspect response
    req = urllib.request.urlopen(f"{running_server}/api/inspect/PIVOT-CASE-01?event_id=EV-WITH-PROC")
    data1 = json.loads(req.read().decode("utf-8"))
    assert data1["event"]["event_id"] == "EV-WITH-PROC"
    assert data1["event"]["process_name"] == "cmd.exe"
    assert str(data1["event"]["pid"]) == "1234"
    assert data1["event"]["process_guid"] == "{AAAA-BBBB-CCCC-DDDD}"

    # 2. Event without process identity handles missing process fields cleanly
    req2 = urllib.request.urlopen(f"{running_server}/api/inspect/PIVOT-CASE-01?event_id=EV-NO-PROC")
    data2 = json.loads(req2.read().decode("utf-8"))
    assert data2["event"]["event_id"] == "EV-NO-PROC"
    assert not data2["event"].get("process_name")
    assert not data2["event"].get("process_guid")


def test_dashboard_collection_security_checks(running_server, test_db_path, tmp_path):
    """Verify POST /api/collect security controls (directories, extensions, path traversal)."""
    store = EvidenceStore(test_db_path)
    store.create_case("SEC-CASE-01")
    store.close()

    # 1. Directory target rejection
    payload = json.dumps({"case_id": "SEC-CASE-01", "file_path": str(tmp_path)}).encode("utf-8")
    req = urllib.request.Request(f"{running_server}/api/collect", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400

    # 2. Unsupported extension rejection (.exe)
    dummy_exe = tmp_path / "malicious.exe"
    dummy_exe.write_bytes(b"MZ12345")
    payload = json.dumps({"case_id": "SEC-CASE-01", "file_path": str(dummy_exe)}).encode("utf-8")
    req = urllib.request.Request(f"{running_server}/api/collect", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400

    # 3. Invalid / traversal case ID rejection
    sample_file = Path("samples/sysmon/realistic_ransomware_sequence.xml")
    payload = json.dumps({"case_id": "../TRAVERSAL", "file_path": str(sample_file)}).encode("utf-8")
    req = urllib.request.Request(f"{running_server}/api/collect", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400


def test_dashboard_report_security_checks(running_server, test_db_path):
    """Verify POST /api/report case_id validation and missing case handling."""
    store = EvidenceStore(test_db_path)
    store.close()

    # Invalid case_id with slash / traversal
    req = urllib.request.Request(f"{running_server}/api/report/../../etc/passwd", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code in (400, 404)

    # Missing case_id
    req = urllib.request.Request(f"{running_server}/api/report/MISSING-CASE-ID", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 404


def test_dashboard_process_missing_graph_node_behavior(running_server, test_db_path):
    """Test process profile endpoints for missing graph nodes and preserving PID=2000 metadata."""
    from ransomeye.evidence import EvidenceEvent

    store = EvidenceStore(test_db_path)
    store.create_case("PROC-CASE-A")
    store.create_case("PROC-CASE-B")

    # Ingest event with process metadata (Process Name: powershell.exe, PID: 2000, Process GUID: {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA})
    ev = EvidenceEvent(
        event_id="EV-PROC-2000",
        timestamp="2026-08-25T23:00:00Z",
        source="sysmon",
        event_type="process_create",
        process_name="powershell.exe",
        pid=2000,
        process_guid="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
    )
    store.save_event("PROC-CASE-A", ev)
    store.close()

    # 1. Event inspect API returns exact process metadata (PID: 2000)
    enc_id = urllib.parse.quote("EV-PROC-2000")
    req = urllib.request.urlopen(f"{running_server}/api/inspect/PROC-CASE-A?event_id={enc_id}")
    data = json.loads(req.read().decode("utf-8"))
    assert data["event"]["process_name"] == "powershell.exe"
    assert str(data["event"]["pid"]) == "2000"
    assert data["event"]["process_guid"] == "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"

    # 2. Process GUID with no graph node returns 404 cleanly (frontend handles as PROCESS PROFILE UNAVAILABLE)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/PROC-CASE-A/%7BAAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA%7D")
    assert exc_info.value.code == 404

    # 3. Case isolation: Process in PROC-CASE-A requested under PROC-CASE-B returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/PROC-CASE-B/%7BAAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA%7D")
    assert exc_info.value.code == 404


def test_dashboard_report_post_contract(running_server, test_db_path):
    """Verify report generation is POST only, returns HTTP 200, message=='Report generated', and contains RANSOMEYE CASE REPORT."""
    store = EvidenceStore(test_db_path)
    store.create_case("REPORT-POST-CASE")
    store.close()

    # GET request to /api/report/CASE must fail (not supported)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/report/REPORT-POST-CASE")
    assert exc_info.value.code in (404, 501)

    # POST request with JSON body {}
    req = urllib.request.Request(
        f"{running_server}/api/report/REPORT-POST-CASE",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["message"] == "Report generated"
        assert "path" in data
        assert "RANSOMEYE CASE REPORT" in data["content"]


def test_dashboard_evidence_search_queries(running_server, test_db_path):
    """Verify GET /api/search with q= empty, q=term, q=nonexistent, case isolation, and Windows path event inspection."""
    from ransomeye.evidence import EvidenceEvent

    store = EvidenceStore(test_db_path)
    store.create_case("SEARCH-CASE-A")
    store.create_case("SEARCH-CASE-B")

    win_path_id = r"sysmon-11-C:\Users\Analyst\Documents\README_DECRYPT.txt"

    ev1 = EvidenceEvent(
        event_id=win_path_id,
        timestamp="2026-08-25T10:00:00Z",
        source="sysmon",
        event_type="file_create",
        process_name="cmd.exe",
        pid=1111,
        file_path=r"C:\Users\Analyst\Documents\README_DECRYPT.txt",
    )
    ev2 = EvidenceEvent(
        event_id="EV-REGULAR-02",
        timestamp="2026-08-25T10:01:00Z",
        source="sysmon",
        event_type="process_create",
        process_name="vssadmin.exe",
        pid=2222,
    )
    ev_case_b = EvidenceEvent(
        event_id="EV-CASE-B-01",
        timestamp="2026-08-25T10:02:00Z",
        source="sysmon",
        event_type="process_create",
        process_name="powershell.exe",
        pid=3333,
    )

    store.save_event("SEARCH-CASE-A", ev1)
    store.save_event("SEARCH-CASE-A", ev2)
    store.save_event("SEARCH-CASE-B", ev_case_b)
    store.close()

    # 1. Empty query q= returns all case-scoped evidence (2 events for SEARCH-CASE-A)
    req = urllib.request.urlopen(f"{running_server}/api/search/SEARCH-CASE-A?q=")
    assert req.status == 200
    data_all = json.loads(req.read().decode("utf-8"))
    assert len(data_all["results"]) == 2

    # 2. Filtered search q=README returns matching event
    req_filt = urllib.request.urlopen(f"{running_server}/api/search/SEARCH-CASE-A?q=README")
    assert req_filt.status == 200
    data_filt = json.loads(req_filt.read().decode("utf-8"))
    assert len(data_filt["results"]) == 1
    assert data_filt["results"][0]["event_id"] == win_path_id

    # 3. Empty search result q=nonexistent
    req_none = urllib.request.urlopen(f"{running_server}/api/search/SEARCH-CASE-A?q=nonexistentterm999")
    assert req_none.status == 200
    data_none = json.loads(req_none.read().decode("utf-8"))
    assert data_none["results"] == []

    # 4. Case isolation: SEARCH-CASE-B returns only its event, not SEARCH-CASE-A events
    req_b = urllib.request.urlopen(f"{running_server}/api/search/SEARCH-CASE-B?q=")
    assert req_b.status == 200
    data_b = json.loads(req_b.read().decode("utf-8"))
    assert len(data_b["results"]) == 1
    assert data_b["results"][0]["event_id"] == "EV-CASE-B-01"

    # 5. Windows path event ID inspection via GET /api/inspect/CASE?event_id=<encoded>
    enc_win = urllib.parse.quote(win_path_id)
    req_insp = urllib.request.urlopen(f"{running_server}/api/inspect/SEARCH-CASE-A?event_id={enc_win}")
    assert req_insp.status == 200
    data_insp = json.loads(req_insp.read().decode("utf-8"))
    assert data_insp["event"]["event_id"] == win_path_id
