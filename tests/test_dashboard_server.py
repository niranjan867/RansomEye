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
    """Test process profile endpoints for existing graph nodes, missing graph nodes, and case isolation."""
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

    # 2. Existing process GUID with percent-encoding resolves successfully (200 OK)
    req_proc = urllib.request.urlopen(f"{running_server}/api/process/PROC-CASE-A/%7BAAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA%7D")
    assert req_proc.status == 200
    proc_data = json.loads(req_proc.read().decode("utf-8"))
    assert str(proc_data["process"]["pid"]) == "2000"
    assert proc_data["process"]["name"] == "powershell.exe"

    # 3. Non-existent process GUID returns 404 cleanly (frontend handles as PROCESS PROFILE UNAVAILABLE)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/PROC-CASE-A/%7BNONEXIST-9999-9999-9999-999999999999%7D")
    assert exc_info.value.code == 404

    # 4. Case isolation: Process in PROC-CASE-A requested under PROC-CASE-B returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/PROC-CASE-B/%7BAAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA%7D")
    assert exc_info.value.code == 404


def test_dashboard_process_guid_resolution_regression(running_server, test_db_path):
    """Regression test: GET /api/process/CASE-RANSOMWARE-DEMO/%7B11111111-2222-3333-4444-555555555555%7D returns 200."""
    sample_file = Path("samples/ransomware_like_activity.json")
    assert sample_file.exists(), "Sample ransomware activity file must exist"

    summary = ingest_evidence(
        database_path=test_db_path,
        case_id="CASE-RANSOMWARE-DEMO",
        file_path=sample_file,
        format_type="auto",
        case_name="Ransomware Demo Case",
        host="VICTIM-PC",
    )
    assert summary["events_accepted"] > 0

    # 1. Percent-encoded braced GUID (%7B...%7D) resolves with 200 OK
    req = urllib.request.urlopen(f"{running_server}/api/process/CASE-RANSOMWARE-DEMO/%7B11111111-2222-3333-4444-555555555555%7D")
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert data["process"]["name"] == "simulated_encryptor.exe"
    assert str(data["process"]["pid"]) == "7777"
    assert data["process"]["guid"] == "{11111111-2222-3333-4444-555555555555}"
    assert data["process"]["command_line"] == "simulated_encryptor.exe --simulate"

    # 2. Raw unbraced GUID resolves with 200 OK
    req_unbraced = urllib.request.urlopen(f"{running_server}/api/process/CASE-RANSOMWARE-DEMO/11111111-2222-3333-4444-555555555555")
    assert req_unbraced.status == 200
    data_unbraced = json.loads(req_unbraced.read().decode("utf-8"))
    assert str(data_unbraced["process"]["pid"]) == "7777"

    # 3. PID query resolves with 200 OK
    req_pid = urllib.request.urlopen(f"{running_server}/api/process/CASE-RANSOMWARE-DEMO/7777")
    assert req_pid.status == 200
    data_pid = json.loads(req_pid.read().decode("utf-8"))
    assert data_pid["process"]["name"] == "simulated_encryptor.exe"

    # 4. Unknown process returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{running_server}/api/process/CASE-RANSOMWARE-DEMO/%7B99999999-9999-9999-9999-999999999999%7D")
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


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_dashboard_case_lifecycle_and_history(running_server, test_db_path):
    """Test case creation, listing, status update, and history tracking."""
    # 1. Create case
    code, res = _post_json(f"{running_server}/api/cases", {
        "case_id": "CASE-TEST-LIFECYCLE",
        "case_name": "Lifecycle Test Case",
        "host": "WIN-SRV-TEST"
    })
    assert code == 201
    assert res["case"]["case_id"] == "CASE-TEST-LIFECYCLE"

    # 2. List cases
    req = urllib.request.urlopen(f"{running_server}/api/cases")
    assert req.status == 200
    cases_data = json.loads(req.read().decode("utf-8"))
    found = [c for c in cases_data["cases"] if c["case_id"] == "CASE-TEST-LIFECYCLE"]
    assert len(found) == 1
    assert found[0]["status"] == "OPEN"

    # 3. Update status
    code, res = _post_json(f"{running_server}/api/case/CASE-TEST-LIFECYCLE/status", {
        "status": "TRIAGED",
        "notes": "Analyst investigating suspicious activity"
    })
    assert code == 200
    assert res["status"] == "TRIAGED"

    # 4. View history
    req = urllib.request.urlopen(f"{running_server}/api/case/CASE-TEST-LIFECYCLE/history")
    assert req.status == 200
    hist_data = json.loads(req.read().decode("utf-8"))
    assert len(hist_data["history"]) >= 1
    assert hist_data["history"][-1]["status"] == "TRIAGED"


def test_dashboard_investigation_and_tree(running_server, test_db_path, tmp_path):
    """Test investigation summary, graph, process tree, and validation endpoints."""
    # Ingest evidence
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-INV-01", "Investigation Case", "HOST-INV")
    store.close()

    ev_file = tmp_path / "inv_events.json"
    ev_file.write_text(json.dumps([
        {
            "event_id": "INV-EV-1",
            "timestamp": "2026-08-25T11:00:00Z",
            "source": "sysmon",
            "event_type": "process_create",
            "process_name": "cmd.exe",
            "pid": 5001,
            "process_guid": "{5001-0000-0000-0000}",
            "command_line": "cmd.exe /c whoami"
        }
    ]), encoding="utf-8")

    code, res = _post_json(f"{running_server}/api/ingest", {
        "case_id": "CASE-INV-01",
        "file_path": str(ev_file)
    })
    assert code == 200
    assert res["events_ingested"] == 1

    # 1. Summary
    req = urllib.request.urlopen(f"{running_server}/api/investigation/CASE-INV-01")
    assert req.status == 200
    inv = json.loads(req.read().decode("utf-8"))
    assert inv["case_id"] == "CASE-INV-01"

    # 2. Graph
    req = urllib.request.urlopen(f"{running_server}/api/investigation/CASE-INV-01/graph")
    assert req.status == 200
    graph = json.loads(req.read().decode("utf-8"))
    assert "nodes" in graph
    assert "edges" in graph

    # 3. Process Tree
    req = urllib.request.urlopen(f"{running_server}/api/tree/CASE-INV-01")
    assert req.status == 200
    tree_data = json.loads(req.read().decode("utf-8"))
    assert "tree" in tree_data

    # 4. Validation
    req = urllib.request.urlopen(f"{running_server}/api/investigation/CASE-INV-01/validation")
    assert req.status == 200
    val_data = json.loads(req.read().decode("utf-8"))
    assert "validation" in val_data


def test_dashboard_custody_and_integrity(running_server, test_db_path, tmp_path):
    """Test custody ledger recording and integrity manifest hash/verify endpoints."""
    # Custody
    code, res = _post_json(f"{running_server}/api/cases", {
        "case_id": "CASE-CUSTODY-01",
        "case_name": "Custody Case"
    })
    assert code == 201

    sample_art = tmp_path / "sample_artifact.bin"
    sample_art.write_bytes(b"forensic evidence sample 12345")

    code, res = _post_json(f"{running_server}/api/custody/CASE-CUSTODY-01", {
        "artifact": str(sample_art),
        "action": "COLLECTED",
        "analyst": "Forensic Analyst Alpha",
        "notes": "Disk image collected at scene"
    })
    assert code == 201
    assert res["entry"]["action"] == "COLLECTED"

    req = urllib.request.urlopen(f"{running_server}/api/custody/CASE-CUSTODY-01")
    assert req.status == 200
    custody_data = json.loads(req.read().decode("utf-8"))
    assert len(custody_data["entries"]) == 1
    assert custody_data["entries"][0]["analyst"] == "Forensic Analyst Alpha"

    # Integrity Hash
    man_path = tmp_path / "test_manifest.txt"
    code, res = _post_json(f"{running_server}/api/integrity/hash", {
        "target_path": str(sample_art),
        "manifest_path": str(man_path)
    })
    assert code == 200
    assert "manifest_path" in res

    # Integrity Verify (should pass)
    code, res = _post_json(f"{running_server}/api/integrity/verify", {
        "target_path": str(sample_art),
        "manifest_path": str(man_path)
    })
    assert code == 200
    assert res["verified"] is True


def test_dashboard_export_and_lock(running_server, test_db_path, tmp_path):
    """Test export generation and concurrency lock management."""
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-EXPORT-01", "Export Case")
    store.close()

    out_dir = tmp_path / "exports"
    code, res = _post_json(f"{running_server}/api/export", {
        "case_id": "CASE-EXPORT-01",
        "output_dir": str(out_dir)
    })
    assert code == 200
    assert "export_path" in res

    # Check lock
    req = urllib.request.urlopen(f"{running_server}/api/export/lock?case_id=CASE-EXPORT-01")
    assert req.status == 200
    lock_info = json.loads(req.read().decode("utf-8"))
    assert "locked" in lock_info

    # Safe unlock
    code, res = _post_json(f"{running_server}/api/export/unlock", {
        "case_id": "CASE-EXPORT-01"
    })
    assert code == 200


def test_dashboard_database_maintenance(running_server, test_db_path, tmp_path):
    """Test database integrity check, online backup, and safe restore endpoints."""
    # 1. Check
    code, res = _post_json(f"{running_server}/api/database/check", {})
    assert code == 200
    assert res["status"] == "OK"

    # 2. Backup
    bkp_path = tmp_path / "backup_test.db"
    code, res = _post_json(f"{running_server}/api/database/backup", {
        "backup_path": str(bkp_path)
    })
    assert code == 200
    assert bkp_path.is_file()

    # 3. Restore
    code, res = _post_json(f"{running_server}/api/database/restore", {
        "backup_path": str(bkp_path),
        "target_path": str(tmp_path / "restored_test.db"),
        "confirm": True
    })
    assert code == 200
    assert res["status"] == "OK"


def test_dashboard_static_and_phishing_analysis(running_server, tmp_path):
    """Test static PE analyzer and phishing message analysis endpoints."""
    # Static analysis on a small file
    test_exe = tmp_path / "test_artifact.exe"
    test_exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

    code, res = _post_json(f"{running_server}/api/static/analyze", {
        "file_path": str(test_exe)
    })
    assert code == 200
    assert "analysis" in res
    assert "sha256" in res["analysis"]

    # Phishing analysis
    code, res = _post_json(f"{running_server}/api/phishing/analyze", {
        "subject": "Urgent password reset required immediately",
        "sender": "support@bank-security-login.xyz",
        "body": "Dear customer, your account has been suspended. Click here to verify your credentials: http://phish.xyz/login"
    })
    assert code == 200
    assert "assessment" in res
    assert res["assessment"]["threat_level"] in ("HIGH", "CRITICAL", "MEDIUM", "LOW", "SUSPICIOUS")


def test_dashboard_static_analysis_ingests_into_case(running_server, test_db_path, tmp_path):
    """Static analysis with a case_id must persist a linked finding and custody record."""
    store = EvidenceStore(test_db_path)
    try:
        store.create_case("CASE-STATIC-API", "Static API Case")
    finally:
        store.close()

    artifact = tmp_path / "ransom_artifact.bin"
    artifact.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"HOW_TO_DECRYPT your files RANSOM note")

    code, res = _post_json(f"{running_server}/api/static/analyze", {
        "file_path": str(artifact),
        "case_id": "CASE-STATIC-API",
    })
    assert code == 200, res
    assert isinstance(res["finding_id"], int)

    store = EvidenceStore(test_db_path)
    try:
        findings = store.get_case_findings("CASE-STATIC-API")
        custody = store.get_custody_events("CASE-STATIC-API")
    finally:
        store.close()

    assert [f["finding_type"] for f in findings] == ["static_file_analysis"]
    assert len(findings[0]["event_ids"]) == 1
    assert [c["action"] for c in custody] == ["reviewed"]
    assert custody[0]["sha256"] == res["analysis"]["sha256"]


def _static_view_source() -> str:
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    start = app_js.index("function initStatic()")
    end = app_js.index("\n// ====", start)
    return app_js[start:end]


def test_static_view_reads_fields_the_backend_returns():
    """Every analysis/section field the Static Analysis view reads must exist in the backend payload."""
    from dataclasses import fields
    import re
    from ransomeye.static_analyzer import PESection, StaticAnalyzer

    source = _static_view_source()
    analysis_keys = set(StaticAnalyzer().analyze_bytes(b"MZ" + b"\x00" * 62).to_dict())
    section_keys = {f.name for f in fields(PESection)}

    read_analysis = set(re.findall(r"\ba\.(\w+)", source))
    read_section = set(re.findall(r"\bsec\.(\w+)", source))

    assert {"file_size", "total_entropy", "suspicious_apis", "extracted_iocs", "sections"} <= read_analysis
    assert read_analysis <= analysis_keys, read_analysis - analysis_keys
    assert read_section and read_section <= section_keys, read_section - section_keys


def test_static_view_never_renders_analyzer_output_as_html():
    """XSS regression: analyzer output (section names, API names, keywords, paths) is attacker-controlled."""
    source = _static_view_source()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in source, f"{sink} used in Static Analysis view"
    assert "${" not in source, "HTML/template string construction in Static Analysis view"


# --------------------------------------------------------------------------- #
# Stage 4: POST /api/script/analyze
# --------------------------------------------------------------------------- #

import base64 as _b64  # noqa: E402


def _enc_command(inner: str = "Invoke-Expression $x") -> str:
    return "powershell -enc " + _b64.b64encode(inner.encode("utf-16-le")).decode("ascii")


def _script_url(running_server: str) -> str:
    return f"{running_server}/api/script/analyze"


def test_api_script_text_analysis(running_server):
    code, res = _post_json(_script_url(running_server), {"text": "Invoke-Expression $x"})
    assert code == 200, res
    assert res["analysis"]["analysis_status"] == "complete"
    assert "PS-IEX-003" in {i["rule_id"] for i in res["analysis"]["indicators"]}
    assert res["finding_ids"] is None  # no case -> analysis only


def test_api_script_file_analysis_without_case(running_server, tmp_path):
    target = tmp_path / "s.ps1"
    target.write_text("vssadmin delete shadows /all /quiet\n", encoding="utf-8")
    code, res = _post_json(_script_url(running_server), {"file_path": str(target)})
    assert code == 200, res
    assert "REC-010" in {i["rule_id"] for i in res["analysis"]["indicators"]}
    assert res["finding_ids"] is None


def test_api_script_file_ingests_into_case(running_server, test_db_path, tmp_path):
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-API-SCRIPT", "api script")
    store.close()

    target = tmp_path / "mal.ps1"
    target.write_text(f"{_enc_command()}\nvssadmin delete shadows /all /quiet\n", encoding="utf-8")
    code, res = _post_json(_script_url(running_server), {
        "file_path": str(target), "case_id": "CASE-API-SCRIPT",
    })
    assert code == 200, res
    assert isinstance(res["finding_ids"], list) and res["finding_ids"]

    store = EvidenceStore(test_db_path)
    try:
        events = store.get_case_events("CASE-API-SCRIPT")
        findings = store.get_case_findings("CASE-API-SCRIPT")
        custody = store.get_custody_events("CASE-API-SCRIPT")
    finally:
        store.close()
    assert len(events) == 1 and events[0]["source"] == "script_analyzer"
    assert len(findings) == len(res["finding_ids"])
    assert [c["action"] for c in custody] == ["reviewed"]


def test_api_script_file_ingest_is_idempotent(running_server, test_db_path, tmp_path):
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-API-IDEM", "idem")
    store.close()
    target = tmp_path / "idem.ps1"
    target.write_text("Invoke-Expression $x\n", encoding="utf-8")

    body = {"file_path": str(target), "case_id": "CASE-API-IDEM"}
    first = _post_json(_script_url(running_server), body)[1]
    second = _post_json(_script_url(running_server), body)[1]
    assert first["finding_ids"] and second["finding_ids"] == []

    store = EvidenceStore(test_db_path)
    try:
        assert len(store.get_case_events("CASE-API-IDEM")) == 1
        assert len(store.get_case_findings("CASE-API-IDEM")) == len(first["finding_ids"])
    finally:
        store.close()


def test_api_script_event_mode(running_server, test_db_path):
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-API-EVT", "evt")
    store.save_event("CASE-API-EVT", {
        "event_id": "EVT-API-1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": _enc_command(),
    })
    store.close()

    code, res = _post_json(_script_url(running_server), {
        "event_id": "EVT-API-1", "case_id": "CASE-API-EVT",
    })
    assert code == 200, res
    assert res["finding_ids"]

    store = EvidenceStore(test_db_path)
    try:
        assert [e["event_id"] for e in store.get_case_events("CASE-API-EVT")] == ["EVT-API-1"]
        assert store.get_custody_events("CASE-API-EVT") == []
    finally:
        store.close()


def test_api_script_text_with_case_is_refused(running_server, test_db_path):
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-API-TXT", "txt")
    store.close()
    code, res = _post_json(_script_url(running_server), {
        "text": "Invoke-Expression $x", "case_id": "CASE-API-TXT",
    })
    assert code == 400
    assert "cannot be added to a case" in res["error"]

    store = EvidenceStore(test_db_path)
    try:
        assert store.get_case_findings("CASE-API-TXT") == []
    finally:
        store.close()


def test_api_script_requires_exactly_one_input(running_server):
    code, res = _post_json(_script_url(running_server), {})
    assert code == 400 and "exactly one" in res["error"]

    code, res = _post_json(_script_url(running_server), {"text": "x", "file_path": "a.ps1"})
    assert code == 400 and "exactly one" in res["error"]


def test_api_script_event_requires_case(running_server):
    code, res = _post_json(_script_url(running_server), {"event_id": "EVT-X"})
    # event_id alone is the single input, but needs a case.
    assert code == 400 and "requires case_id" in res["error"]


def test_api_script_unknown_case(running_server, test_db_path, tmp_path):
    # Database exists (with a different case), but the requested case is absent.
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-OTHER", "other")
    store.close()
    target = tmp_path / "s.ps1"
    target.write_text("Invoke-Expression $x\n", encoding="utf-8")
    code, res = _post_json(_script_url(running_server), {
        "file_path": str(target), "case_id": "NO_SUCH_CASE",
    })
    assert code == 404 and "Case not found" in res["error"]


def test_api_script_unknown_event(running_server, test_db_path):
    store = EvidenceStore(test_db_path)
    store.create_case("CASE-API-NOEVT", "noevt")
    store.close()
    code, res = _post_json(_script_url(running_server), {
        "event_id": "MISSING", "case_id": "CASE-API-NOEVT",
    })
    assert code == 404 and "Event not found" in res["error"]


def test_api_script_missing_file(running_server, tmp_path):
    code, res = _post_json(_script_url(running_server), {"file_path": str(tmp_path / "nope.ps1")})
    assert code == 400 and "not found" in res["error"].lower()


def test_api_script_unsupported_container_not_clean(running_server, tmp_path):
    target = tmp_path / "doc.docm"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    code, res = _post_json(_script_url(running_server), {"file_path": str(target)})
    assert code == 200
    assert res["analysis"]["analysis_status"] == "unsupported_container"
    assert res["analysis"]["severity"] == "NOT_ANALYZED"


@pytest.mark.parametrize("bad_path", [
    r"\\server\share\x.ps1",
    r"\\?\C:\x.ps1",
    r"\\.\PhysicalDrive0",
])
def test_api_script_unc_and_device_paths_rejected(running_server, bad_path):
    code, res = _post_json(_script_url(running_server), {"file_path": bad_path})
    assert code == 400 and "UNC" in res["error"]


def test_api_script_invalid_language(running_server):
    code, res = _post_json(_script_url(running_server), {"text": "x", "language": "perl"})
    assert code == 400 and "Unsupported language" in res["error"]


def test_api_script_malformed_json_body(running_server):
    # Body that is not valid JSON is treated as empty -> exactly-one-input error.
    req = urllib.request.Request(
        _script_url(running_server), data=b"{not json", method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            code, res = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        code, res = e.code, json.loads(e.read())
    assert code == 400 and "exactly one" in res["error"]


def test_api_script_response_is_deterministic(running_server):
    body = {"text": f"{_enc_command()}\nvssadmin delete shadows"}
    first = _post_json(_script_url(running_server), body)[1]["analysis"]
    second = _post_json(_script_url(running_server), body)[1]["analysis"]
    assert first == second


def test_api_script_attacker_strings_are_json_data_not_markup(running_server):
    # An attacker-controlled URL containing HTML must round-trip as JSON data,
    # not break the response or appear interpreted.
    payload = 'Invoke-WebRequest "http://evil.invalid/</script><img src=x onerror=alert(1)>"'
    code, res = _post_json(_script_url(running_server), {"text": payload})
    assert code == 200
    blob = json.dumps(res)
    assert "<img src=x" in blob  # preserved verbatim as data
    # It is present only inside string values, never as a structural element.
    assert res["analysis"]["analysis_status"] == "complete"


def _script_view_source() -> str:
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    start = app_js.index("function scriptEl(")
    end = app_js.index("\n// ==", app_js.index("function initScript("))
    return app_js[start:end]


def test_script_view_never_uses_html_sinks():
    """XSS regression: the Script Analysis view must build DOM nodes, not HTML strings."""
    source = _script_view_source()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in source, f"{sink} used in Script Analysis view"


def test_script_view_reads_fields_the_api_returns(running_server):
    """Top-level analysis fields the view reads must exist in the API response."""
    code, res = _post_json(_script_url(running_server), {"text": f"{_enc_command()}\nvssadmin delete shadows"})
    assert code == 200
    analysis = res["analysis"]
    for key in ("analysis_status", "severity", "score", "confidence", "language",
                "file_size", "sha256", "decoded_layers", "indicators", "techniques", "iocs", "warnings"):
        assert key in analysis, key
    assert "finding_ids" in res
    ind = analysis["indicators"][0]
    for key in ("rule_id", "title", "severity", "technique", "layer_index", "line", "excerpt", "category"):
        assert key in ind, key
    layer = analysis["decoded_layers"][0]
    for key in ("index", "depth", "parent_index", "method", "size", "is_text", "encoding", "preview", "sha256"):
        assert key in layer, key


def test_script_view_registered_in_nav_and_router():
    static_dir = Path(dashboard_server.__file__).parent / "static"
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    app_js = (static_dir / "app.js").read_text(encoding="utf-8")
    assert 'data-view="script"' in html
    assert 'id="tpl-script"' in html
    assert "case 'script': initScript();" in app_js
    assert "'script'" in app_js.split("const GLOBAL_VIEWS")[1].split("]")[0]
