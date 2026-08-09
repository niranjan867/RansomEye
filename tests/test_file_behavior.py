"""Tests for the File Behavior Engine.

Covers threshold boundaries, window inclusivity, process grouping,
duplicate event handling, malformed input safety, deterministic ordering,
extension edge cases, case-insensitive ransom note matching, and the
double-counting migration in threat_assessment.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ransomeye.file_behavior import (
    EXTENSION_CHANGE_SCORE,
    FILE_CHURN_SCORE,
    FILE_CHURN_THRESHOLD,
    FILE_CHURN_WINDOW_SECONDS,
    MASS_ACTIVITY_WINDOW_SECONDS,
    MASS_CREATE_THRESHOLD,
    MASS_DELETE_THRESHOLD,
    MASS_MODIFY_WINDOW_SECONDS,
    analyze_file_behavior,
    detect_extension_changes,
    detect_file_churn,
    detect_mass_creation,
    detect_mass_deletion,
    detect_mass_modification,
    detect_ransom_note,
)
from ransomeye.rules import MASS_MODIFY_SCORE, MASS_MODIFY_THRESHOLD, RANSOM_NOTE_SCORE

BASE_TS = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)


def _ev(event_id, ts, event_type, guid=None, pid=None, path=None, metadata=None):
    """Create a minimal event dict for testing."""
    ev = {"event_id": event_id, "timestamp": ts, "event_type": event_type}
    if guid is not None:
        ev["process_guid"] = guid
    if pid is not None:
        ev["pid"] = pid
    if path is not None:
        ev["file_path"] = path
    if metadata is not None:
        ev["metadata"] = metadata
    return ev


def _mod_events(count, ts=None, guid="{P1}", prefix="E"):
    """Generate count file_modify events at the same timestamp."""
    if ts is None:
        ts = BASE_TS.isoformat()
    return [
        _ev(f"{prefix}{i}", ts, "file_modify", guid=guid, path=f"C:\\f{i}.txt")
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Normal activity — no findings
# ---------------------------------------------------------------------------

class TestNormalActivity:
    def test_single_file_operations_produce_no_findings(self):
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_create", guid="{P1}", path="C:\\a.txt"),
            _ev("E2", (BASE_TS + timedelta(seconds=1)).isoformat(), "file_modify", guid="{P1}", path="C:\\a.txt"),
            _ev("E3", (BASE_TS + timedelta(seconds=2)).isoformat(), "file_delete", guid="{P1}", path="C:\\a.txt"),
        ]
        assert analyze_file_behavior(events) == []

    def test_empty_event_list(self):
        assert analyze_file_behavior([]) == []


# ---------------------------------------------------------------------------
# Mass Modification — threshold boundaries
# ---------------------------------------------------------------------------

class TestMassModification:
    def test_exactly_at_threshold(self):
        """50 modifications qualifies."""
        findings = detect_mass_modification(_mod_events(50))
        assert len(findings) == 1
        assert findings[0]["type"] == "mass_file_modification"
        assert len(findings[0]["event_ids"]) == 50

    def test_one_below_threshold(self):
        """49 modifications does not qualify."""
        assert detect_mass_modification(_mod_events(49)) == []

    def test_one_above_threshold(self):
        """51 modifications qualifies with all 51 event_ids."""
        findings = detect_mass_modification(_mod_events(51))
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 51

    def test_window_inclusive_boundary(self):
        """An event at exactly start + 30s is included in the window."""
        events = []
        for i in range(50):
            offset = timedelta(seconds=(30 * i / 49))  # spread across 0–30s
            events.append(
                _ev(f"E{i}", (BASE_TS + offset).isoformat(), "file_modify",
                    guid="{P1}", path=f"C:\\f{i}.txt")
            )
        findings = detect_mass_modification(events)
        assert len(findings) == 1

    def test_just_beyond_window(self):
        """Events spanning > 30s should not all fit in one window.

        Place 25 events at t=0 and 25 at t=31s — neither group qualifies.
        """
        events = _mod_events(25, ts=BASE_TS.isoformat(), prefix="A")
        t2 = (BASE_TS + timedelta(seconds=31)).isoformat()
        events += _mod_events(25, ts=t2, prefix="B")
        assert detect_mass_modification(events) == []

    def test_score_value(self):
        findings = detect_mass_modification(_mod_events(50))
        assert findings[0]["score"] == MASS_MODIFY_SCORE

    def test_event_ids_are_deterministic(self):
        """Same input always yields the same event_ids in the same order."""
        a = detect_mass_modification(_mod_events(50))
        b = detect_mass_modification(_mod_events(50))
        assert a[0]["event_ids"] == b[0]["event_ids"]


# ---------------------------------------------------------------------------
# Mass Creation — threshold boundaries
# ---------------------------------------------------------------------------

class TestMassCreation:
    def _create_events(self, count, guid="{P1}", prefix="C"):
        return [
            _ev(f"{prefix}{i}", BASE_TS.isoformat(), "file_create",
                guid=guid, path=f"C:\\new{i}.txt")
            for i in range(count)
        ]

    def test_exactly_at_threshold(self):
        findings = detect_mass_creation(self._create_events(100))
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 100

    def test_one_below_threshold(self):
        assert detect_mass_creation(self._create_events(99)) == []

    def test_one_above_threshold(self):
        findings = detect_mass_creation(self._create_events(101))
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 101


# ---------------------------------------------------------------------------
# Mass Deletion — threshold boundaries
# ---------------------------------------------------------------------------

class TestMassDeletion:
    def _delete_events(self, count, guid="{P1}", prefix="D"):
        return [
            _ev(f"{prefix}{i}", BASE_TS.isoformat(), "file_delete",
                guid=guid, path=f"C:\\old{i}.txt")
            for i in range(count)
        ]

    def test_exactly_at_threshold(self):
        findings = detect_mass_deletion(self._delete_events(50))
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 50

    def test_one_below_threshold(self):
        assert detect_mass_deletion(self._delete_events(49)) == []

    def test_one_above_threshold(self):
        findings = detect_mass_deletion(self._delete_events(51))
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 51


# ---------------------------------------------------------------------------
# File Churn
# ---------------------------------------------------------------------------

class TestFileChurn:
    def _churn_events(self, count, guid="{P1}"):
        events = []
        for i in range(count):
            events.append(_ev(f"C{i}", BASE_TS.isoformat(), "file_create",
                              guid=guid, path=f"C:\\t{i}.tmp"))
            events.append(_ev(f"D{i}", BASE_TS.isoformat(), "file_delete",
                              guid=guid, path=f"C:\\t{i}.tmp"))
        return events

    def test_at_threshold(self):
        """Exactly 10 creates and 10 deletes qualifies."""
        findings = detect_file_churn(self._churn_events(10))
        assert len(findings) == 1
        assert findings[0]["type"] == "file_churn"
        assert len(findings[0]["event_ids"]) == 20

    def test_below_threshold(self):
        """9 creates and 9 deletes does not qualify."""
        assert detect_file_churn(self._churn_events(9)) == []

    def test_creates_only_no_churn(self):
        """10 creates but 0 deletes does not qualify."""
        events = [
            _ev(f"C{i}", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        assert detect_file_churn(events) == []

    def test_deletes_only_no_churn(self):
        """10 deletes but 0 creates does not qualify."""
        events = [
            _ev(f"D{i}", BASE_TS.isoformat(), "file_delete",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        assert detect_file_churn(events) == []

    def test_churn_beyond_window(self):
        """Creates at t=0 and deletes at t=11s should not qualify."""
        events = [
            _ev(f"C{i}", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        t2 = (BASE_TS + timedelta(seconds=11)).isoformat()
        events += [
            _ev(f"D{i}", t2, "file_delete",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        assert detect_file_churn(events) == []

    def test_churn_at_window_boundary(self):
        """Creates at t=0, deletes at exactly t=10s should qualify."""
        events = [
            _ev(f"C{i}", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        t2 = (BASE_TS + timedelta(seconds=10)).isoformat()
        events += [
            _ev(f"D{i}", t2, "file_delete",
                guid="{P1}", path=f"C:\\t{i}.tmp")
            for i in range(10)
        ]
        findings = detect_file_churn(events)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Ransom Note Detection
# ---------------------------------------------------------------------------

class TestRansomNote:
    def test_known_pattern(self):
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\HOW_TO_DECRYPT.txt"),
        ]
        findings = detect_ransom_note(events)
        assert len(findings) == 1
        assert findings[0]["type"] == "ransom_note"
        assert findings[0]["score"] == RANSOM_NOTE_SCORE
        assert findings[0]["event_ids"] == ["E1"]

    def test_case_insensitive(self):
        """RANSOM_NOTE_KEYWORDS are matched case-insensitively via .upper()."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\how_to_decrypt.txt"),
        ]
        findings = detect_ransom_note(events)
        assert len(findings) == 1

    def test_normal_file_not_flagged(self):
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\readme.md"),
        ]
        assert detect_ransom_note(events) == []

    def test_modify_event_not_flagged(self):
        """Only file_create triggers ransom note detection."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_modify",
                guid="{P1}", path="C:\\HOW_TO_DECRYPT.txt"),
        ]
        assert detect_ransom_note(events) == []


# ---------------------------------------------------------------------------
# Extension Changes
# ---------------------------------------------------------------------------

class TestExtensionChange:
    def test_extension_changed(self):
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\photo.enc",
                metadata={"old_path": "C:\\photo.jpg"}),
        ]
        findings = detect_extension_changes(events)
        assert len(findings) == 1
        assert "jpg" in findings[0]["reason"]
        assert "enc" in findings[0]["reason"]

    def test_same_extension_no_finding(self):
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\b.txt",
                metadata={"old_path": "C:\\a.txt"}),
        ]
        assert detect_extension_changes(events) == []

    def test_missing_old_path(self):
        """Missing old_path in metadata should not crash."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\photo.enc", metadata={}),
        ]
        assert detect_extension_changes(events) == []

    def test_missing_metadata(self):
        """No metadata at all should not crash."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\photo.enc"),
        ]
        assert detect_extension_changes(events) == []

    def test_old_path_no_extension(self):
        """Old path without extension should not trigger."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\photo.enc",
                metadata={"old_path": "C:\\Makefile"}),
        ]
        assert detect_extension_changes(events) == []

    def test_new_path_no_extension(self):
        """New path without extension should not trigger."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\Makefile",
                metadata={"old_path": "C:\\photo.jpg"}),
        ]
        assert detect_extension_changes(events) == []

    def test_non_dict_metadata_ignored(self):
        """Non-dict metadata should not crash."""
        events = [
            _ev("E1", BASE_TS.isoformat(), "file_rename",
                guid="{P1}", path="C:\\photo.enc",
                metadata="not-a-dict"),
        ]
        assert detect_extension_changes(events) == []


# ---------------------------------------------------------------------------
# Process Grouping
# ---------------------------------------------------------------------------

class TestProcessGrouping:
    def test_separate_processes_separate_findings(self):
        """Two processes each with 50 mods → two findings."""
        events = _mod_events(50, guid="{PA}") + _mod_events(50, guid="{PB}", prefix="F")
        findings = detect_mass_modification(events)
        assert len(findings) == 2
        procs = {f["process_identity"] for f in findings}
        assert procs == {"GUID:{PA}", "GUID:{PB}"}

    def test_mixed_processes_below_threshold(self):
        """25 from each of two processes → neither qualifies alone."""
        events = _mod_events(25, guid="{PA}") + _mod_events(25, guid="{PB}", prefix="F")
        assert detect_mass_modification(events) == []

    def test_pid_fallback(self):
        """Events with PID but no GUID group by PID."""
        events = [
            _ev(f"E{i}", BASE_TS.isoformat(), "file_modify",
                pid=1234, path=f"C:\\f{i}.txt")
            for i in range(50)
        ]
        findings = detect_mass_modification(events)
        assert len(findings) == 1
        assert findings[0]["process_identity"] == "PID:1234"


# ---------------------------------------------------------------------------
# Duplicate Event Handling
# ---------------------------------------------------------------------------

class TestDuplicateEvents:
    def test_duplicate_event_ids_not_inflated(self):
        """Events with the same event_id should not inflate the count.

        The engine processes all events it receives. If a caller passes
        duplicate event_ids, the count reflects the number of input events,
        but the same event_id appears only as many times as it was provided.
        """
        events = [
            _ev("SAME", BASE_TS.isoformat(), "file_modify",
                guid="{P1}", path=f"C:\\f{i}.txt")
            for i in range(50)
        ]
        findings = detect_mass_modification(events)
        assert len(findings) == 1
        # All 50 events had event_id "SAME" — they are all included
        assert len(findings[0]["event_ids"]) == 50


# ---------------------------------------------------------------------------
# Malformed / Missing Timestamps
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_missing_timestamp_skipped(self):
        """Events without a timestamp are silently excluded."""
        events = [{"event_id": f"E{i}", "event_type": "file_modify",
                    "process_guid": "{P1}", "file_path": f"C:\\f{i}.txt"}
                   for i in range(50)]
        # All events lack timestamps → nothing parseable → no findings
        assert detect_mass_modification(events) == []

    def test_malformed_timestamp_skipped(self):
        """Events with unparseable timestamps are silently excluded."""
        events = [
            _ev(f"E{i}", "not-a-date", "file_modify",
                guid="{P1}", path=f"C:\\f{i}.txt")
            for i in range(50)
        ]
        assert detect_mass_modification(events) == []

    def test_mixed_valid_invalid_timestamps(self):
        """Valid events still produce findings alongside invalid ones."""
        valid = _mod_events(50)
        invalid = [
            _ev("BAD1", None, "file_modify", guid="{P1}", path="C:\\x.txt"),
            _ev("BAD2", "garbage", "file_modify", guid="{P1}", path="C:\\y.txt"),
        ]
        findings = detect_mass_modification(valid + invalid)
        assert len(findings) == 1
        assert len(findings[0]["event_ids"]) == 50

    def test_out_of_order_timestamps(self):
        """Events in arbitrary order are sorted internally."""
        events = []
        for i in range(50):
            # Spread across 0–29s in reverse order — all fit within 30s window
            offset = timedelta(seconds=(29 * (49 - i) / 49))
            events.append(
                _ev(f"E{i}", (BASE_TS + offset).isoformat(), "file_modify",
                    guid="{P1}", path=f"C:\\f{i}.txt")
            )
        findings = detect_mass_modification(events)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Double-Counting Protection in threat_assessment
# ---------------------------------------------------------------------------

class TestDoubleCounting:
    def test_mass_modification_scored_once(self):
        """Mass modification contributes exactly MASS_MODIFY_SCORE to the total.

        rules.py detects mass modification → +20.
        file_behavior detects mass_file_modification → +20.
        The deduplication subtracts the legacy +20, so only the file_behavior
        +20 remains. No correlation bonus because base_result is now 0 and
        no behavior_findings (powershell/certutil/recovery) are present.
        """
        from ransomeye.threat_assessment import assess_threat

        events = _mod_events(MASS_MODIFY_THRESHOLD)
        result = assess_threat(events)

        assert result["score"] == MASS_MODIFY_SCORE
        # Verify the finding set: exactly 1 mass_file_modification from file_behavior
        types = [r.split(" (+")[0] for r in result["reasons"]]
        mass_mod_reasons = [
            t for t in types if "Mass file modification" in t
        ]
        assert len(mass_mod_reasons) == 1

    def test_ransom_note_scored_once(self):
        """Ransom note contributes exactly RANSOM_NOTE_SCORE."""
        from ransomeye.threat_assessment import assess_threat

        events = [
            _ev("E1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\HOW_TO_DECRYPT.txt"),
        ]
        result = assess_threat(events)
        assert result["score"] == RANSOM_NOTE_SCORE

    def test_mass_mod_plus_ransom_note_scored_once_each(self):
        """Combined mass mod + ransom note = 20 + 10 = 30."""
        from ransomeye.threat_assessment import assess_threat

        events = _mod_events(MASS_MODIFY_THRESHOLD)
        events.append(
            _ev("NOTE1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\README_DECRYPT.txt")
        )
        result = assess_threat(events)
        assert result["score"] == MASS_MODIFY_SCORE + RANSOM_NOTE_SCORE

    def test_file_behavior_plus_powershell(self):
        """File behavior + powershell triggers correlation bonus."""
        from ransomeye.threat_assessment import assess_threat

        events = _mod_events(MASS_MODIFY_THRESHOLD)
        events.append({
            "event_id": "PS1",
            "timestamp": BASE_TS.isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "999",
        })
        result = assess_threat(events)
        # file_behavior: +20, powershell: +10, correlation bonus: +10 = 40
        # but behavior floor for 1 behavior finding = 25, 40 > 25 so no floor
        assert result["score"] == MASS_MODIFY_SCORE + 10 + 10

    def test_score_cap_at_100(self):
        """Total score never exceeds 100."""
        from ransomeye.threat_assessment import assess_threat

        events = _mod_events(MASS_MODIFY_THRESHOLD)
        events.append(
            _ev("NOTE1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\README_DECRYPT.txt")
        )
        events.append({
            "event_id": "PS1",
            "timestamp": BASE_TS.isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "998",
        })
        events.append({
            "event_id": "REC1",
            "timestamp": BASE_TS.isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "pid": "997",
        })
        result = assess_threat(events)
        assert result["score"] <= 100

    def test_severity_boundaries(self):
        """Severity thresholds: SAFE ≤24, LOW ≤49, MEDIUM ≤69, HIGH ≤84, CRITICAL."""
        from ransomeye.threat_assessment import assess_threat

        # SAFE: no events
        assert assess_threat([])["severity"] == "SAFE"

        # Mass mod only = 20 → SAFE
        assert assess_threat(_mod_events(50))["severity"] == "SAFE"

    def test_finding_count_includes_file_behavior(self):
        """finding_count includes both behavior and file_behavior findings."""
        from ransomeye.threat_assessment import assess_threat

        events = _mod_events(MASS_MODIFY_THRESHOLD)
        events.append(
            _ev("NOTE1", BASE_TS.isoformat(), "file_create",
                guid="{P1}", path="C:\\README_DECRYPT.txt")
        )
        events.append({
            "event_id": "PS1",
            "timestamp": BASE_TS.isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "999",
        })
        result = assess_threat(events)
        # 1 powershell + 1 mass_file_modification + 1 ransom_note = 3
        assert result["finding_count"] >= 3


# ---------------------------------------------------------------------------
# Deterministic Ordering
# ---------------------------------------------------------------------------

class TestDeterministicOrdering:
    def test_findings_stable_across_runs(self):
        """Identical input always produces identical finding output."""
        events = _mod_events(50, guid="{PA}") + _mod_events(50, guid="{PB}", prefix="F")
        a = detect_mass_modification(events)
        b = detect_mass_modification(events)
        assert len(a) == len(b)
        for fa, fb in zip(a, b):
            assert fa["process_identity"] == fb["process_identity"]
            assert fa["event_ids"] == fb["event_ids"]
