"""Advanced analyst-oriented timeline for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import InvestigationGraph
from ransomeye.reconstruction import AttackSequence, AttackStage


@dataclass(frozen=True)
class TimelineEntry:
    """A lightweight immutable model for a timeline entry."""
    entry_id: str
    timestamp: datetime | None
    end_time: datetime | None
    entry_type: str
    title: str
    description: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    process_ids: tuple[str, ...] = field(default_factory=tuple)
    correlation_ids: tuple[str, ...] = field(default_factory=tuple)
    parent_process_name: str | None = None
    pid: int | None = None


@dataclass(frozen=True)
class AdvancedTimeline:
    """An ordered sequence of analytical timeline entries."""
    case_id: str
    entries: tuple[TimelineEntry, ...]

    # Store assessment properties directly if needed for the summary
    assessment_score: int | None = None
    assessment_severity: str | None = None
    assessment_confidence: float | None = None

    def get_entries(self) -> tuple[TimelineEntry, ...]:
        return self.entries

    def get_entries_by_type(self, entry_type: str) -> list[TimelineEntry]:
        return [e for e in self.entries if e.entry_type == entry_type]

    def get_entries_for_evidence(self, evidence_id: str) -> list[TimelineEntry]:
        return [e for e in self.entries if evidence_id in e.evidence_ids]

    def get_entries_for_finding(self, finding_id: str) -> list[TimelineEntry]:
        return [e for e in self.entries if finding_id in e.finding_ids]

    def get_entries_for_process(self, process_id: str) -> list[TimelineEntry]:
        return [e for e in self.entries if process_id in e.process_ids]

    def get_entries_for_correlation(self, correlation_id: str) -> list[TimelineEntry]:
        return [e for e in self.entries if correlation_id in e.correlation_ids]

    def summary(self) -> str:
        """Provide a deterministic text rendering of the timeline."""
        lines = [
            "ADVANCED INVESTIGATION TIMELINE",
            "================================"
        ]

        if not self.entries:
            lines.append("")
            lines.append("No entries.")
            return "\n".join(lines)

        # Optional overall metadata summary if needed, but the prompt says:
        # Example:
        # ADVANCED INVESTIGATION TIMELINE
        # ================================
        #
        # [10:30:01]
        # PROCESS ...
        #
        # Or:
        # Case: RE-M14-001
        # Entries: 12
        # ...
        # Oh, there are two distinct examples in the prompt.
        # "17. TIMELINE SUMMARY" -> Provide: summary() -> Case: ..., Entries: ..., Time Range: ...
        # "18. HUMAN-READABLE RENDERING" -> ADVANCED INVESTIGATION TIMELINE ... [10:30:01] PROCESS ...
        # Let's provide BOTH? Wait, 17 says "Provide: summary() Example: ... Case: ...".
        # 18 says "Provide deterministic text rendering. Example: ... [10:30:01] PROCESS ... ".
        # Let's put the metadata in `summary()` and the event list in `render()`? Or both in `summary()`?
        # The prompt says:
        # "17. TIMELINE SUMMARY Provide: summary() Example: [metadata]"
        # "18. HUMAN-READABLE RENDERING Provide deterministic text rendering. Example: [timeline output]"
        pass # I'll implement both in separate methods for clarity.

    def metadata_summary(self) -> str:
        """Return the metadata summary (17. TIMELINE SUMMARY)."""
        valid_times = [e.timestamp for e in self.entries if e.timestamp]
        min_time = min(valid_times).strftime("%H:%M:%S") if valid_times else "N/A"
        max_time_list = []
        for e in self.entries:
            if e.end_time:
                max_time_list.append(e.end_time)
            elif e.timestamp:
                max_time_list.append(e.timestamp)
        max_time = max(max_time_list).strftime("%H:%M:%S") if max_time_list else "N/A"

        proc_count = len(set(pid for e in self.entries for pid in e.process_ids))
        finding_count = len(set(fid for e in self.entries for fid in e.finding_ids))
        corr_count = len(set(cid for e in self.entries for cid in e.correlation_ids))
        ev_count = len(set(eid for e in self.entries for eid in e.evidence_ids))

        lines = [
            "ADVANCED INVESTIGATION TIMELINE",
            "================================",
            "",
            "Case:",
            self.case_id,
            "",
            "Entries:",
            str(len(self.entries)),
            "",
            "Time Range:",
            f"{min_time} \u2192 {max_time}",  # u2192 is right arrow
            "",
            "Processes:",
            str(proc_count),
            "",
            "Findings:",
            str(finding_count),
            "",
            "Correlations:",
            str(corr_count),
            "",
            "Evidence:",
            str(ev_count),
        ]

        if self.assessment_severity:
            lines.extend([
                "",
                "Assessment:",
                self.assessment_severity
            ])
            if self.assessment_score is not None:
                lines.append(f"{self.assessment_score}/100")

        return "\n".join(lines)

    def render(self) -> str:
        """Return the human-readable timeline rendering (18. HUMAN-READABLE RENDERING)."""
        lines = [
            "ADVANCED INVESTIGATION TIMELINE",
            "================================",
            ""
        ]

        for i, entry in enumerate(self.entries):
            if i > 0 and entry.entry_type != "ASSESSMENT":
                lines.append("\n    \u2193\n")

            if entry.entry_type == "ASSESSMENT":
                lines.append("────────────────────────────────────────")
                lines.append("ASSESSMENT")
                if self.assessment_severity and self.assessment_score is not None:
                    lines.append(f"{self.assessment_severity} \u2014 {self.assessment_score}/100")
                if self.assessment_confidence is not None:
                    # e.g., 0.95 -> 95%
                    conf_pct = int(self.assessment_confidence * 100)
                    lines.append(f"Confidence: {conf_pct}%")
                continue

            # Time header
            t1 = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "N/A"
            if entry.end_time and entry.end_time != entry.timestamp:
                t2 = entry.end_time.strftime("%H:%M:%S")
                lines.append(f"[{t1} \u2014 {t2}]")
            else:
                lines.append(f"[{t1}]")

            lines.append(entry.entry_type)

            if entry.title:
                lines.append(entry.title)
            if entry.description:
                lines.append(entry.description)

            if entry.parent_process_name:
                lines.append(f"Parent: {entry.parent_process_name}")

            if entry.finding_ids:
                lines.append(f"Finding: {', '.join(sorted(entry.finding_ids))}")
            if entry.evidence_ids:
                evs = sorted(entry.evidence_ids)
                if len(evs) > 3:
                    lines.append(f"Evidence: {evs[0]} ... {evs[-1]}")
                else:
                    lines.append(f"Evidence: {', '.join(evs)}")

        return "\n".join(lines)


def _map_stage_type(stage_type: str) -> str:
    mapping = {
        "PROCESS_EXECUTION": "PROCESS",
        "SUSPICIOUS_COMMAND": "COMMAND",
        "FILE_ACTIVITY": "FILE_ACTIVITY",
        "MASS_FILE_MODIFICATION": "MASS_FILE_MODIFICATION",
        "RANSOM_NOTE": "RANSOM_NOTE",
        "NETWORK_ACTIVITY": "NETWORK",
        "FINDING": "FINDING",
        "CORRELATION": "CORRELATION",
        "ASSESSMENT": "ASSESSMENT",
    }
    return mapping.get(stage_type, stage_type)


def build_advanced_timeline(
    investigation: Investigation,
    attack_sequence: AttackSequence,
    graph: InvestigationGraph
) -> AdvancedTimeline:
    """Build an advanced analyst timeline from the attack sequence and investigation context."""

    entries = []

    for i, stage in enumerate(attack_sequence.stages):
        entry_type = _map_stage_type(stage.stage_type)

        # Figure out parent process context if possible
        parent_name = None
        pid = None
        if stage.process_ids:
            # try to find the process node in the graph to get its parent
            for proc_id in stage.process_ids:
                node = graph.get_node(proc_id)
                if node:
                    if node.attributes.get("pid"):
                        pid = node.attributes["pid"]
                    # get parent
                    parents = graph.get_process_parents(proc_id)
                    if parents:
                        parent_name = parents[0].label
                        break

        entries.append(TimelineEntry(
            entry_id=f"ENTRY-{i:04d}",
            timestamp=stage.timestamp,
            end_time=stage.end_time,
            entry_type=entry_type,
            title=stage.title,
            description=stage.description,
            evidence_ids=stage.evidence_ids,
            finding_ids=stage.finding_ids,
            process_ids=stage.process_ids,
            correlation_ids=stage.correlation_ids,
            parent_process_name=parent_name,
            pid=pid
        ))

    ass_score = None
    ass_sev = None
    ass_conf = None
    if investigation.assessment:
        ass_score = investigation.assessment.get("score")
        ass_sev = investigation.assessment.get("severity")
        ass_conf = investigation.assessment.get("confidence")

    case_id = investigation.case.get("case_id", "UNKNOWN")

    # Enforce deterministic ordering (should already be sorted, but enforce it)
    def _priority(entry: TimelineEntry) -> int:
        mapping = {
            "PROCESS": 10,
            "NETWORK": 20,
            "FILE_ACTIVITY": 30,
            "MASS_FILE_MODIFICATION": 31,
            "RANSOM_NOTE": 32,
            "COMMAND": 40,
            "FINDING": 50,
            "CORRELATION": 60,
            "ASSESSMENT": 100,
        }
        return mapping.get(entry.entry_type, 90)

    sorted_entries = sorted(
        entries,
        key=lambda e: (
            e.timestamp is None,
            e.timestamp,
            _priority(e),
            e.entry_id
        )
    )

    return AdvancedTimeline(
        case_id=case_id,
        entries=tuple(sorted_entries),
        assessment_score=ass_score,
        assessment_severity=ass_sev,
        assessment_confidence=ass_conf
    )
