"""Attack reconstruction and advanced timeline for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import InvestigationGraph, _get_process_id


@dataclass(frozen=True)
class AttackStage:
    """A deterministic, chronological stage of an attack."""
    stage_id: str
    timestamp: datetime | None
    stage_type: str
    title: str
    description: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    process_ids: tuple[str, ...] = field(default_factory=tuple)
    correlation_ids: tuple[str, ...] = field(default_factory=tuple)

    # Optional end time for ranges like Correlations
    end_time: datetime | None = None


@dataclass(frozen=True)
class AttackSequence:
    """A chronologically ordered, read-only sequence of attack stages."""
    stages: tuple[AttackStage, ...]

    def summary(self) -> str:
        """Return a human-readable text representation of the attack sequence."""
        lines = ["ATTACK RECONSTRUCTION", "====================="]

        for i, stage in enumerate(self.stages):
            if i > 0:
                lines.append("\n        ↓\n")

            if stage.timestamp:
                time_str = f"[{stage.timestamp.strftime('%H:%M:%S')}]"
                lines.append(f"{time_str} {stage.stage_type}")
            else:
                lines.append("────────────────────────────")
                lines.append(stage.stage_type)

            if stage.title:
                lines.append(stage.title)

            if stage.description:
                lines.append(stage.description)

            if stage.process_ids:
                # simplify process rendering if it's just 'PROCESS:PID:123'
                # But the prompt example doesn't explicitly print Process if it's in the title,
                # actually it says: "Process: powershell.exe" for SUSPICIOUS_COMMAND.
                # Let's just output it if we have it and it's not a generic PROCESS_EXECUTION.
                # Wait, the example:
                # [10:30:08] PROCESS_EXECUTION
                # suspicious.exe [PID 3000]
                # Evidence: EVT-004
                #
                # [10:30:12] MASS_FILE_MODIFICATION
                # File modification activity
                # Finding: F-002
                # Evidence: EVT-005, EVT-006
                if stage.stage_type not in ("PROCESS_EXECUTION", "FILE_ACTIVITY", "MASS_FILE_MODIFICATION", "RANSOM_NOTE"):
                    pass # We will rely on other properties or the user can adjust if needed

            if stage.correlation_ids:
                lines.append(f"Incident: {', '.join(sorted(stage.correlation_ids))}")
            if stage.finding_ids:
                lines.append(f"Finding: {', '.join(sorted(stage.finding_ids))}")
            if stage.evidence_ids:
                lines.append(f"Evidence: {', '.join(sorted(stage.evidence_ids))}")

        return "\n".join(lines)


def _get_stage_priority(stage_type: str) -> int:
    """Priority mapping for deterministic tie-breaking on equal timestamps."""
    mapping = {
        "PROCESS_EXECUTION": 10,
        "NETWORK_ACTIVITY": 20,
        "FILE_ACTIVITY": 30,
        "MASS_FILE_MODIFICATION": 31,
        "RANSOM_NOTE": 32,
        "SUSPICIOUS_COMMAND": 40,
        "FINDING": 50,
        "CORRELATION": 60,
        "ASSESSMENT": 100,
    }
    return mapping.get(stage_type, 90)


def reconstruct_attack(investigation: Investigation, graph: InvestigationGraph) -> AttackSequence:
    """Reconstruct an evidence-backed chronological sequence of the attack."""

    stages: list[AttackStage] = []

    # Track which events have been grouped into larger multi-event stages (e.g. mass modification)
    # so we don't duplicate them as individual file activity stages.
    grouped_evidence_ids: set[str] = set()

    # 1. Process Findings first to identify aggregations or upgrades
    finding_upgrades = {}  # evidence_id -> dict of upgraded properties

    for finding in investigation.findings:
        f_id = finding.get("finding_id")
        if not f_id:
            continue

        f_type = finding.get("finding_type", "").lower()
        f_title = finding.get("title") or f_type
        f_desc = finding.get("description", "")
        ev_ids = finding.get("event_ids", [])

        # Determine stage type
        if "mass" in f_type and "file" in f_type:
            stage_type = "MASS_FILE_MODIFICATION"
        elif "ransom" in f_type and "note" in f_type:
            stage_type = "RANSOM_NOTE"
        elif f_type in ("suspicious_powershell", "encoded_command", "suspicious_command", "suspicious_process"):
            stage_type = "SUSPICIOUS_COMMAND"
        else:
            stage_type = "FINDING"

        # Grouping behavior: if it's a mass file modification, group them.
        if stage_type == "MASS_FILE_MODIFICATION" and len(ev_ids) > 1:
            # Create a single grouped stage
            evs = [e for e in investigation.evidence if e.event_id in ev_ids]
            if not evs:
                continue

            min_time = min(e.timestamp for e in evs)
            max_time = max(e.timestamp for e in evs)

            pids = set()
            for e in evs:
                pid = _get_process_id(e)
                if pid:
                    pids.add(pid)

            stages.append(AttackStage(
                stage_id=f"STAGE-F-{f_id}",
                timestamp=min_time,
                end_time=max_time,
                stage_type=stage_type,
                title=f_title,
                description=f_desc,
                evidence_ids=tuple(sorted(ev_ids)),
                finding_ids=(f_id,),
                process_ids=tuple(sorted(pids))
            ))
            grouped_evidence_ids.update(ev_ids)

        else:
            # Upgrade behavior for individual events
            for eid in ev_ids:
                if eid not in finding_upgrades:
                    finding_upgrades[eid] = {
                        "finding_ids": set(),
                        "stage_type": stage_type,
                        "title": f_title,
                        "description": f_desc
                    }
                finding_upgrades[eid]["finding_ids"].add(f_id)
                # Keep the most severe stage type if multiple (simplification: last one wins or specific overrides)
                if stage_type != "FINDING":
                    finding_upgrades[eid]["stage_type"] = stage_type
                if f_title and finding_upgrades[eid]["title"] == "FINDING":
                    finding_upgrades[eid]["title"] = f_title

    # 2. Process Raw Evidence Events
    for i, event in enumerate(investigation.evidence):
        if event.event_id in grouped_evidence_ids:
            continue

        ev_type = event.event_type
        stage_type = "UNKNOWN"
        title = ""
        desc = ""

        proc_id = _get_process_id(event)
        pids = (proc_id,) if proc_id else ()

        if ev_type in ("process_create", "process_creation"):
            stage_type = "PROCESS_EXECUTION"
            proc_name = event.process_name or "unknown"
            pid_str = f" [PID {event.pid}]" if event.pid else ""
            title = f"{proc_name}{pid_str}"
            if event.command_line:
                desc = event.command_line

        elif ev_type in ("file_create", "file_modify", "file_delete", "file_rename"):
            stage_type = "FILE_ACTIVITY"
            action = ev_type.replace("file_", "").capitalize()
            fname = event.file_path.split("\\")[-1].split("/")[-1] if event.file_path else "unknown file"
            title = f"File {action.lower()} activity"
            desc = f"{action} {fname}"

        elif ev_type == "network_connect":
            stage_type = "NETWORK_ACTIVITY"
            title = "Network connection"
            if event.network:
                dip = event.network.get("destination_ip", "")
                dport = event.network.get("destination_port", "")
                desc = f"Connected to {dip}:{dport}" if dport else f"Connected to {dip}"
        else:
            stage_type = ev_type.upper()
            title = ev_type

        finding_ids = set()

        # Apply upgrades from findings
        if event.event_id in finding_upgrades:
            upg = finding_upgrades[event.event_id]
            stage_type = upg["stage_type"]
            # If the finding has a specific title, we might use it instead or alongside
            if upg["title"] and upg["stage_type"] != "FINDING":
                title = upg["title"]
            finding_ids.update(upg["finding_ids"])

        stages.append(AttackStage(
            stage_id=f"STAGE-E-{event.event_id}",
            timestamp=event.timestamp,
            stage_type=stage_type,
            title=title,
            description=desc,
            evidence_ids=(event.event_id,),
            finding_ids=tuple(sorted(finding_ids)),
            process_ids=pids
        ))

    # 3. Process Correlations
    for corr in investigation.correlations:
        c_id = corr.get("incident_id")
        if not c_id:
            continue

        # Parse timestamp
        from ransomeye.correlation import _parse_dt
        start_time = _parse_dt(corr.get("start_time"))
        end_time = _parse_dt(corr.get("end_time"))

        ev_ids = corr.get("evidence_event_ids", [])

        # Extract process ids
        pids = set()
        for p in corr.get("processes", []):
            guid = p.get("process_guid")
            pid = p.get("pid")
            if guid:
                pids.add(f"PROCESS:{guid}")
            elif pid is not None:
                pids.add(f"PROCESS:PID:{pid}")

        stages.append(AttackStage(
            stage_id=f"STAGE-C-{c_id}",
            timestamp=start_time,
            end_time=end_time,
            stage_type="CORRELATION",
            title=f"Incident: {c_id}",
            description=f"Correlated {len(ev_ids)} events",
            evidence_ids=tuple(sorted(ev_ids)),
            correlation_ids=(c_id,),
            process_ids=tuple(sorted(pids))
        ))

    # 4. Process Assessment
    if investigation.assessment:
        score = investigation.assessment.get("score")
        sev = investigation.assessment.get("severity")
        conf = investigation.assessment.get("confidence")

        desc_lines = []
        if score is not None:
            desc_lines.append(f"Threat Score: {score}/100")
        if sev:
            desc_lines.append(f"Severity: {sev}")
        if conf is not None:
            desc_lines.append(f"Confidence: {conf}")

            ass_time = None

        stages.append(AttackStage(
            stage_id="STAGE-A-ASSESSMENT",
            timestamp=ass_time,
            stage_type="ASSESSMENT",
            title="Threat Assessment",
            description="\n".join(desc_lines)
        ))

    # Sort stages chronologically and deterministically
    sorted_stages = sorted(
        stages,
        key=lambda s: (
            s.timestamp is None,
            s.timestamp,
            _get_stage_priority(s.stage_type),
            s.stage_id
        )
    )

    return AttackSequence(stages=tuple(sorted_stages))
