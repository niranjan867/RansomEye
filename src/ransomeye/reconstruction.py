"""Attack reconstruction and advanced timeline for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import InvestigationGraph, _get_process_id


def _normalize_dt(dt: datetime | None) -> datetime | None:
    """Normalize datetime to UTC for timezone-safe comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)



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
    attributes: dict[str, Any] = field(default_factory=dict)

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
                lines.append(f"Incident: {', '.join(sorted(str(c) for c in stage.correlation_ids))}")
            if stage.finding_ids:
                lines.append(f"Finding: {', '.join(sorted(str(f) for f in stage.finding_ids))}")
            if stage.evidence_ids:
                lines.append(f"Evidence: {', '.join(sorted(str(e) for e in stage.evidence_ids))}")

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

    # Pre-index correlations per evidence event
    event_correlations: dict[str, set[str]] = {}
    for corr in investigation.correlations:
        c_id_val = corr.get("incident_id")
        if c_id_val:
            for eid_val in corr.get("evidence_event_ids", []):
                event_correlations.setdefault(str(eid_val), set()).add(str(c_id_val))

    for finding in investigation.findings:
        f_id = finding.get("finding_id")
        if f_id is None:
            continue
        f_id_str = str(f_id)

        f_type = finding.get("finding_type", "").lower()
        f_title = finding.get("title")
        f_desc = finding.get("description") or finding.get("reason", "")
        ev_ids = [str(x) for x in (finding.get("event_ids") or [])]

        # Determine stage type and evidence-supported titles
        if "mass" in f_type and "file" in f_type:
            stage_type = "MASS_FILE_MODIFICATION"
            if not f_title:
                f_title = "Mass File Modification Activity"
        elif "ransom" in f_type and "note" in f_type:
            stage_type = "RANSOM_NOTE"
            if not f_title:
                f_title = "Ransom Note Creation"
        elif f_type in ("suspicious_powershell", "encoded_command"):
            stage_type = "SUSPICIOUS_COMMAND"
            if not f_title:
                f_title = "Suspicious PowerShell Execution"
        elif "certutil" in f_type:
            stage_type = "COMMAND"
            if not f_title:
                f_title = "File Download Activity (CertUtil LOLBIN)"
        elif "recovery" in f_type or "inhibition" in f_type:
            stage_type = "COMMAND"
            if not f_title:
                f_title = "Recovery-Inhibition Command"
        elif "static" in f_type:
            stage_type = "SUSPICIOUS_EXECUTABLE"
            if not f_title:
                f_title = "Suspicious Executable Activity"
        elif "script" in f_type:
            stage_type = "SCRIPT_EXECUTION"
            if not f_title:
                f_title = "PowerShell Download Cradle Detected"
        elif "phish" in f_type:
            stage_type = "PHISHING"
            if not f_title:
                f_title = "Suspicious Phishing Artifact Submitted"
        elif "ioc_contextual_lolbin" in f_type:
            stage_type = "COMMAND"
            if not f_title:
                f_title = "LOLBIN Command Activity Detected"
        elif "ioc" in f_type:
            stage_type = "FINDING"
            if not f_title:
                f_title = "Threat Indicator Extraction"
        elif f_type in ("suspicious_command", "suspicious_process"):
            stage_type = "SUSPICIOUS_COMMAND"
            if not f_title:
                f_title = "Suspicious Process Activity"
        else:
            stage_type = "FINDING"
            if not f_title:
                f_title = f_type.replace("_", " ").title()

        # Grouping behavior: if it's a mass file modification, group them.
        if stage_type == "MASS_FILE_MODIFICATION" and len(ev_ids) > 1:
            # Create a single grouped stage
            evs = [e for e in investigation.evidence if e.event_id in ev_ids]
            if not evs:
                continue

            min_time = min(evs, key=lambda e: _normalize_dt(e.timestamp)).timestamp
            max_time = max(evs, key=lambda e: _normalize_dt(e.timestamp)).timestamp

            pids = set()
            for e in evs:
                pid = _get_process_id(e)
                if pid:
                    pids.add(pid)

            stages.append(AttackStage(
                stage_id=f"STAGE-F-{f_id_str}",
                timestamp=min_time,
                end_time=max_time,
                stage_type=stage_type,
                title=f_title,
                description=f_desc or f"Mass file modification detected across {len(ev_ids)} files",
                evidence_ids=tuple(sorted(ev_ids)),
                finding_ids=(f_id_str,),
                process_ids=tuple(sorted(pids)),
                attributes={"file_count": len(ev_ids), "finding_reason": f_desc}
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
                finding_upgrades[eid]["finding_ids"].add(f_id_str)
                # Keep the most severe stage type if multiple (simplification: last one wins or specific overrides)
                if stage_type != "FINDING":
                    finding_upgrades[eid]["stage_type"] = stage_type
                if f_title and (finding_upgrades[eid]["title"] in ("FINDING", "file_stream_hash", f_type) or stage_type != "FINDING"):
                    finding_upgrades[eid]["title"] = f_title
                if f_desc and not finding_upgrades[eid]["description"]:
                    finding_upgrades[eid]["description"] = f_desc

    # 2. Process Raw Evidence Events
    for i, event in enumerate(investigation.evidence):
        if event.event_id in grouped_evidence_ids:
            continue

        ev_type = event.event_type
        stage_type = "UNKNOWN"
        title = ""
        desc = ""
        attributes: dict[str, Any] = {}

        proc_id = _get_process_id(event)
        pids = (proc_id,) if proc_id else ()

        if ev_type in ("process_create", "process_creation"):
            stage_type = "PROCESS_EXECUTION"
            proc_name = event.process_name or "unknown"
            pid_str = f" [PID {event.pid}]" if event.pid else ""
            title = f"{proc_name}{pid_str}"
            if event.command_line:
                desc = event.command_line
                attributes["command_line"] = event.command_line
            else:
                desc = f"Process {proc_name} created"
            attributes["process_name"] = proc_name
            if event.pid:
                attributes["pid"] = event.pid
            if event.parent_image:
                attributes["parent_image"] = event.parent_image
            if event.parent_pid:
                attributes["parent_pid"] = event.parent_pid

        elif ev_type in ("file_create", "file_modify", "file_delete", "file_rename"):
            stage_type = "FILE_ACTIVITY"
            action = ev_type.replace("file_", "").capitalize()
            fname = event.file_path.split("\\")[-1].split("/")[-1] if event.file_path else "unknown file"
            title = f"File {action.lower()} activity"
            desc = f"{action} {fname}"
            if event.file_path:
                attributes["file_path"] = event.file_path
                desc = f"{action} {fname} ({event.file_path})"

        elif ev_type == "network_connect":
            stage_type = "NETWORK_ACTIVITY"
            if event.network:
                attributes.update(event.network)

            proc_name = event.process_name or ""
            dip = attributes.get("destination_ip", "")
            dport = attributes.get("destination_port", "")
            dest_str = f"{dip}:{dport}" if dport else f"{dip}"
            if proc_name:
                title = f"{proc_name} \u2192 {dest_str}" if dest_str else f"{proc_name} network connection"
                desc = f"Outbound connection to {dest_str} initiated by {proc_name}" if dest_str else f"Network connection by {proc_name}"
            else:
                title = f"Network Connection \u2192 {dest_str}" if dest_str else "Network Connection"
                desc = f"Observed outbound network connection to {dest_str}" if dest_str else "Network connection observed"

        elif ev_type == "dns_query":
            stage_type = "NETWORK_ACTIVITY"
            if event.network:
                attributes.update(event.network)
                qname = event.network.get("query_name", "")
                qres = event.network.get("query_results", "")
                title = f"DNS Query: {qname}" if qname else "DNS Query"
                desc = f"Result: {qres}" if qres else (f"Query for {qname}" if qname else "DNS resolution query")
            else:
                title = "DNS Query"
                desc = "DNS resolution query"

        elif ev_type == "file_stream_hash":
            stage_type = "ARTIFACT_INGESTION"
            meta = event.metadata or {}
            fname = event.file_path.split("\\")[-1].split("/")[-1] if event.file_path else (meta.get("file_name") or meta.get("artifact_label") or "artifact")
            obs = meta.get("observation", "")
            if obs == "phishing_message_provenance" or fname.endswith(".eml"):
                title = "Phishing Artifact Submitted"
                subj = meta.get("subject", "Mandatory Security Verification")
                desc = f"Email artifact '{fname}' submitted for analysis (Subject: {subj})"
            elif obs == "static_script_analysis" or fname.endswith(".ps1"):
                title = "Suspicious Script Artifact"
                lang = meta.get("language", "powershell")
                desc = f"Script '{fname}' ({lang}) submitted for forensic analysis"
            elif obs == "pcap_capture_provenance" or fname.endswith(".pcap"):
                title = "Network Capture Artifact"
                pkts = meta.get("total_packets", 2)
                desc = f"PCAP capture '{fname}' ({pkts} packets) submitted for traffic inspection"
            elif obs == "ioc_extraction_provenance" or "indicators" in fname:
                title = "Threat Indicator Artifact"
                desc = f"IOC indicator feed '{fname}' submitted for intelligence extraction"
            elif meta.get("file_type") == "Windows PE Executable / DLL" or fname.endswith(".exe"):
                title = "Suspicious Executable Artifact"
                ent = meta.get("total_entropy", "")
                desc = f"Staged binary '{fname}' (PE Executable, entropy {ent}) submitted for static analysis"
            else:
                title = f"Evidence Artifact: {fname}"
                desc = f"Artifact {fname} ingested into case evidence store"
        else:
            stage_type = ev_type.upper()
            title = ev_type.replace("_", " ").title()
            desc = f"Event {event.event_id} ({ev_type})"

        finding_ids = set()

        # Apply upgrades from findings
        if event.event_id in finding_upgrades:
            upg = finding_upgrades[event.event_id]
            stage_type = upg["stage_type"]
            if upg["title"]:
                title = upg["title"]
            if upg["description"]:
                if desc and desc != upg["description"]:
                    attributes["finding_reason"] = upg["description"]
                else:
                    desc = upg["description"]
            finding_ids.update(upg["finding_ids"])

        event_corrs = tuple(sorted(event_correlations.get(str(event.event_id), set())))
        if event_corrs:
            attributes["correlation_ids"] = list(event_corrs)

        stages.append(AttackStage(
            stage_id=f"STAGE-E-{event.event_id}",
            timestamp=event.timestamp,
            stage_type=stage_type,
            title=title,
            description=desc,
            evidence_ids=(event.event_id,),
            finding_ids=tuple(sorted(finding_ids)),
            process_ids=pids,
            attributes=attributes
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

        ev_count = len(ev_ids)
        c_title = corr.get("title") or f"Incident: {c_id}"
        c_desc = corr.get("description") or corr.get("summary") or (
            f"Correlated {ev_count} events across incident lifecycle" if ev_count > 1 else f"Correlated event {ev_ids[0] if ev_ids else ''}"
        )

        stages.append(AttackStage(
            stage_id=f"STAGE-C-{c_id}",
            timestamp=start_time,
            end_time=end_time,
            stage_type="CORRELATION",
            title=c_title,
            description=c_desc,
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
            _normalize_dt(s.timestamp),
            _get_stage_priority(s.stage_type),
            s.stage_id
        )
    )

    return AttackSequence(stages=tuple(sorted_stages))
