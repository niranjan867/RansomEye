"""In-memory investigation evidence graph for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation


@dataclass(frozen=True)
class GraphNode:
    """A generic node in the investigation graph."""
    node_id: str
    node_type: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """A directional relationship between two graph nodes."""
    edge_id: str
    source_id: str
    target_id: str
    relationship: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    attributes: dict[str, Any] = field(default_factory=dict)


class InvestigationGraph:
    """In-memory graph representing the investigation evidence and analysis."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._edges_by_source: dict[str, list[GraphEdge]] = {}
        self._edges_by_target: dict[str, list[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        """Add a node if it does not already exist."""
        if node.node_id not in self.nodes:
            self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directional edge and update adjacency indexes."""
        self.edges.append(edge)
        self._edges_by_source.setdefault(edge.source_id, []).append(edge)
        self._edges_by_target.setdefault(edge.target_id, []).append(edge)

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return a specific node by ID."""
        return self.nodes.get(node_id)

    def get_nodes(self, node_type: str | None = None) -> list[GraphNode]:
        """Return all nodes, optionally filtered by type."""
        if node_type:
            return [n for n in self.nodes.values() if n.node_type == node_type]
        return list(self.nodes.values())

    def get_edges(self) -> list[GraphEdge]:
        """Return all edges."""
        return list(self.edges)

    def get_edges_for_node(self, node_id: str) -> list[GraphEdge]:
        """Return all edges where the node is either source or target."""
        source_edges = self._edges_by_source.get(node_id, [])
        target_edges = self._edges_by_target.get(node_id, [])
        return source_edges + target_edges

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        """Return all nodes directly connected to the specified node."""
        neighbor_ids = set()
        for edge in self._edges_by_source.get(node_id, []):
            neighbor_ids.add(edge.target_id)
        for edge in self._edges_by_target.get(node_id, []):
            neighbor_ids.add(edge.source_id)

        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def get_process_nodes(self) -> list[GraphNode]:
        return self.get_nodes("PROCESS")

    def get_file_nodes(self) -> list[GraphNode]:
        return self.get_nodes("FILE")

    def get_finding_nodes(self) -> list[GraphNode]:
        return self.get_nodes("FINDING")

    def get_correlation_nodes(self) -> list[GraphNode]:
        return self.get_nodes("CORRELATION")

    def get_supporting_evidence(self, node_id: str) -> list[GraphNode]:
        """Return Evidence nodes that support the given finding or edge."""
        # For finding, it's connected by SUPPORTS edge from EVIDENCE
        evidence_nodes = []
        for edge in self._edges_by_target.get(node_id, []):
            if edge.relationship == "SUPPORTS" and edge.source_id.startswith("EVIDENCE:"):
                node = self.nodes.get(edge.source_id)
                if node:
                    evidence_nodes.append(node)
        return evidence_nodes

    def get_process_children(self, process_id: str) -> list[GraphNode]:
        children = []
        for edge in self._edges_by_source.get(process_id, []):
            if edge.relationship == "SPAWNED":
                node = self.nodes.get(edge.target_id)
                if node:
                    children.append(node)
        return children

    def get_process_parents(self, process_id: str) -> list[GraphNode]:
        parents = []
        for edge in self._edges_by_target.get(process_id, []):
            if edge.relationship == "SPAWNED":
                node = self.nodes.get(edge.source_id)
                if node:
                    parents.append(node)
        return parents

    def summary(self, case_id: str) -> str:
        """Return a deterministic summary of the graph."""
        nodes_by_type = {}
        for node in self.nodes.values():
            nodes_by_type[node.node_type] = nodes_by_type.get(node.node_type, 0) + 1

        edges_by_rel = {}
        for edge in self.edges:
            edges_by_rel[edge.relationship] = edges_by_rel.get(edge.relationship, 0) + 1

        lines = [
            "INVESTIGATION GRAPH",
            "===================",
            "",
            "Case:",
            case_id,
            "",
            "Nodes:",
            f"  Processes:     {nodes_by_type.get('PROCESS', 0)}",
            f"  Files:         {nodes_by_type.get('FILE', 0)}",
            f"  Network:       {nodes_by_type.get('NETWORK', 0)}",
            f"  Evidence:      {nodes_by_type.get('EVIDENCE', 0)}",
            f"  Findings:      {nodes_by_type.get('FINDING', 0)}",
            f"  Correlations:  {nodes_by_type.get('CORRELATION', 0)}",
            f"  Assessment:    {nodes_by_type.get('ASSESSMENT', 0)}",
            "",
            "Edges:",
        ]

        # Deterministic sorting of edge relationships for output
        for rel in sorted(edges_by_rel.keys()):
            lines.append(f"  {rel.ljust(14)} {edges_by_rel[rel]}")

        if not edges_by_rel:
            lines.append("  None")

        return "\n".join(lines)


def _get_process_id(event: EvidenceEvent | dict[str, Any]) -> str | None:
    if isinstance(event, EvidenceEvent):
        guid = event.process_guid
        pid = event.pid
    else:
        guid = event.get("process_guid")
        pid = event.get("pid")

    if guid:
        return f"PROCESS:{guid}"
    if pid is not None:
        return f"PROCESS:PID:{pid}"
    return None


def _get_parent_process_id(event: EvidenceEvent) -> str | None:
    if event.parent_process_guid:
        return f"PROCESS:{event.parent_process_guid}"
    if event.parent_pid is not None:
        return f"PROCESS:PID:{event.parent_pid}"
    return None


def _get_file_id(file_path: str) -> str:
    return f"FILE:{file_path.lower().strip()}"


def build_investigation_graph(investigation: Investigation) -> InvestigationGraph:
    """Build a deterministic graph from an Investigation domain model."""
    graph = InvestigationGraph()
    case_id = investigation.case.get("case_id", "UNKNOWN")
    case_node_id = f"CASE:{case_id}"

    # 1. CASE NODE
    graph.add_node(GraphNode(
        node_id=case_node_id,
        node_type="CASE",
        label=f"Case {case_id}",
        attributes=dict(investigation.case)
    ))

    # Edge accumulator to prevent duplicates
    # Key: (source_id, target_id, relationship)
    # Value: set of evidence_ids
    accumulated_edges: dict[tuple[str, str, str], set[str]] = {}

    def _accumulate_edge(source: str, target: str, rel: str, ev_id: str | None = None) -> None:
        key = (source, target, rel)
        if key not in accumulated_edges:
            accumulated_edges[key] = set()
        if ev_id:
            accumulated_edges[key].add(ev_id)

    # 2. EVIDENCE NODES & PROCESS/FILE/NETWORK NODES
    for event in investigation.evidence:
        ev_node_id = f"EVIDENCE:{event.event_id}"
        graph.add_node(GraphNode(
            node_id=ev_node_id,
            node_type="EVIDENCE",
            label=f"Evidence {event.event_id}",
            attributes={"event_type": event.event_type, "timestamp": str(event.timestamp)}
        ))

        proc_id = _get_process_id(event)
        if proc_id:
            proc_name = event.process_name or "unknown process"
            graph.add_node(GraphNode(
                node_id=proc_id,
                node_type="PROCESS",
                label=proc_name,
                attributes={"process_name": event.process_name, "pid": event.pid}
            ))

            # Parent relationships (SPAWNED)
            if event.event_type in ("process_creation", "process_create"):
                parent_id = _get_parent_process_id(event)
                if parent_id:
                    parent_name = event.parent_image or f"PID {event.parent_pid}"
                    graph.add_node(GraphNode(
                        node_id=parent_id,
                        node_type="PROCESS",
                        label=str(parent_name),
                        attributes={"pid": event.parent_pid}
                    ))
                    _accumulate_edge(parent_id, proc_id, "SPAWNED", event.event_id)

            # File relationships (CREATED, MODIFIED, DELETED, RENAMED)
            if event.event_type in ("file_create", "file_modify", "file_delete", "file_rename") and event.file_path:
                file_id = _get_file_id(event.file_path)
                file_name = event.file_path.split("\\")[-1].split("/")[-1]
                graph.add_node(GraphNode(
                    node_id=file_id,
                    node_type="FILE",
                    label=file_name,
                    attributes={"file_path": event.file_path}
                ))

                rel = event.event_type.replace("file_", "").upper()
                if rel == "MODIFY":
                    rel = "MODIFIED"
                elif rel.endswith("E"):
                    rel += "D"
                elif not rel.endswith("ED"):
                    rel += "ED"

                _accumulate_edge(proc_id, file_id, rel, event.event_id)

            # Network relationships (CONNECTED_TO)
            if event.event_type == "network_connect" and event.network:
                dest_ip = event.network.get("destination_ip")
                if dest_ip:
                    dest_port = event.network.get("destination_port")
                    if dest_port:
                        net_id = f"NETWORK:{dest_ip}:{dest_port}"
                        label = f"{dest_ip}:{dest_port}"
                    else:
                        net_id = f"NETWORK:{dest_ip}"
                        label = str(dest_ip)

                    graph.add_node(GraphNode(
                        node_id=net_id,
                        node_type="NETWORK",
                        label=label,
                        attributes=dict(event.network)
                    ))
                    _accumulate_edge(proc_id, net_id, "CONNECTED_TO", event.event_id)

    # 3. FINDING NODES & EVIDENCE -> FINDING
    finding_nodes = {}
    for finding in investigation.findings:
        f_id = finding.get("finding_id")
        if f_id is None:
            continue
        find_node_id = f"FINDING:{f_id}"
        finding_nodes[f_id] = find_node_id

        graph.add_node(GraphNode(
            node_id=find_node_id,
            node_type="FINDING",
            label=finding.get("finding_type", f"Finding {f_id}"),
            attributes=dict(finding)
        ))

        for ev_id in finding.get("event_ids", []):
            _accumulate_edge(f"EVIDENCE:{ev_id}", find_node_id, "SUPPORTS", ev_id)

    # 4. CORRELATION NODES & FINDING -> CORRELATION
    for corr in investigation.correlations:
        inc_id = corr.get("incident_id")
        if not inc_id:
            continue

        corr_node_id = f"CORRELATION:{inc_id}"
        graph.add_node(GraphNode(
            node_id=corr_node_id,
            node_type="CORRELATION",
            label=f"Incident {inc_id}",
            attributes=dict(corr)
        ))

        corr_ev_ids = set(corr.get("evidence_event_ids", []))

        # Determine FINDING -> CORRELATION associations by intersecting evidence IDs
        for finding in investigation.findings:
            f_id = finding.get("finding_id")
            if f_id is None:
                continue

            find_ev_ids = set(finding.get("event_ids", []))
            intersection = find_ev_ids.intersection(corr_ev_ids)
            if intersection:
                find_node_id = f"FINDING:{f_id}"
                for shared_ev in intersection:
                    _accumulate_edge(find_node_id, corr_node_id, "ASSOCIATED_WITH", shared_ev)

    # 5. ASSESSMENT NODE & CORRELATION -> ASSESSMENT
    if investigation.assessment:
        ass_node_id = f"ASSESSMENT:{case_id}"
        graph.add_node(GraphNode(
            node_id=ass_node_id,
            node_type="ASSESSMENT",
            label="Threat Assessment",
            attributes=dict(investigation.assessment)
        ))

        for corr in investigation.correlations:
            inc_id = corr.get("incident_id")
            if inc_id:
                _accumulate_edge(f"CORRELATION:{inc_id}", ass_node_id, "CONTRIBUTES_TO")

    # Finalize Edges deterministically
    sorted_edge_keys = sorted(accumulated_edges.keys())
    for (src, tgt, rel) in sorted_edge_keys:
        ev_ids = tuple(sorted(accumulated_edges[(src, tgt, rel)]))
        edge_id = f"{src}-[{rel}]->{tgt}"
        graph.add_edge(GraphEdge(
            edge_id=edge_id,
            source_id=src,
            target_id=tgt,
            relationship=rel,
            evidence_ids=ev_ids
        ))

    return graph
