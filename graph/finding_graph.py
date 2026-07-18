"""
graph/finding_graph.py
───────────────────────
FindingGraph — builds a relationship graph between findings.

Nodes  = findings
Edges  = relationships (same host, same CVE, same tag, chain)

Used by the report engine and analyst to surface
correlated findings and attack paths.
"""

import json
from pathlib import Path
from typing  import Dict, List, Optional, Set, Tuple

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Relationship types
# ─────────────────────────────────────────────────────────────

class RelType:
    SAME_HOST   = "same_host"
    SAME_CVE    = "same_cve"
    SAME_TAG    = "same_tag"
    CHAINS_TO   = "chains_to"
    ESCALATES   = "escalates"
    CORRELATED  = "correlated"


# ─────────────────────────────────────────────────────────────
# Graph node and edge
# ─────────────────────────────────────────────────────────────

class Node:
    def __init__(self, finding: Finding):
        self.id       = finding.id
        self.finding  = finding
        self.edges:   List["Edge"] = []
        self.score:   float = 0.0

    def to_dict(self) -> Dict:
        return {
            "id":       self.id,
            "title":    self.finding.title,
            "severity": self.finding.severity.value,
            "host":     self.finding.host,
            "source":   self.finding.source,
            "tags":     self.finding.tags,
            "score":    self.score,
            "edges":    len(self.edges),
        }


class Edge:
    def __init__(
        self,
        source_id: str,
        target_id: str,
        rel_type:  str,
        weight:    float = 1.0,
    ):
        self.source_id = source_id
        self.target_id = target_id
        self.rel_type  = rel_type
        self.weight    = weight

    def to_dict(self) -> Dict:
        return {
            "source":   self.source_id,
            "target":   self.target_id,
            "type":     self.rel_type,
            "weight":   self.weight,
        }


# ─────────────────────────────────────────────────────────────
# FindingGraph
# ─────────────────────────────────────────────────────────────

class FindingGraph:
    """
    In-memory graph of finding relationships.

    Builds automatically from session findings by
    detecting shared hosts, CVEs, tags, and chain patterns.
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("graph.findings")
        self.nodes:  Dict[str, Node] = {}
        self.edges:  List[Edge]      = []

    # ── Public API ────────────────────────────────────────────

    def build(self) -> "FindingGraph":
        """Build the graph from all session findings."""
        findings = self.session.get_findings()
        if not findings:
            return self

        # Create nodes
        for f in findings:
            self.nodes[f.id] = Node(f)

        # Create edges
        self._link_same_host(findings)
        self._link_same_cve(findings)
        self._link_same_tag(findings)
        self._link_chains(findings)

        # Score nodes by connectivity
        self._score_nodes()

        self.logger.success(
            f"Finding graph built | "
            f"nodes={len(self.nodes)} edges={len(self.edges)}"
        )
        return self

    def get_neighbours(self, finding_id: str) -> List[Node]:
        """Return all nodes directly connected to a finding."""
        node = self.nodes.get(finding_id)
        if not node:
            return []
        neighbour_ids = {
            e.target_id for e in self.edges
            if e.source_id == finding_id
        } | {
            e.source_id for e in self.edges
            if e.target_id == finding_id
        }
        return [self.nodes[nid] for nid in neighbour_ids if nid in self.nodes]

    def get_clusters(self) -> List[List[str]]:
        """
        Return connected component clusters of finding IDs.
        Each cluster is a group of related findings.
        """
        visited:  Set[str]        = set()
        clusters: List[List[str]] = []

        def dfs(node_id: str, cluster: List[str]):
            visited.add(node_id)
            cluster.append(node_id)
            for neighbour in self.get_neighbours(node_id):
                if neighbour.id not in visited:
                    dfs(neighbour.id, cluster)

        for node_id in self.nodes:
            if node_id not in visited:
                cluster: List[str] = []
                dfs(node_id, cluster)
                if len(cluster) > 1:
                    clusters.append(cluster)

        clusters.sort(key=len, reverse=True)
        return clusters

    def top_nodes(self, n: int = 10) -> List[Node]:
        """Return top N nodes by connectivity score."""
        return sorted(
            self.nodes.values(),
            key=lambda node: node.score,
            reverse=True,
        )[:n]

    def to_dict(self) -> Dict:
        """Serialise graph to dict for reporting."""
        return {
            "nodes":    [n.to_dict() for n in self.nodes.values()],
            "edges":    [e.to_dict() for e in self.edges],
            "clusters": self.get_clusters(),
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "clusters":    len(self.get_clusters()),
                "top_node":    self.top_nodes(1)[0].to_dict()
                               if self.nodes else None,
            },
        }

    def save(self, path: Optional[Path] = None):
        """Save graph to JSON file."""
        out = path or self.session.dir("report") / "finding_graph.json"
        out.write_text(
            json.dumps(self.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        self.logger.info(f"Finding graph saved → {out}")

    # ── Edge builders ─────────────────────────────────────────

    def _link_same_host(self, findings: List[Finding]):
        """Link findings that share the same host."""
        host_map: Dict[str, List[str]] = {}
        for f in findings:
            if f.host:
                host_map.setdefault(f.host, []).append(f.id)

        for host, ids in host_map.items():
            if len(ids) < 2:
                continue
            for i in range(len(ids)):
                for j in range(i + 1, min(i + 6, len(ids))):
                    self._add_edge(ids[i], ids[j], RelType.SAME_HOST, 0.8)

    def _link_same_cve(self, findings: List[Finding]):
        """Link findings that share the same CVE."""
        cve_map: Dict[str, List[str]] = {}
        for f in findings:
            if f.cve:
                cve_map.setdefault(f.cve, []).append(f.id)

        for cve, ids in cve_map.items():
            if len(ids) < 2:
                continue
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    self._add_edge(ids[i], ids[j], RelType.SAME_CVE, 1.0)

    def _link_same_tag(self, findings: List[Finding]):
        """Link findings that share high-value tags."""
        high_value_tags = {
            "sqli", "xss", "rce", "lfi", "ssrf", "ssti",
            "credentials", "secret", "takeover", "privesc",
        }
        tag_map: Dict[str, List[str]] = {}
        for f in findings:
            for tag in f.tags:
                if tag.lower() in high_value_tags:
                    tag_map.setdefault(tag.lower(), []).append(f.id)

        for tag, ids in tag_map.items():
            if len(ids) < 2:
                continue
            for i in range(len(ids)):
                for j in range(i + 1, min(i + 4, len(ids))):
                    self._add_edge(ids[i], ids[j], RelType.SAME_TAG, 0.6)

    def _link_chains(self, findings: List[Finding]):
        """
        Link findings that form natural attack chains.
        e.g. subdomain → port scan → vuln → exploit
        """
        source_order = [
            "recon.passive",
            "recon.normal",
            "recon.depth",
            "intel",
            "exploit.web",
            "exploit.network",
            "exploit.password",
            "exploit.post",
        ]

        by_source: Dict[str, List[Finding]] = {}
        for f in findings:
            by_source.setdefault(f.source, []).append(f)

        # Link findings in source order progression
        for i in range(len(source_order) - 1):
            src_a = source_order[i]
            src_b = source_order[i + 1]
            fa_list = by_source.get(src_a, [])
            fb_list = by_source.get(src_b, [])
            for fa in fa_list[:5]:
                for fb in fb_list[:5]:
                    if fa.host == fb.host or not fb.host:
                        self._add_edge(
                            fa.id, fb.id,
                            RelType.CHAINS_TO, 1.5
                        )

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        rel_type:  str,
        weight:    float,
    ):
        """Add an edge if nodes exist and edge is not duplicate."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        # Check for duplicate
        for e in self.edges:
            if (e.source_id == source_id and e.target_id == target_id) or \
               (e.source_id == target_id and e.target_id == source_id):
                return
        edge = Edge(source_id, target_id, rel_type, weight)
        self.edges.append(edge)
        self.nodes[source_id].edges.append(edge)
        self.nodes[target_id].edges.append(edge)

    def _score_nodes(self):
        """Score nodes by weighted edge count and severity."""
        sev_weights = {
            "critical": 10.0,
            "high":     7.0,
            "medium":   4.0,
            "low":      1.5,
            "info":     0.0,
        }
        for node in self.nodes.values():
            edge_score = sum(e.weight for e in node.edges)
            sev_score  = sev_weights.get(node.finding.severity.value, 0)
            node.score = round(edge_score + sev_score, 2)
