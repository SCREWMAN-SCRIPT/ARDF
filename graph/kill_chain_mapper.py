"""
graph/kill_chain_mapper.py
───────────────────────────
KillChainMapper — maps session findings to MITRE ATT&CK
techniques and produces kill chain stage data for reports.
"""

import json
from pathlib import Path
from typing  import Dict, List, Optional

from modules.session import Session, Finding
from modules.logger  import get_logger, ARDFLogger


KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command & Control",
]

SOURCE_TO_STAGE = {
    "recon.passive":    "Reconnaissance",
    "recon.normal":     "Reconnaissance",
    "recon.depth":      "Discovery",
    "intel":            "Reconnaissance",
    "exploit.web":      "Initial Access",
    "exploit.network":  "Lateral Movement",
    "exploit.password": "Credential Access",
    "exploit.post":     "Privilege Escalation",
    "defense.monitor":  "Defense Evasion",
}

TAG_TO_STAGE = {
    "subdomain":    "Reconnaissance",
    "passive":      "Reconnaissance",
    "osint":        "Reconnaissance",
    "port":         "Discovery",
    "nmap":         "Discovery",
    "sqli":         "Initial Access",
    "xss":          "Initial Access",
    "rce":          "Execution",
    "lfi":          "Initial Access",
    "ssrf":         "Initial Access",
    "ssti":         "Execution",
    "brute":        "Credential Access",
    "credentials":  "Credential Access",
    "kerberoast":   "Credential Access",
    "secret":       "Credential Access",
    "smb":          "Lateral Movement",
    "ssh":          "Lateral Movement",
    "privesc":      "Privilege Escalation",
    "suid":         "Privilege Escalation",
    "takeover":     "Resource Development",
    "s3":           "Collection",
    "cloud":        "Collection",
    "bucket":       "Collection",
    "persistence":  "Persistence",
    "c2":           "Command & Control",
}


class KillChainMapper:
    """Maps session findings to MITRE ATT&CK kill chain stages."""

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("graph.kill_chain")

    def map(self) -> Dict:
        """
        Map all findings to kill chain stages.
        Returns stage data for report rendering.
        """
        findings = self.session.get_findings()
        stages: Dict[str, List[Dict]] = {s: [] for s in KILL_CHAIN_STAGES}

        for finding in findings:
            stage = self._resolve_stage(finding)
            if stage in stages:
                stages[stage].append({
                    "id":       finding.id,
                    "title":    finding.title,
                    "severity": finding.severity.value,
                    "host":     finding.host,
                    "source":   finding.source,
                    "tags":     finding.tags[:5],
                })

        # Build summary
        active_stages = {
            s: items for s, items in stages.items() if items
        }
        total_mapped  = sum(len(v) for v in active_stages.values())

        result = {
            "session_id":    self.session.meta.session_id,
            "target":        self.session.meta.target,
            "stages":        stages,
            "active_stages": list(active_stages.keys()),
            "stage_count":   len(active_stages),
            "total_mapped":  total_mapped,
            "coverage_pct":  round(
                len(active_stages) / len(KILL_CHAIN_STAGES) * 100, 1
            ),
        }

        self._save(result)
        self.logger.success(
            f"Kill chain mapped | "
            f"stages={len(active_stages)}/{len(KILL_CHAIN_STAGES)} | "
            f"findings_mapped={total_mapped}"
        )
        return result

    def _resolve_stage(self, finding: Finding) -> str:
        """Resolve the kill chain stage for a finding."""
        # Check source first
        stage = SOURCE_TO_STAGE.get(finding.source)
        if stage:
            return stage
        # Check tags
        for tag in finding.tags:
            stage = TAG_TO_STAGE.get(tag.lower())
            if stage:
                return stage
        # Check title keywords
        title_lower = finding.title.lower()
        for keyword, stage in TAG_TO_STAGE.items():
            if keyword in title_lower:
                return stage
        return "Discovery"

    def _save(self, result: Dict):
        out = self.session.dir("report") / "kill_chain.json"
        out.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
