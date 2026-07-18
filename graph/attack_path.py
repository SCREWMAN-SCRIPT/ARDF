"""
graph/attack_path.py
─────────────────────
AttackPathBuilder — builds logical attack paths from findings.

An attack path is an ordered sequence of findings that together
represent a realistic multi-step compromise scenario.

Used by the report engine to surface the most critical
narrative paths through the finding set.
"""

import json
from pathlib import Path
from typing  import Dict, List, Optional, Tuple

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Attack path
# ─────────────────────────────────────────────────────────────

class AttackPath:
    """
    A single ordered attack path through findings.
    """

    def __init__(
        self,
        name:     str,
        steps:    List[Finding],
        severity: SeverityLevel,
        mitre:    List[str],
        narrative: str = "",
    ):
        self.name      = name
        self.steps     = steps
        self.severity  = severity
        self.mitre     = mitre
        self.narrative = narrative
        self.score     = self._compute_score()

    def _compute_score(self) -> float:
        weights = {
            "critical": 10.0, "high": 7.0,
            "medium":   4.0,  "low":  1.5, "info": 0.0,
        }
        return sum(
            weights.get(f.severity.value, 0)
            for f in self.steps
        )

    def to_dict(self) -> Dict:
        return {
            "name":      self.name,
            "severity":  self.severity.value,
            "score":     self.score,
            "steps":     len(self.steps),
            "mitre":     self.mitre,
            "narrative": self.narrative,
            "findings": [
                {
                    "id":       f.id,
                    "title":    f.title,
                    "severity": f.severity.value,
                    "host":     f.host,
                    "source":   f.source,
                }
                for f in self.steps
            ],
        }


# ─────────────────────────────────────────────────────────────
# AttackPathBuilder
# ─────────────────────────────────────────────────────────────

class AttackPathBuilder:
    """
    Builds attack paths from session findings.

    Identifies realistic multi-step compromise scenarios
    by chaining related findings in logical order.
    """

    # Known attack path patterns
    PATH_PATTERNS = [
        {
            "name":     "Web Application to Server Compromise",
            "requires": [["sqli", "rce", "lfi", "ssti", "cmdi"], ["rce", "shell", "confirmed"]],
            "mitre":    ["T1190", "T1059"],
            "severity": SeverityLevel.CRITICAL,
            "narrative": "Web vulnerability exploited to achieve remote code execution on the server.",
        },
        {
            "name":     "Credential Discovery to Lateral Movement",
            "requires": [["secret", "credentials", "api_key"], ["smb", "ssh", "rdp"]],
            "mitre":    ["T1552", "T1021"],
            "severity": SeverityLevel.CRITICAL,
            "narrative": "Exposed credentials harvested and used to access internal services.",
        },
        {
            "name":     "Subdomain Takeover to Phishing",
            "requires": [["subdomain", "takeover"], ["cname", "dns"]],
            "mitre":    ["T1584", "T1598"],
            "severity": SeverityLevel.HIGH,
            "narrative": "Dangling DNS record exploitable for subdomain takeover enabling phishing.",
        },
        {
            "name":     "Exposed Service to Brute Force",
            "requires": [["port", "open", "ssh", "rdp", "ftp"], ["brute", "brute-force", "credentials"]],
            "mitre":    ["T1046", "T1110"],
            "severity": SeverityLevel.HIGH,
            "narrative": "Exposed network service brute-forced to gain authenticated access.",
        },
        {
            "name":     "Cloud Bucket Exposure to Data Exfiltration",
            "requires": [["s3", "cloud", "bucket"], ["exposed", "public", "open"]],
            "mitre":    ["T1530"],
            "severity": SeverityLevel.HIGH,
            "narrative": "Misconfigured cloud storage bucket exposing sensitive data publicly.",
        },
        {
            "name":     "Reconnaissance to Targeted Attack",
            "requires": [["subdomain", "passive", "osint"], ["port", "service", "version"]],
            "mitre":    ["T1596", "T1046"],
            "severity": SeverityLevel.MEDIUM,
            "narrative": "Passive reconnaissance reveals attack surface enabling targeted exploitation.",
        },
    ]

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("graph.attack_path")

    # ── Public API ────────────────────────────────────────────

    def build_all(self) -> List[AttackPath]:
        """Build all detectable attack paths from session findings."""
        findings = self.session.get_findings()
        if not findings:
            return []

        paths = []
        for pattern in self.PATH_PATTERNS:
            path = self._match_pattern(pattern, findings)
            if path:
                paths.append(path)

        # Sort by score descending
        paths.sort(key=lambda p: p.score, reverse=True)

        self.logger.success(
            f"Attack paths identified: {len(paths)}"
        )
        return paths

    def save(
        self,
        paths:      List[AttackPath],
        output_dir: Optional[Path] = None,
    ) -> Path:
        """Save attack paths to JSON."""
        out = output_dir or self.session.dir("report")
        out.mkdir(parents=True, exist_ok=True)
        path = out / "attack_paths.json"
        path.write_text(
            json.dumps(
                {
                    "session_id": self.session.meta.session_id,
                    "target":     self.session.meta.target,
                    "paths":      [p.to_dict() for p in paths],
                    "count":      len(paths),
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return path

    # ── Internal ──────────────────────────────────────────────

    def _match_pattern(
        self,
        pattern:  Dict,
        findings: List[Finding],
    ) -> Optional[AttackPath]:
        """
        Match a path pattern against findings.
        Pattern requires is a list of tag groups — at least
        one tag from each group must appear in findings.
        """
        requires   = pattern["requires"]
        step_groups: List[List[Finding]] = []

        for tag_group in requires:
            matched = [
                f for f in findings
                if any(
                    tag in [t.lower() for t in f.tags] or
                    tag in f.title.lower() or
                    tag in f.description.lower()
                    for tag in tag_group
                )
            ]
            if not matched:
                return None
            step_groups.append(matched)

        # Build path steps — one finding per group, highest severity first
        steps = []
        for group in step_groups:
            best = sorted(
                group,
                key=lambda f: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(
                    f.severity.value, 9
                ),
            )[0]
            if best not in steps:
                steps.append(best)

        if len(steps) < 2:
            return None

        return AttackPath(
            name      = pattern["name"],
            steps     = steps,
            severity  = pattern["severity"],
            mitre     = pattern["mitre"],
            narrative = pattern["narrative"],
        )
