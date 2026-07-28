"""
graph/attack_path.py
────────────────────
Attack path detection for ARDF.

Enhanced with Cloudflare bypass paths:
  - Multi-step attack path detection
  - Cloudflare bypass integration
  - Origin discovery paths
  - WAF evasion paths
  - Confidence scoring

The attack path mapper identifies potential multi-step
attack chains and maps them to MITRE ATT&CK techniques.
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

@dataclass
class AttackStep:
    """A single step in an attack path."""
    id: str
    name: str
    technique: str
    description: str
    prerequisites: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """A complete attack path."""
    id: str
    name: str
    description: str
    steps: List[AttackStep]
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    severity: str = "medium"
    prerequisites: List[str] = field(default_factory=list)
    is_cloudflare_bypass: bool = False


# ─────────────────────────────────────────────────────────────
# Attack Path Definitions
# ─────────────────────────────────────────────────────────────

class AttackPathDefinitions:
    """
    Pre-defined attack path templates.
    """

    @staticmethod
    def get_cloudflare_bypass_paths(target: str) -> List[AttackPath]:
        """Generate Cloudflare bypass attack paths."""
        return [
            AttackPath(
                id=f"cf_bypass_{target}",
                name="Cloudflare Origin Discovery",
                description="Discover origin IP behind Cloudflare and attack directly",
                is_cloudflare_bypass=True,
                severity="high",
                confidence=0.7,
                mitre_techniques=["T1190", "T1584", "T1046"],
                prerequisites=["cloudflare_detected"],
                steps=[
                    AttackStep(
                        id="cf_recon",
                        name="Cloudflare Reconnaissance",
                        technique="T1046",
                        description="Detect Cloudflare and identify version",
                        prerequisites=[],
                        conditions=["cloudflare_detected"]
                    ),
                    AttackStep(
                        id="cf_bypass",
                        name="Cloudflare Bypass",
                        technique="T1584",
                        description="Execute bypass techniques to find origin IP",
                        prerequisites=["cf_recon"],
                        conditions=["bypass_attempted"]
                    ),
                    AttackStep(
                        id="origin_attack",
                        name="Direct Origin Attack",
                        technique="T1190",
                        description="Attack origin IP directly, bypassing Cloudflare",
                        prerequisites=["cf_bypass"],
                        conditions=["origin_found"]
                    )
                ]
            ),
            AttackPath(
                id=f"cf_worker_{target}",
                name="Cloudflare Worker Misconfiguration Exploit",
                description="Exploit misconfigured Cloudflare Workers",
                is_cloudflare_bypass=True,
                severity="medium",
                confidence=0.5,
                mitre_techniques=["T1190", "T1584"],
                prerequisites=["cloudflare_detected"],
                steps=[
                    AttackStep(
                        id="worker_recon",
                        name="Worker Enumeration",
                        technique="T1046",
                        description="Enumerate Cloudflare Worker endpoints",
                        prerequisites=[],
                        conditions=["cloudflare_detected"]
                    ),
                    AttackStep(
                        id="worker_exploit",
                        name="Worker Exploitation",
                        technique="T1190",
                        description="Exploit misconfigured Worker routing",
                        prerequisites=["worker_recon"],
                        conditions=["worker_vulnerable"]
                    ),
                    AttackStep(
                        id="origin_access",
                        name="Origin Access via Worker",
                        technique="T1190",
                        description="Access origin via exploited Worker",
                        prerequisites=["worker_exploit"],
                        conditions=["access_gained"]
                    )
                ]
            )
        ]

    @staticmethod
    def get_waf_bypass_paths(waf_type: str, target: str) -> List[AttackPath]:
        """Generate WAF bypass paths."""
        return [
            AttackPath(
                id=f"waf_bypass_{target}",
                name=f"WAF Bypass ({waf_type})",
                description=f"Bypass {waf_type} WAF protection",
                severity="medium",
                confidence=0.6,
                mitre_techniques=["T1190", "T1059"],
                prerequisites=["waf_detected"],
                steps=[
                    AttackStep(
                        id="waf_fingerprint",
                        name="WAF Fingerprinting",
                        technique="T1046",
                        description=f"Identify {waf_type} WAF configuration",
                        prerequisites=[],
                        conditions=["waf_detected"]
                    ),
                    AttackStep(
                        id="waf_bypass",
                        name="WAF Evasion",
                        technique="T1059",
                        description="Use evasion techniques to bypass WAF",
                        prerequisites=["waf_fingerprint"],
                        conditions=["bypass_attempted"]
                    ),
                    AttackStep(
                        id="exploit",
                        name="Exploit After Bypass",
                        technique="T1190",
                        description="Execute exploit after WAF bypass",
                        prerequisites=["waf_bypass"],
                        conditions=["bypass_successful"]
                    )
                ]
            )
        ]

    @staticmethod
    def get_standard_paths() -> List[AttackPath]:
        """Get standard attack paths."""
        return [
            AttackPath(
                id="standard_web",
                name="Standard Web Application Attack",
                description="Recon → Discover → Exploit web application",
                severity="high",
                confidence=0.8,
                mitre_techniques=["T1046", "T1059", "T1190"],
                prerequisites=[],
                steps=[
                    AttackStep(
                        id="web_recon",
                        name="Web Reconnaissance",
                        technique="T1046",
                        description="Discover web endpoints and technologies",
                        prerequisites=[],
                        conditions=[]
                    ),
                    AttackStep(
                        id="web_vuln",
                        name="Vulnerability Discovery",
                        technique="T1046",
                        description="Find vulnerabilities in web application",
                        prerequisites=["web_recon"],
                        conditions=["vuln_found"]
                    ),
                    AttackStep(
                        id="web_exploit",
                        name="Web Exploitation",
                        technique="T1190",
                        description="Exploit discovered vulnerability",
                        prerequisites=["web_vuln"],
                        conditions=["exploit_available"]
                    )
                ]
            ),
            AttackPath(
                id="standard_network",
                name="Standard Network Attack",
                description="Scan → Identify → Exploit network services",
                severity="high",
                confidence=0.7,
                mitre_techniques=["T1046", "T1110", "T1190"],
                prerequisites=[],
                steps=[
                    AttackStep(
                        id="net_scan",
                        name="Network Scan",
                        technique="T1046",
                        description="Scan for open ports and services",
                        prerequisites=[],
                        conditions=[]
                    ),
                    AttackStep(
                        id="net_vuln",
                        name="Service Vulnerability",
                        technique="T1046",
                        description="Identify vulnerable services",
                        prerequisites=["net_scan"],
                        conditions=["service_vuln"]
                    ),
                    AttackStep(
                        id="net_exploit",
                        name="Service Exploitation",
                        technique="T1190",
                        description="Exploit vulnerable service",
                        prerequisites=["net_vuln"],
                        conditions=["exploit_available"]
                    )
                ]
            )
        ]


# ─────────────────────────────────────────────────────────────
# Attack Path Mapper
# ─────────────────────────────────────────────────────────────

class AttackPathMapper:
    """
    Map findings to attack paths with Cloudflare awareness.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("attack_path")
        self.paths: List[AttackPath] = []

    # ── Path generation ──────────────────────────────────────

    def generate_paths(self, findings: Optional[List[Finding]] = None) -> List[AttackPath]:
        """
        Generate attack paths from findings.
        """
        if findings is None:
            findings = self.session.get_findings()

        target = self.session.meta.target
        self.paths = []

        # Check for Cloudflare
        cloudflare_detected = False
        waf_type = None
        
        for f in findings:
            if "cloudflare" in f.tags:
                cloudflare_detected = True
                waf_type = "cloudflare"
            elif "waf" in f.tags:
                waf_type = f.title.lower().split("waf")[0].strip() or "unknown"

        # Add Cloudflare bypass paths
        if cloudflare_detected:
            self.paths.extend(AttackPathDefinitions.get_cloudflare_bypass_paths(target))
            
            # Check if bypass was successful
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    if data.get("bypass_achieved"):
                        # Update confidence for bypass paths
                        for path in self.paths:
                            if path.is_cloudflare_bypass:
                                path.confidence = 0.9
                                path.severity = "critical"
                except Exception:
                    pass

        # Add WAF bypass paths
        if waf_type and waf_type != "cloudflare":
            self.paths.extend(AttackPathDefinitions.get_waf_bypass_paths(waf_type, target))

        # Add standard paths
        self.paths.extend(AttackPathDefinitions.get_standard_paths())

        # Filter paths based on prerequisites
        self.paths = self._filter_paths(self.paths, findings)

        # Score paths
        for path in self.paths:
            path.confidence = self._score_path(path, findings)

        # Sort by confidence
        self.paths.sort(key=lambda p: p.confidence, reverse=True)

        return self.paths

    def _filter_paths(self, paths: List[AttackPath], findings: List[Finding]) -> List[AttackPath]:
        """Filter paths based on available findings."""
        filtered = []
        tags = set()
        for f in findings:
            tags.update(f.tags)

        for path in paths:
            # Check if prerequisites are met
            if path.prerequisites:
                prereq_met = all(
                    p.lower() in [t.lower() for t in tags] or
                    any(p.lower() in f.title.lower() for f in findings)
                    for p in path.prerequisites
                )
                if not prereq_met:
                    continue
            filtered.append(path)

        return filtered

    def _score_path(self, path: AttackPath, findings: List[Finding]) -> float:
        """Score an attack path based on evidence."""
        score = 0.5  # Base score

        # Boost for completed steps
        completed_steps = 0
        for step in path.steps:
            step_found = any(
                step.name.lower() in f.title.lower() or
                any(step.technique in f.tags for f in findings)
                for f in findings
            )
            if step_found:
                completed_steps += 1

        if path.steps:
            score += 0.3 * (completed_steps / len(path.steps))

        # Boost for Cloudflare bypass
        if path.is_cloudflare_bypass:
            score += 0.1

            # Check if bypass data exists
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    if data.get("bypass_achieved"):
                        score += 0.2
                except Exception:
                    pass

        # Boost for high severity findings
        for f in findings:
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                score += 0.05

        return min(score, 1.0)

    # ── Path analysis ────────────────────────────────────────

    def find_attack_chains(self) -> List[Dict]:
        """
        Find multi-step attack chains (combinations of paths).
        """
        if not self.paths:
            self.generate_paths()

        chains = []
        for path in self.paths:
            # Find paths that can be chained
            for other in self.paths:
                if path.id == other.id:
                    continue

                # Check if path prerequisites are met by other path
                if any(p in other.prerequisites for p in path.prerequisites):
                    chains.append({
                        "chain": f"{path.name} → {other.name}",
                        "first": path,
                        "second": other,
                        "confidence": (path.confidence + other.confidence) / 2,
                        "mitre": list(set(path.mitre_techniques + other.mitre_techniques))
                    })

        # Sort by confidence
        chains.sort(key=lambda c: c["confidence"], reverse=True)
        return chains

    def get_recommendations(self) -> List[Dict]:
        """
        Get recommendations based on attack paths.
        """
        if not self.paths:
            self.generate_paths()

        recommendations = []
        for path in self.paths[:3]:
            if path.confidence > 0.6:
                next_steps = []
                for step in path.steps:
                    step_found = False
                    for f in self.session.get_findings():
                        if step.name.lower() in f.title.lower():
                            step_found = True
                            break
                    if not step_found:
                        next_steps.append(step.name)
                        break

                if next_steps:
                    recommendations.append({
                        "path": path.name,
                        "next_step": next_steps[0],
                        "confidence": path.confidence,
                        "mitre": path.mitre_techniques,
                        "is_cloudflare_bypass": path.is_cloudflare_bypass
                    })

        return recommendations

    # ── Path visualization ───────────────────────────────────

    def render_path(self, path: AttackPath) -> str:
        """Render attack path as ASCII diagram."""
        lines = []
        lines.append(f"\033[1m{path.name}\033[0m")
        lines.append(f"  {path.description}")
        lines.append(f"  Confidence: {path.confidence*100:.0f}%")
        lines.append(f"  MITRE: {', '.join(path.mitre_techniques)}")
        lines.append("")

        for i, step in enumerate(path.steps):
            prefix = "├── " if i < len(path.steps) - 1 else "└── "
            lines.append(f"  {prefix}\033[36m{step.name}\033[0m")
            lines.append(f"      {step.description}")
            if step.technique:
                lines.append(f"      Technique: {step.technique}")
            if step.prerequisites:
                lines.append(f"      Requires: {', '.join(step.prerequisites)}")
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def map_attack_paths(
    session: Session,
    logger: Optional[ARDFLogger] = None,
    render: bool = False
) -> Dict[str, Any]:
    """
    Map attack paths from session findings.

    Args:
        session: Active ARDF session
        logger: ARDFLogger instance
        render: Render paths to console

    Returns:
        Dictionary with paths and recommendations
    """
    if logger is None:
        logger = get_logger("attack_path")

    logger.banner("ATTACK PATH MAPPING", style="bold red")

    mapper = AttackPathMapper(session, logger)
    paths = mapper.generate_paths()
    chains = mapper.find_attack_chains()
    recommendations = mapper.get_recommendations()

    # Save results
    result_path = session.dir("graph") / "attack_paths.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)

    result_data = {
        "paths": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "confidence": p.confidence,
                "severity": p.severity,
                "mitre_techniques": p.mitre_techniques,
                "is_cloudflare_bypass": p.is_cloudflare_bypass,
                "steps": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "technique": s.technique,
                        "description": s.description,
                        "prerequisites": s.prerequisites
                    }
                    for s in p.steps
                ]
            }
            for p in paths
        ],
        "chains": chains,
        "recommendations": recommendations
    }

    result_path.write_text(json.dumps(result_data, indent=2, default=str))
    logger.success(f"Attack paths saved → {result_path}")

    # Render if requested
    if render:
        print("\n" + "=" * 60)
        print("\033[1mATTACK PATHS\033[0m")
        print("=" * 60 + "\n")
        for path in paths[:5]:
            print(mapper.render_path(path))
            print("-" * 40)

        if recommendations:
            print("\033[1mRecommendations:\033[0m")
            for rec in recommendations[:3]:
                print(f"  • \033[36m{rec['next_step']}\033[0m ({rec['path']})")
                print(f"    Confidence: {rec['confidence']*100:.0f}%")

    # Add findings
    for path in paths[:3]:
        if path.confidence > 0.6:
            session.add_finding(Finding(
                source="graph.attack_path",
                title=f"Attack path identified: {path.name}",
                description=f"{path.description} (confidence: {path.confidence*100:.0f}%)",
                severity=SeverityLevel.HIGH if path.severity == "high" else SeverityLevel.MEDIUM,
                host=session.meta.target,
                tags=["attack_path", "mitre"] + path.mitre_techniques,
                evidence=json.dumps([{"step": s.name, "technique": s.technique} for s in path.steps])
            ))

    return result_data