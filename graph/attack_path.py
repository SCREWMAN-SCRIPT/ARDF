"""
graph/attack_path.py
────────────────────
Attack path detection for ARDF.

Enhanced with new attack paths for SQL injection and brute-force.
"""

import json
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


@dataclass
class AttackStep:
    id: str
    name: str
    technique: str
    description: str
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    id: str
    name: str
    description: str
    steps: List[AttackStep]
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    severity: str = "medium"
    prerequisites: List[str] = field(default_factory=list)
    is_cloudflare_bypass: bool = False


class AttackPathDefinitions:
    """Pre-defined attack path templates including new SQLi and brute-force paths."""

    @staticmethod
    def get_cloudflare_bypass_paths(target: str) -> List[AttackPath]:
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
                    AttackStep("cf_recon", "Cloudflare Reconnaissance", "T1046",
                              "Detect Cloudflare and identify version", []),
                    AttackStep("cf_bypass", "Cloudflare Bypass", "T1584",
                              "Execute bypass techniques to find origin IP", ["cf_recon"]),
                    AttackStep("origin_attack", "Direct Origin Attack", "T1190",
                              "Attack origin IP directly", ["cf_bypass"])
                ]
            )
        ]

    @staticmethod
    def get_sqli_paths(target: str) -> List[AttackPath]:
        """SQL injection attack paths."""
        return [
            AttackPath(
                id=f"sqli_{target}",
                name="SQL Injection Attack",
                description="Exploit SQL injection vulnerability to extract data",
                severity="critical",
                confidence=0.8,
                mitre_techniques=["T1190", "T1505", "T1041"],
                prerequisites=["sqli_parameters_found"],
                steps=[
                    AttackStep("sqli_recon", "SQL Injection Discovery", "T1190",
                              "Identify SQL injection points", []),
                    AttackStep("sqli_validate", "SQL Injection Validation", "T1505",
                              "Confirm SQL injection vulnerability", ["sqli_recon"]),
                    AttackStep("sqli_exploit", "SQL Injection Exploitation", "T1041",
                              "Extract data from database", ["sqli_validate"])
                ]
            ),
            AttackPath(
                id=f"sqli_oauth_{target}",
                name="SQL Injection via OAuth",
                description="Exploit SQL injection in OAuth flow",
                severity="critical",
                confidence=0.6,
                mitre_techniques=["T1190", "T1550"],
                prerequisites=["oauth_detected", "sqli_parameters_found"],
                steps=[
                    AttackStep("oauth_recon", "OAuth Flow Discovery", "T1550",
                              "Identify OAuth endpoints", []),
                    AttackStep("sqli_oauth", "SQL Injection in OAuth", "T1190",
                              "Inject SQL in OAuth parameters", ["oauth_recon"]),
                    AttackStep("oauth_bypass", "OAuth Flow Bypass", "T1550",
                              "Bypass OAuth with SQL injection", ["sqli_oauth"])
                ]
            )
        ]

    @staticmethod
    def get_bruteforce_paths(target: str) -> List[AttackPath]:
        """Brute-force attack paths."""
        return [
            AttackPath(
                id=f"bruteforce_{target}",
                name="Credential Brute-Force",
                description="Brute-force authentication credentials",
                severity="high",
                confidence=0.7,
                mitre_techniques=["T1110", "T1078"],
                prerequisites=["login_endpoints_found"],
                steps=[
                    AttackStep("auth_recon", "Authentication Discovery", "T1110",
                              "Identify login endpoints and auth methods", []),
                    AttackStep("bruteforce_attack", "Credential Brute-Force", "T1110",
                              "Attempt to brute-force credentials", ["auth_recon"]),
                    AttackStep("credential_use", "Credential Usage", "T1078",
                              "Use found credentials for access", ["bruteforce_attack"])
                ]
            ),
            AttackPath(
                id=f"default_creds_{target}",
                name="Default Credential Exploitation",
                description="Exploit default credentials on services",
                severity="critical",
                confidence=0.8,
                mitre_techniques=["T1110", "T1078"],
                prerequisites=["service_detected"],
                steps=[
                    AttackStep("service_recon", "Service Discovery", "T1110",
                              "Identify services with default credentials", []),
                    AttackStep("default_creds", "Default Credential Testing", "T1110",
                              "Test default credentials on services", ["service_recon"]),
                    AttackStep("service_access", "Service Access", "T1078",
                              "Access service with default credentials", ["default_creds"])
                ]
            )
        ]

    @staticmethod
    def get_standard_paths() -> List[AttackPath]:
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
                    AttackStep("web_recon", "Web Reconnaissance", "T1046",
                              "Discover web endpoints and technologies", []),
                    AttackStep("web_vuln", "Vulnerability Discovery", "T1046",
                              "Find vulnerabilities", ["web_recon"]),
                    AttackStep("web_exploit", "Web Exploitation", "T1190",
                              "Exploit discovered vulnerability", ["web_vuln"])
                ]
            )
        ]


class AttackPathMapper:
    """Map findings to attack paths."""

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("attack_path")
        self.paths: List[AttackPath] = []

    def generate_paths(self, findings: Optional[List[Finding]] = None) -> List[AttackPath]:
        if findings is None:
            findings = self.session.get_findings()

        target = self.session.meta.target
        self.paths = []

        # Detect conditions
        cloudflare_detected = False
        sqli_detected = False
        bruteforce_detected = False
        login_endpoints_found = False
        oauth_detected = False
        service_detected = False

        for f in findings:
            if "cloudflare" in f.tags:
                cloudflare_detected = True
            if "sqli" in f.tags or "injection" in f.tags:
                sqli_detected = True
            if "bruteforce" in f.tags or "auth" in f.tags:
                bruteforce_detected = True
            if "login" in f.tags or "portal" in f.tags:
                login_endpoints_found = True
            if "oauth" in f.tags:
                oauth_detected = True
            if "service" in f.tags:
                service_detected = True

        # Add Cloudflare paths
        if cloudflare_detected:
            self.paths.extend(AttackPathDefinitions.get_cloudflare_bypass_paths(target))
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    if data.get("bypass_achieved"):
                        for path in self.paths:
                            if path.is_cloudflare_bypass:
                                path.confidence = 0.9
                                path.severity = "critical"
                except Exception:
                    pass

        # Add SQLi paths
        if sqli_detected:
            self.paths.extend(AttackPathDefinitions.get_sqli_paths(target))
            for path in self.paths:
                if "sqli" in path.id:
                    path.confidence = 0.85
                    path.severity = "critical"

        # Add brute-force paths
        if bruteforce_detected or login_endpoints_found:
            self.paths.extend(AttackPathDefinitions.get_bruteforce_paths(target))
            for path in self.paths:
                if "bruteforce" in path.id or "default_creds" in path.id:
                    path.confidence = 0.75
                    path.severity = "high"

        # Add OAuth SQLi path
        if oauth_detected and sqli_detected:
            for path in AttackPathDefinitions.get_sqli_paths(target):
                if "oauth" in path.id:
                    self.paths.append(path)

        # Add standard paths
        self.paths.extend(AttackPathDefinitions.get_standard_paths())

        # Score paths
        for path in self.paths:
            path.confidence = min(path.confidence + 0.1, 1.0)

        # Sort by confidence
        self.paths.sort(key=lambda p: p.confidence, reverse=True)

        return self.paths

    def get_recommendations(self) -> List[Dict]:
        if not self.paths:
            self.generate_paths()

        recommendations = []
        for path in self.paths[:5]:
            if path.confidence > 0.5:
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
                        "is_cloudflare_bypass": path.is_cloudflare_bypass,
                        "is_sqli": "sqli" in path.id,
                        "is_bruteforce": "bruteforce" in path.id,
                    })

        return recommendations


def map_attack_paths(session: Session, logger: Optional[ARDFLogger] = None,
                     render: bool = False) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("attack_path")

    logger.banner("ATTACK PATH MAPPING", style="bold red")

    mapper = AttackPathMapper(session, logger)
    paths = mapper.generate_paths()
    recommendations = mapper.get_recommendations()

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
                "steps": [{"id": s.id, "name": s.name, "technique": s.technique} for s in p.steps]
            }
            for p in paths
        ],
        "recommendations": recommendations
    }

    result_path = session.dir("graph") / "attack_paths.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result_data, indent=2, default=str))
    logger.success(f"Attack paths saved → {result_path}")

    # Add findings for high-confidence paths
    for path in paths[:3]:
        if path.confidence > 0.6:
            session.add_finding(Finding(
                source="graph.attack_path",
                title=f"Attack path identified: {path.name}",
                description=f"{path.description} (confidence: {path.confidence*100:.0f}%)",
                severity=SeverityLevel.HIGH if path.severity == "critical" else SeverityLevel.MEDIUM,
                host=session.meta.target,
                tags=["attack_path", "mitre"] + path.mitre_techniques,
                evidence=json.dumps([{"step": s.name, "technique": s.technique} for s in path.steps])
            ))

    return result_data