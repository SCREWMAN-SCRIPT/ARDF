"""
modules/validate/classifier.py
──────────────────────────────
Vulnerability classification and routing.

Categorizes findings into vulnerability types and routes
them to the appropriate validation modules.

Categories:
  A: Web Application (HTTP/HTTPS)
  B: Network Services & Protocols
  C: Authentication & Access Control
  D: Data Exposure & Information Disclosure
  E: Cryptography & Encryption
  F: Cloud & Infrastructure
  G: Database & Data Storage
  H: Business Logic & Configuration
  I: Supply Chain & Third-Party
  J: Physical & Social Engineering
"""

import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


class VulnCategory(Enum):
    """Vulnerability categories."""
    WEB_APPLICATION = "A"
    NETWORK_SERVICES = "B"
    AUTHENTICATION = "C"
    DATA_EXPOSURE = "D"
    CRYPTOGRAPHY = "E"
    CLOUD_INFRASTRUCTURE = "F"
    DATABASE = "G"
    BUSINESS_LOGIC = "H"
    SUPPLY_CHAIN = "I"
    SOCIAL_ENGINEERING = "J"


class VulnType(Enum):
    """Specific vulnerability types."""
    # Web Application
    SQLI = "sqli"
    NOSQLI = "nosqli"
    LDAPI = "ldapi"
    CMDI = "cmdi"
    CODEI = "codei"
    XXE = "xxe"
    XPATHI = "xpathi"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    
    # Authentication
    BRUTE_FORCE = "bruteforce"
    DEFAULT_CREDS = "default_creds"
    SESSION_FIXATION = "session_fixation"
    JWT_ATTACK = "jwt_attack"
    OAUTH_ATTACK = "oauth_attack"
    MFA_BYPASS = "mfa_bypass"
    
    # Network
    SMB_NULL = "smb_null"
    SNMP_DEFAULT = "snmp_default"
    FTP_ANON = "ftp_anon"
    DNS_ZONE = "dns_zone"
    
    # Cloud
    S3_PUBLIC = "s3_public"
    K8S_EXPOSED = "k8s_exposed"
    IAC_EXPOSED = "iac_exposed"


@dataclass
class ClassifiedVulnerability:
    """A classified vulnerability ready for validation."""
    finding: Finding
    category: VulnCategory
    vuln_type: VulnType
    validator_module: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    priority: int = 0
    requires_confirmation: bool = True


class VulnerabilityClassifier:
    """
    Classify findings and route to validation modules.
    """

    # Category mapping
    CATEGORY_MAP = {
        "sqli": VulnCategory.WEB_APPLICATION,
        "nosqli": VulnCategory.WEB_APPLICATION,
        "ldapi": VulnCategory.WEB_APPLICATION,
        "cmdi": VulnCategory.WEB_APPLICATION,
        "codei": VulnCategory.WEB_APPLICATION,
        "xxe": VulnCategory.WEB_APPLICATION,
        "xpathi": VulnCategory.WEB_APPLICATION,
        "path_traversal": VulnCategory.WEB_APPLICATION,
        "xss": VulnCategory.WEB_APPLICATION,
        "csrf": VulnCategory.WEB_APPLICATION,
        "ssrf": VulnCategory.WEB_APPLICATION,
        "ssti": VulnCategory.WEB_APPLICATION,
        "open_redirect": VulnCategory.WEB_APPLICATION,
        
        "bruteforce": VulnCategory.AUTHENTICATION,
        "default_creds": VulnCategory.AUTHENTICATION,
        "session_fixation": VulnCategory.AUTHENTICATION,
        "jwt_attack": VulnCategory.AUTHENTICATION,
        "oauth_attack": VulnCategory.AUTHENTICATION,
        "mfa_bypass": VulnCategory.AUTHENTICATION,
        
        "smb_null": VulnCategory.NETWORK_SERVICES,
        "snmp_default": VulnCategory.NETWORK_SERVICES,
        "ftp_anon": VulnCategory.NETWORK_SERVICES,
        "dns_zone": VulnCategory.NETWORK_SERVICES,
        
        "s3_public": VulnCategory.CLOUD_INFRASTRUCTURE,
        "k8s_exposed": VulnCategory.CLOUD_INFRASTRUCTURE,
        "iac_exposed": VulnCategory.CLOUD_INFRASTRUCTURE,
    }

    # Validator module mapping
    VALIDATOR_MAP = {
        VulnType.SQLI: "validate.sqli",
        VulnType.NOSQLI: "validate.nosqli",
        VulnType.LDAPI: "validate.ldap",
        VulnType.CMDI: "validate.cmdi",
        VulnType.CODEI: "validate.code",
        VulnType.XXE: "validate.xxe",
        VulnType.XPATHI: "validate.xpath",
        VulnType.PATH_TRAVERSAL: "validate.path_traversal",
        VulnType.XSS: "validate.xss",
        VulnType.CSRF: "validate.csrf",
        VulnType.SSRF: "validate.ssrf",
        VulnType.SSTI: "validate.ssti",
        VulnType.OPEN_REDIRECT: "validate.open_redirect",
        VulnType.BRUTE_FORCE: "validate.auth",
        VulnType.DEFAULT_CREDS: "validate.auth",
        VulnType.SESSION_FIXATION: "validate.session",
        VulnType.JWT_ATTACK: "validate.jwt",
        VulnType.OAUTH_ATTACK: "validate.oauth",
        VulnType.MFA_BYPASS: "validate.mfa",
        VulnType.SMB_NULL: "validate.network",
        VulnType.SNMP_DEFAULT: "validate.network",
        VulnType.FTP_ANON: "validate.network",
        VulnType.DNS_ZONE: "validate.network",
        VulnType.S3_PUBLIC: "validate.cloud",
        VulnType.K8S_EXPOSED: "validate.cloud",
        VulnType.IAC_EXPOSED: "validate.cloud",
    }

    # Detection patterns for each vulnerability type
    PATTERNS = {
        VulnType.SQLI: [
            r"SQL syntax",
            r"mysql",
            r"postgres",
            r"mssql",
            r"oracle",
            r"sqlite",
            r"SQL error",
            r"Warning: mysql",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB",
            r"SQLSTATE",
        ],
        VulnType.NOSQLI: [
            r"MongoDB",
            r"mongodb",
            r"Redis",
            r"redis",
            r"Elasticsearch",
            r"elastic",
            r"GraphQL",
            r"graphql",
        ],
        VulnType.LDAPI: [
            r"LDAP",
            r"ldap",
            r"filter",
            r"search",
            r"dn",
        ],
        VulnType.CMDI: [
            r"command",
            r"exec",
            r"system",
            r"shell",
            r"passthru",
            r"popen",
            r"proc_open",
        ],
        VulnType.XXE: [
            r"XML",
            r"DOCTYPE",
            r"entity",
            r"xxe",
            r"external entity",
        ],
        VulnType.PATH_TRAVERSAL: [
            r"\.\./",
            r"\.\.\\",
            r"file:",
            r"etc/passwd",
            r"windows/win.ini",
        ],
        VulnType.XSS: [
            r"script",
            r"alert",
            r"onerror",
            r"onload",
            r"javascript:",
        ],
        VulnType.SSRF: [
            r"url",
            r"fetch",
            r"request",
            r"curl",
            r"wget",
        ],
        VulnType.SSTI: [
            r"\{\{",
            r"\{%",
            r"\{\#",
            r"{{",
            r"}}",
        ],
        VulnType.JWT_ATTACK: [
            r"JWT",
            r"jwt",
            r"json web token",
            r"alg:none",
        ],
        VulnType.DEFAULT_CREDS: [
            r"default",
            r"default password",
            r"admin:admin",
            r"root:root",
        ],
        VulnType.S3_PUBLIC: [
            r"s3",
            r"bucket",
            r"public",
            r"aws",
            r"amazon",
        ],
        VulnType.K8S_EXPOSED: [
            r"kubernetes",
            r"k8s",
            r"kube",
            r"pod",
            r"namespace",
        ],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.classifier")

    def classify_finding(self, finding: Finding) -> Optional[ClassifiedVulnerability]:
        """
        Classify a single finding.
        """
        if not finding.tags:
            return None

        vuln_type = None
        confidence = 0.0
        evidence = []

        # Check tags first
        for tag in finding.tags:
            tag_lower = tag.lower()
            for vt, patterns in self.PATTERNS.items():
                if tag_lower == vt.value or tag_lower in vt.value:
                    vuln_type = vt
                    confidence = 0.8
                    evidence.append(f"Tag match: {tag}")
                    break
            if vuln_type:
                break

        # Check title and description
        if not vuln_type:
            text = f"{finding.title} {finding.description}".lower()
            for vt, patterns in self.PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.I):
                        vuln_type = vt
                        confidence = 0.6
                        evidence.append(f"Pattern match: {pattern}")
                        break
                if vuln_type:
                    break

        if not vuln_type:
            return None

        # Get category
        category = self.CATEGORY_MAP.get(vuln_type.value, VulnCategory.WEB_APPLICATION)

        # Get validator module
        validator = self.VALIDATOR_MAP.get(vuln_type, "validate.generic")

        # Calculate priority based on severity and confidence
        priority = 0
        if finding.severity == SeverityLevel.CRITICAL:
            priority += 10
        elif finding.severity == SeverityLevel.HIGH:
            priority += 7
        elif finding.severity == SeverityLevel.MEDIUM:
            priority += 4
        else:
            priority += 1

        if confidence > 0.7:
            priority += 2

        requires_confirmation = finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)

        return ClassifiedVulnerability(
            finding=finding,
            category=category,
            vuln_type=vuln_type,
            validator_module=validator,
            confidence=confidence,
            evidence=evidence,
            priority=priority,
            requires_confirmation=requires_confirmation,
        )

    def classify_findings(self, findings: List[Finding]) -> Dict[VulnCategory, List[ClassifiedVulnerability]]:
        """
        Classify multiple findings and group by category.
        """
        classified = {cat: [] for cat in VulnCategory}

        for finding in findings:
            result = self.classify_finding(finding)
            if result:
                classified[result.category].append(result)

        # Sort by priority
        for cat in classified:
            classified[cat].sort(key=lambda x: x.priority, reverse=True)

        return classified

    def get_validation_plan(self, findings: List[Finding]) -> Dict[str, List[ClassifiedVulnerability]]:
        """
        Generate a validation plan grouped by validator module.
        """
        classified = self.classify_findings(findings)

        plan: Dict[str, List[ClassifiedVulnerability]] = {}

        for cat, vulns in classified.items():
            for vuln in vulns:
                module = vuln.validator_module
                if module not in plan:
                    plan[module] = []
                plan[module].append(vuln)

        return plan

    def get_recommendations(self, classified: List[ClassifiedVulnerability]) -> List[Dict]:
        """
        Get recommendations for validation.
        """
        recommendations = []

        for vuln in classified[:10]:
            recommendations.append({
                "finding_id": vuln.finding.id,
                "vuln_type": vuln.vuln_type.value,
                "category": vuln.category.value,
                "module": vuln.validator_module,
                "priority": vuln.priority,
                "confidence": vuln.confidence,
                "requires_confirmation": vuln.requires_confirmation,
                "title": vuln.finding.title,
                "host": vuln.finding.host,
                "port": vuln.finding.port,
                "cve": vuln.finding.cve,
                "evidence": vuln.evidence[:3],
            })

        return recommendations

    def run(self, findings: Optional[List[Finding]] = None) -> Dict[str, Any]:
        """
        Run vulnerability classification.
        """
        if findings is None:
            findings = self.session.get_findings()

        self.logger.banner("VULNERABILITY CLASSIFICATION", style="bold yellow")

        classified = self.classify_findings(findings)
        plan = self.get_validation_plan(findings)

        # Count by category
        counts = {cat.value: len(vulns) for cat, vulns in classified.items() if vulns}

        self.logger.success(f"Classified {len(findings)} findings into {len(plan)} validation modules")

        result = {
            "total_findings": len(findings),
            "classified_count": sum(len(v) for v in classified.values()),
            "counts_by_category": counts,
            "validation_plan": {k: len(v) for k, v in plan.items()},
            "classified": {cat.value: [self._vuln_to_dict(v) for v in vulns] for cat, vulns in classified.items() if vulns},
            "recommendations": self.get_recommendations(sum(classified.values(), [])),
        }

        # Save results
        report_path = self.session.dir("validate") / "classification_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result, indent=2, default=str))

        return result

    def _vuln_to_dict(self, vuln: ClassifiedVulnerability) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "finding_id": vuln.finding.id,
            "title": vuln.finding.title,
            "category": vuln.category.value,
            "vuln_type": vuln.vuln_type.value,
            "validator": vuln.validator_module,
            "confidence": vuln.confidence,
            "priority": vuln.priority,
            "requires_confirmation": vuln.requires_confirmation,
            "host": vuln.finding.host,
            "port": vuln.finding.port,
            "cve": vuln.finding.cve,
            "evidence": vuln.evidence,
        }