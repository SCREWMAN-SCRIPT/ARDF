"""
modules/defense/sigma_writer.py
────────────────────────────────
Generates Sigma detection rules from ARDF findings.
Rules are written in standard Sigma YAML format and can be
imported directly into any Sigma-compatible SIEM.
"""

import uuid
import json
from datetime import datetime
from pathlib  import Path
from typing   import Any, Dict, List, Optional

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Sigma rule templates per finding category
# ─────────────────────────────────────────────────────────────

SIGMA_TEMPLATES: Dict[str, Dict] = {

    "port_scan": {
        "title":       "Network Port Scan Detected",
        "description": "Detects rapid sequential connection attempts indicative of port scanning",
        "logsource":   {"category": "network_connection", "product": "linux"},
        "detection": {
            "selection": {"event_type": "connection_attempt"},
            "timeframe": "1m",
            "condition": "selection | count() by src_ip > 50",
        },
        "level":       "medium",
        "tags":        ["attack.discovery", "attack.t1046"],
        "falsepositives": ["Legitimate network monitoring tools", "Vulnerability scanners"],
    },

    "subdomain_enum": {
        "title":       "Subdomain Enumeration via DNS",
        "description": "Detects high-volume DNS queries from a single source — indicative of subdomain enumeration",
        "logsource":   {"category": "dns_query", "product": "dns"},
        "detection": {
            "selection": {"query_type": "A"},
            "timeframe": "1m",
            "condition": "selection | count() by src_ip > 100",
        },
        "level":       "medium",
        "tags":        ["attack.reconnaissance", "attack.t1596"],
        "falsepositives": ["CDN resolvers", "Load balancers"],
    },

    "sqli": {
        "title":       "SQL Injection Attempt Detected",
        "description": "Detects common SQL injection patterns in HTTP request parameters",
        "logsource":   {"category": "webserver", "product": "nginx"},
        "detection": {
            "selection": {
                "request|contains": [
                    "' OR '1'='1",
                    "UNION SELECT",
                    "' AND SLEEP(",
                    "1=1--",
                    "admin'--",
                    "' OR 1=1",
                    "information_schema",
                    "WAITFOR DELAY",
                ],
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.initial_access", "attack.t1190"],
        "falsepositives": ["Legitimate security scanning", "Pen test activity"],
    },

    "xss": {
        "title":       "Cross-Site Scripting Attempt Detected",
        "description": "Detects XSS payload patterns in HTTP requests",
        "logsource":   {"category": "webserver", "product": "nginx"},
        "detection": {
            "selection": {
                "request|contains": [
                    "<script>",
                    "javascript:",
                    "onerror=",
                    "onload=",
                    "alert(",
                    "document.cookie",
                    "<img src=x",
                    "&#x3C;script",
                ],
            },
            "condition": "selection",
        },
        "level":       "medium",
        "tags":        ["attack.t1059.007"],
        "falsepositives": ["Security scanners", "WAF testing"],
    },

    "lfi": {
        "title":       "Local File Inclusion Attempt",
        "description": "Detects path traversal and LFI patterns in web requests",
        "logsource":   {"category": "webserver", "product": "nginx"},
        "detection": {
            "selection": {
                "request|contains": [
                    "../../../",
                    "..%2F..%2F",
                    "/etc/passwd",
                    "/etc/shadow",
                    "/proc/self",
                    "....//....//",
                    "%252e%252e",
                ],
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.t1083"],
        "falsepositives": ["Security scanners"],
    },

    "rce": {
        "title":       "Remote Command Execution Attempt",
        "description": "Detects command injection payloads in HTTP requests",
        "logsource":   {"category": "webserver", "product": "nginx"},
        "detection": {
            "selection": {
                "request|contains": [
                    ";id;",
                    "|id|",
                    "`id`",
                    "$(id)",
                    ";whoami",
                    "/bin/bash",
                    "/bin/sh",
                    "cmd.exe",
                    "powershell",
                ],
            },
            "condition": "selection",
        },
        "level":       "critical",
        "tags":        ["attack.execution", "attack.t1059"],
        "falsepositives": ["None expected in production"],
    },

    "ssrf": {
        "title":       "Server-Side Request Forgery Attempt",
        "description": "Detects SSRF payloads targeting internal infrastructure",
        "logsource":   {"category": "webserver", "product": "nginx"},
        "detection": {
            "selection": {
                "request|contains": [
                    "169.254.169.254",
                    "metadata.google.internal",
                    "localhost",
                    "127.0.0.1",
                    "0.0.0.0",
                    "file:///",
                    "dict://",
                    "gopher://",
                ],
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.t1090"],
        "falsepositives": ["Internal health checks"],
    },

    "brute_force": {
        "title":       "Authentication Brute Force Detected",
        "description": "Detects repeated failed authentication attempts from a single source",
        "logsource":   {"category": "authentication", "product": "linux"},
        "detection": {
            "selection": {
                "event_id":   [4625, 4771],
                "status":     "failure",
            },
            "timeframe": "5m",
            "condition": "selection | count() by src_ip > 10",
        },
        "level":       "high",
        "tags":        ["attack.credential_access", "attack.t1110"],
        "falsepositives": ["Misconfigured services", "Forgotten passwords"],
    },

    "smb_enum": {
        "title":       "SMB Enumeration Activity",
        "description": "Detects SMB share enumeration — common in network reconnaissance",
        "logsource":   {"category": "network_connection", "product": "windows"},
        "detection": {
            "selection": {
                "dst_port":  445,
                "protocol":  "tcp",
            },
            "timeframe": "1m",
            "condition": "selection | count() by src_ip > 20",
        },
        "level":       "medium",
        "tags":        ["attack.discovery", "attack.t1135"],
        "falsepositives": ["Windows domain operations", "Backup software"],
    },

    "weak_tls": {
        "title":       "Weak TLS Protocol or Cipher Detected",
        "description": "Detects connections using deprecated TLS versions or weak cipher suites",
        "logsource":   {"category": "network_connection", "product": "linux"},
        "detection": {
            "selection": {
                "tls_version|contains": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
            },
            "condition": "selection",
        },
        "level":       "medium",
        "tags":        ["attack.t1040"],
        "falsepositives": ["Legacy application requirements"],
    },

    "secret_in_code": {
        "title":       "Hardcoded Secret or API Key Exposure",
        "description": "Detects potential hardcoded credentials or tokens in file access logs",
        "logsource":   {"category": "file_event", "product": "linux"},
        "detection": {
            "selection": {
                "file_name|contains": [".env", "config.js", "secrets.yaml",
                                       "credentials.json", ".npmrc", ".git-credentials"],
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.credential_access", "attack.t1552"],
        "falsepositives": ["Developers accessing config files"],
    },

    "dns_takeover": {
        "title":       "Potential Subdomain Takeover",
        "description": "Detects DNS CNAME pointing to unclaimed cloud resources",
        "logsource":   {"category": "dns_query", "product": "dns"},
        "detection": {
            "selection": {
                "answer|contains": [
                    "azurewebsites.net",
                    "s3.amazonaws.com",
                    "herokuapp.com",
                    "github.io",
                    "netlify.app",
                ],
                "response_code": "NXDOMAIN",
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.t1584"],
        "falsepositives": ["DNS propagation delays"],
    },

    "privesc": {
        "title":       "Privilege Escalation Attempt",
        "description": "Detects SUID binary execution or sudo abuse patterns",
        "logsource":   {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "commandline|contains": [
                    "sudo -l",
                    "sudo su",
                    "/bin/bash -p",
                    "chmod +s",
                    "python -c 'import os",
                    "perl -e 'exec",
                ],
            },
            "condition": "selection",
        },
        "level":       "high",
        "tags":        ["attack.privilege_escalation", "attack.t1548"],
        "falsepositives": ["System administrators", "Legitimate maintenance"],
    },

    "cloud_bucket": {
        "title":       "Cloud Storage Bucket Enumeration",
        "description": "Detects attempts to access or enumerate cloud storage buckets",
        "logsource":   {"category": "proxy", "product": "linux"},
        "detection": {
            "selection": {
                "url|contains": [
                    "s3.amazonaws.com",
                    "storage.googleapis.com",
                    "blob.core.windows.net",
                ],
                "status_code": [200, 403],
            },
            "condition": "selection",
        },
        "level":       "medium",
        "tags":        ["attack.collection", "attack.t1530"],
        "falsepositives": ["Legitimate cloud storage access"],
    },
}

# Map finding tags/keywords → sigma template keys
TAG_TO_TEMPLATE: Dict[str, str] = {
    "sqli":         "sqli",
    "sql":          "sqli",
    "xss":          "xss",
    "lfi":          "lfi",
    "rfi":          "lfi",
    "rce":          "rce",
    "cmdi":         "rce",
    "ssrf":         "ssrf",
    "brute":        "brute_force",
    "bruteforce":   "brute_force",
    "brute-force":  "brute_force",
    "smb":          "smb_enum",
    "ssl":          "weak_tls",
    "tls":          "weak_tls",
    "secret":       "secret_in_code",
    "takeover":     "dns_takeover",
    "subdomain":    "subdomain_enum",
    "port":         "port_scan",
    "nmap":         "port_scan",
    "masscan":      "port_scan",
    "privesc":      "privesc",
    "suid":         "privesc",
    "cloud":        "cloud_bucket",
    "s3":           "cloud_bucket",
    "bucket":       "cloud_bucket",
}


# ─────────────────────────────────────────────────────────────
# SigmaWriter
# ─────────────────────────────────────────────────────────────

class SigmaWriter:
    """
    Generates Sigma detection rules from ARDF session findings.

    Usage
    ─────
        writer = SigmaWriter(session, logger)
        rules  = writer.generate_all()
        writer.save_rules(rules, output_dir)
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("defense.sigma")
        self._today  = datetime.utcnow().strftime("%Y-%m-%d")

    # ── Public API ────────────────────────────────────────────

    def generate_all(self) -> List[Dict]:
        """Generate Sigma rules for all session findings."""
        findings = self.session.get_findings()
        if not findings:
            self.logger.warning("No findings to generate Sigma rules for")
            return []

        rules     = []
        seen_keys = set()

        for finding in findings:
            template_key = self._resolve_template(finding)
            if not template_key or template_key in seen_keys:
                continue
            rule = self._build_rule(template_key, finding)
            if rule:
                rules.append(rule)
                seen_keys.add(template_key)

        self.logger.success(f"Generated {len(rules)} Sigma rules from {len(findings)} findings")
        return rules

    def generate_for_finding(self, finding: Finding) -> Optional[Dict]:
        """Generate a single Sigma rule for one finding."""
        template_key = self._resolve_template(finding)
        if not template_key:
            return None
        return self._build_rule(template_key, finding)

    def generate_for_technique(self, technique: str, context: Dict) -> Optional[Dict]:
        """
        Generate a Sigma rule for a specific attack technique.
        Called by purple_runner when a technique is observed.
        """
        template_key = TAG_TO_TEMPLATE.get(technique.lower())
        if not template_key or template_key not in SIGMA_TEMPLATES:
            return None

        tmpl = SIGMA_TEMPLATES[template_key].copy()
        rule_id = str(uuid.uuid4())

        return {
            "id":            rule_id,
            "template_key":  template_key,
            "title":         tmpl["title"],
            "level":         tmpl["level"],
            "sigma_rule":    self._render_yaml(rule_id, tmpl, context),
            "tags":          tmpl.get("tags", []),
            "falsepositives":tmpl.get("falsepositives", []),
        }

    def save_rules(
        self,
        rules:      List[Dict],
        output_dir: Optional[Path] = None,
    ) -> List[Path]:
        """Save all generated Sigma rules as individual YAML files."""
        out = output_dir or self.session.dir("report") / "sigma_rules"
        out.mkdir(parents=True, exist_ok=True)
        saved = []
        for rule in rules:
            safe_title = rule["title"].replace(" ", "_").replace("/", "_")[:50]
            path = out / f"sigma_{safe_title}.yml"
            path.write_text(rule["sigma_rule"], encoding="utf-8")
            saved.append(path)
        self.logger.success(f"Saved {len(saved)} Sigma rules to {out}")
        return saved

    # ── Rule building ─────────────────────────────────────────

    def _build_rule(self, template_key: str, finding: Finding) -> Optional[Dict]:
        """Build a complete Sigma rule dict from a template + finding."""
        if template_key not in SIGMA_TEMPLATES:
            return None

        tmpl    = SIGMA_TEMPLATES[template_key].copy()
        rule_id = str(uuid.uuid4())
        context = {
            "finding_title": finding.title,
            "host":          finding.host,
            "cve":           finding.cve or "",
        }

        return {
            "id":             rule_id,
            "template_key":   template_key,
            "title":          tmpl["title"],
            "level":          tmpl["level"],
            "finding_id":     finding.id,
            "finding_title":  finding.title,
            "sigma_rule":     self._render_yaml(rule_id, tmpl, context),
            "tags":           tmpl.get("tags", []),
            "falsepositives": tmpl.get("falsepositives", []),
            "mitre_tags":     tmpl.get("tags", []),
        }

    def _render_yaml(
        self,
        rule_id: str,
        tmpl:    Dict,
        context: Dict,
    ) -> str:
        """Render a Sigma rule as a YAML string."""
        title       = tmpl.get("title", "ARDF Detection Rule")
        description = tmpl.get("description", "")
        level       = tmpl.get("level", "medium")
        logsource   = tmpl.get("logsource", {})
        detection   = tmpl.get("detection", {})
        tags        = tmpl.get("tags", [])
        falsepos    = tmpl.get("falsepositives", ["Unknown"])
        cve         = context.get("cve", "")

        refs = ["https://github.com/SigmaHQ/sigma"]
        if cve:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        # Logsource block
        ls_lines = "\n".join(
            f"    {k}: {v}" for k, v in logsource.items()
        )

        # Detection block
        det_lines = self._render_detection(detection)

        # Tags block
        tag_lines = "\n".join(f"    - {t}" for t in tags)

        # False positives
        fp_lines = "\n".join(f"    - {f}" for f in falsepos)

        # References
        ref_lines = "\n".join(f"    - {r}" for r in refs)

        return (
            f"title: {title}\n"
            f"id: {rule_id}\n"
            f"status: experimental\n"
            f"description: |\n"
            f"    {description}\n"
            f"    Generated by ARDF for finding: {context.get('finding_title','')}\n"
            f"references:\n"
            f"{ref_lines}\n"
            f"author: ARDF\n"
            f"date: {self._today}\n"
            f"tags:\n"
            f"{tag_lines}\n"
            f"logsource:\n"
            f"{ls_lines}\n"
            f"detection:\n"
            f"{det_lines}\n"
            f"falsepositives:\n"
            f"{fp_lines}\n"
            f"level: {level}\n"
        )

    def _render_detection(self, detection: Dict, indent: int = 4) -> str:
        """Render detection block as YAML lines."""
        lines = []
        pad   = " " * indent

        for key, value in detection.items():
            if isinstance(value, dict):
                lines.append(f"{pad}{key}:")
                for k2, v2 in value.items():
                    if isinstance(v2, list):
                        lines.append(f"{pad}    {k2}:")
                        for item in v2:
                            lines.append(f"{pad}        - '{item}'")
                    else:
                        lines.append(f"{pad}    {k2}: {v2}")
            elif isinstance(value, list):
                lines.append(f"{pad}{key}:")
                for item in value:
                    lines.append(f"{pad}    - {item}")
            else:
                lines.append(f"{pad}{key}: {value}")

        return "\n".join(lines)

    # ── Template resolution ───────────────────────────────────

    def _resolve_template(self, finding: Finding) -> Optional[str]:
        """Map a finding to the best matching Sigma template."""
        # Check tags first
        for tag in finding.tags:
            key = TAG_TO_TEMPLATE.get(tag.lower())
            if key:
                return key

        # Check title keywords
        title_lower = finding.title.lower()
        for keyword, key in TAG_TO_TEMPLATE.items():
            if keyword in title_lower:
                return key

        # Check source
        source_map = {
            "recon.passive": "subdomain_enum",
            "recon.normal":  "port_scan",
            "recon.depth":   "port_scan",
        }
        return source_map.get(finding.source)
