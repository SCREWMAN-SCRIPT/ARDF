"""
modules/defense/remediation.py
───────────────────────────────
RemediationBuilder — generates structured remediation plans
from session findings.

Outputs
───────
  - Prioritised remediation action list
  - Per-finding remediation notes
  - Markdown remediation report
  - JSON remediation export
"""

import json
from datetime import datetime
from pathlib  import Path
from typing   import Dict, List, Optional

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Static remediation library
# ─────────────────────────────────────────────────────────────

REMEDIATION_MAP: Dict[str, Dict] = {

    "sqli": {
        "title":   "SQL Injection",
        "steps": [
            "Replace all dynamic SQL queries with parameterised statements or ORM queries",
            "Implement input validation and whitelist allowable characters",
            "Apply least-privilege database accounts — no DROP, CREATE, or GRANT",
            "Enable WAF rules targeting SQL injection patterns (OWASP CRS)",
            "Audit all database query construction in the codebase",
        ],
        "effort":    "medium",
        "timeline":  "1–2 weeks",
        "owner":     "Development team",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },

    "xss": {
        "title":   "Cross-Site Scripting (XSS)",
        "steps": [
            "HTML-encode all user-supplied output before rendering in templates",
            "Implement a strict Content-Security-Policy header",
            "Use HttpOnly and Secure flags on all session cookies",
            "Adopt a modern templating engine with auto-escaping enabled",
            "Add X-XSS-Protection and X-Content-Type-Options headers",
        ],
        "effort":    "medium",
        "timeline":  "1–2 weeks",
        "owner":     "Development team",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },

    "lfi": {
        "title":   "Local / Remote File Inclusion",
        "steps": [
            "Never use user input to construct file paths",
            "Implement a whitelist of allowable file names/paths",
            "Run the web server process as a non-privileged user",
            "Disable allow_url_include and allow_url_fopen in PHP",
            "Chroot or containerise the web application",
        ],
        "effort":    "medium",
        "timeline":  "1 week",
        "owner":     "Development team",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
    },

    "rce": {
        "title":   "Remote Code Execution",
        "steps": [
            "Eliminate any use of eval(), exec(), system() with user-supplied input",
            "Apply virtual patching via WAF while permanent fix is developed",
            "Isolate the affected service in a container or VM immediately",
            "Rotate all credentials that may have been exposed",
            "Audit all command execution calls in the codebase",
            "Apply the vendor patch or update to a non-vulnerable version",
        ],
        "effort":    "high",
        "timeline":  "Immediate — patch within 24 hours",
        "owner":     "Development + Security teams",
        "references": [
            "https://owasp.org/www-community/attacks/Code_Injection",
        ],
    },

    "ssrf": {
        "title":   "Server-Side Request Forgery (SSRF)",
        "steps": [
            "Validate and sanitise all user-supplied URLs before making server-side requests",
            "Implement an allowlist of permitted destinations — deny all others",
            "Block access to link-local and loopback addresses (169.254.x.x, 127.x.x.x)",
            "Use a separate network zone for outbound HTTP requests with no internal access",
            "Disable unnecessary URL schemes (file://, dict://, gopher://)",
        ],
        "effort":    "medium",
        "timeline":  "1–2 weeks",
        "owner":     "Development team",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },

    "ssti": {
        "title":   "Server-Side Template Injection (SSTI)",
        "steps": [
            "Never pass user-supplied input directly into template rendering functions",
            "Use a sandboxed template environment where available",
            "Validate and sanitise all data before passing to templates",
            "Upgrade to a non-vulnerable version of the template engine",
        ],
        "effort":    "medium",
        "timeline":  "1 week",
        "owner":     "Development team",
        "references": [
            "https://portswigger.net/research/server-side-template-injection",
        ],
    },

    "xxe": {
        "title":   "XML External Entity Injection (XXE)",
        "steps": [
            "Disable external entity processing in the XML parser",
            "Use a less complex data format such as JSON where possible",
            "Patch or upgrade the XML parsing library",
            "Validate and sanitise all XML input before parsing",
        ],
        "effort":    "low",
        "timeline":  "2–3 days",
        "owner":     "Development team",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
    },

    "brute_force": {
        "title":   "Authentication Brute Force",
        "steps": [
            "Implement account lockout after 5 failed attempts with exponential backoff",
            "Deploy multi-factor authentication (MFA) on all user accounts",
            "Install Fail2Ban to automatically block repeated offenders",
            "Enforce a strong password policy (minimum 12 characters, complexity)",
            "Consider CAPTCHA on login forms after a threshold of failures",
        ],
        "effort":    "low",
        "timeline":  "2–3 days",
        "owner":     "Operations / DevOps",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
    },

    "ssl": {
        "title":   "Weak TLS Configuration",
        "steps": [
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 — enable TLS 1.2 and 1.3 only",
            "Remove weak cipher suites (RC4, DES, 3DES, EXPORT, NULL)",
            "Enable HSTS with a minimum max-age of 1 year and includeSubDomains",
            "Renew certificates with SHA-256 or stronger signature algorithm",
            "Test configuration at https://ssllabs.com/ssltest/",
        ],
        "effort":    "low",
        "timeline":  "1 day",
        "owner":     "Operations / DevOps",
        "references": [
            "https://ssl-config.mozilla.org/",
        ],
    },

    "secret": {
        "title":   "Exposed Secrets / Credentials",
        "steps": [
            "Immediately revoke and rotate all exposed API keys, tokens, and passwords",
            "Remove secrets from source code and move to environment variables or a secrets manager",
            "Audit git history for committed secrets — use BFG Repo Cleaner to purge",
            "Add .env and config files to .gitignore",
            "Implement pre-commit hooks (detect-secrets, gitleaks) to prevent future leaks",
            "Enable secret scanning in your CI/CD pipeline",
        ],
        "effort":    "medium",
        "timeline":  "Immediate rotation — 1 week for full remediation",
        "owner":     "Development + Security teams",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },

    "subdomain_takeover": {
        "title":   "Subdomain Takeover",
        "steps": [
            "Remove or update the dangling DNS CNAME record immediately",
            "Audit all DNS records for CNAMEs pointing to decommissioned services",
            "Claim the resource on the third-party platform if still in use",
            "Implement a DNS monitoring process to detect orphaned records",
            "Document all subdomains and their associated resources",
        ],
        "effort":    "low",
        "timeline":  "Immediate — fix within hours",
        "owner":     "Operations / DNS admin",
        "references": [
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ],
    },

    "cloud_bucket": {
        "title":   "Exposed Cloud Storage Bucket",
        "steps": [
            "Immediately set the bucket ACL to private",
            "Enable Block Public Access at the account level",
            "Audit bucket contents for sensitive data and notify affected parties if data was exposed",
            "Enable server-side encryption on the bucket",
            "Enable CloudTrail / bucket access logging",
            "Review and restrict IAM bucket policies",
        ],
        "effort":    "low",
        "timeline":  "Immediate",
        "owner":     "Cloud / DevOps team",
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        ],
    },

    "smb": {
        "title":   "SMB Exposure",
        "steps": [
            "Block SMB ports (135, 137-139, 445) at the perimeter firewall",
            "Apply the latest Windows security patches — especially MS17-010",
            "Disable SMBv1 on all systems",
            "Restrict SMB access to authorised internal hosts only",
            "Enable SMB signing to prevent relay attacks",
        ],
        "effort":    "low",
        "timeline":  "1–2 days",
        "owner":     "Operations / Windows admin",
        "references": [
            "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        ],
    },

    "default": {
        "title":   "General Security Finding",
        "steps": [
            "Review the finding details and assess exploitability in your environment",
            "Apply vendor-recommended patches or mitigations",
            "Implement compensating controls if patching is not immediately possible",
            "Monitor for exploitation indicators",
            "Schedule a follow-up assessment to verify remediation",
        ],
        "effort":    "medium",
        "timeline":  "Varies",
        "owner":     "Security team",
        "references": [],
    },
}

# Tag → remediation key mapping
TAG_REMEDIATION_MAP: Dict[str, str] = {
    "sqli":          "sqli",
    "sql":           "sqli",
    "xss":           "xss",
    "lfi":           "lfi",
    "rfi":           "lfi",
    "rce":           "rce",
    "cmdi":          "rce",
    "ssrf":          "ssrf",
    "ssti":          "ssti",
    "xxe":           "xxe",
    "brute":         "brute_force",
    "brute-force":   "brute_force",
    "bruteforce":    "brute_force",
    "ssl":           "ssl",
    "tls":           "ssl",
    "secret":        "secret",
    "api_key":       "secret",
    "token":         "secret",
    "takeover":      "subdomain_takeover",
    "subdomain":     "subdomain_takeover",
    "s3":            "cloud_bucket",
    "bucket":        "cloud_bucket",
    "cloud":         "cloud_bucket",
    "smb":           "smb",
    "netbios":       "smb",
}


# ─────────────────────────────────────────────────────────────
# RemediationBuilder
# ─────────────────────────────────────────────────────────────

class RemediationBuilder:
    """
    Generates structured remediation plans from session findings.
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("defense.remediation")

    # ── Public API ────────────────────────────────────────────

    def build(self) -> Dict:
        """Build full remediation plan from session findings."""
        findings = self.session.get_findings()
        if not findings:
            return {}

        items     = self._build_items(findings)
        markdown  = self._render_markdown(items, findings)
        plan      = {
            "session_id":   self.session.meta.session_id,
            "target":       self.session.meta.target,
            "generated_at": datetime.utcnow().isoformat(),
            "total_items":  len(items),
            "items":        items,
        }

        # Save outputs
        out_dir = self.session.dir("report") / "remediation"
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "remediation_plan.json"
        json_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

        md_path = out_dir / "remediation_plan.md"
        md_path.write_text(markdown, encoding="utf-8")

        self.logger.success(
            f"Remediation plan saved → {out_dir} ({len(items)} items)"
        )
        return plan

    def get_item_for_finding(self, finding: Finding) -> Dict:
        """Get remediation item for a single finding."""
        key      = self._resolve_key(finding)
        rem      = REMEDIATION_MAP.get(key, REMEDIATION_MAP["default"])
        return self._build_item(finding, key, rem)

    # ── Internal ──────────────────────────────────────────────

    def _build_items(self, findings: List[Finding]) -> List[Dict]:
        items    = []
        seen_keys = set()

        sev_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH:     1,
            SeverityLevel.MEDIUM:   2,
            SeverityLevel.LOW:      3,
            SeverityLevel.INFO:     4,
        }
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 9))

        for finding in sorted_findings:
            key = self._resolve_key(finding)
            if key in seen_keys:
                continue
            rem = REMEDIATION_MAP.get(key, REMEDIATION_MAP["default"])
            items.append(self._build_item(finding, key, rem))
            seen_keys.add(key)

        return items

    def _build_item(self, finding: Finding, key: str, rem: Dict) -> Dict:
        return {
            "finding_id":   finding.id,
            "finding_title":finding.title,
            "severity":     finding.severity.value,
            "host":         finding.host,
            "cve":          finding.cve,
            "category":     key,
            "title":        rem["title"],
            "steps":        rem["steps"],
            "effort":       rem["effort"],
            "timeline":     rem["timeline"],
            "owner":        rem["owner"],
            "references":   rem["references"],
            "notes":        finding.remediation or "",
        }

    def _resolve_key(self, finding: Finding) -> str:
        for tag in finding.tags:
            key = TAG_REMEDIATION_MAP.get(tag.lower())
            if key:
                return key
        title_lower = finding.title.lower()
        for keyword, key in TAG_REMEDIATION_MAP.items():
            if keyword in title_lower:
                return key
        return "default"

    def _render_markdown(self, items: List[Dict], findings: List[Finding]) -> str:
        ts      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        summary = self.session.findings_summary()

        lines = [
            f"# ARDF Remediation Plan",
            f"",
            f"**Target:** {self.session.meta.target}  ",
            f"**Generated:** {ts}  ",
            f"**Session:** `{self.session.meta.session_id}`  ",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, cnt in summary.items():
            if cnt > 0:
                lines.append(f"| {sev.upper()} | {cnt} |")

        lines += ["", f"**Total remediation items:** {len(items)}", ""]
        lines += ["---", "", "## Remediation Actions", ""]

        for i, item in enumerate(items, 1):
            lines += [
                f"### {i}. [{item['severity'].upper()}] {item['title']}",
                f"",
                f"**Finding:** {item['finding_title']}  ",
                f"**Host:** `{item['host']}`  ",
                f"**Effort:** {item['effort']}  ",
                f"**Timeline:** {item['timeline']}  ",
                f"**Owner:** {item['owner']}  ",
            ]
            if item.get("cve"):
                lines.append(f"**CVE:** [{item['cve']}]"
                             f"(https://nvd.nist.gov/vuln/detail/{item['cve']})  ")
            lines += ["", "**Steps:**", ""]
            for j, step in enumerate(item["steps"], 1):
                lines.append(f"{j}. {step}")
            if item.get("notes"):
                lines += ["", f"**Notes:** {item['notes']}"]
            if item.get("references"):
                lines += ["", "**References:**"]
                for ref in item["references"]:
                    lines.append(f"- {ref}")
            lines += ["", "---", ""]

        return "\n".join(lines)
