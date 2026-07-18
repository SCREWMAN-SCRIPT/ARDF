"""
modules/defense/hardening.py
─────────────────────────────
HardeningEngine — generates concrete hardening scripts and
configuration recommendations from session findings.

Outputs
───────
  - Shell scripts (bash) for Linux hardening
  - Nginx / Apache config snippets
  - sysctl recommendations
  - UFW / iptables rules
  - SSH hardening config
  - TLS configuration recommendations
"""

import json
from datetime import datetime
from pathlib  import Path
from typing   import Dict, List, Optional, Tuple

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Hardening rule library
# ─────────────────────────────────────────────────────────────

HARDENING_RULES: List[Dict] = [

    # ── Web ───────────────────────────────────────────────────
    {
        "triggers":    ["sqli", "sql", "xss", "lfi", "rfi", "rce", "cmdi", "ssrf", "ssti"],
        "category":    "web",
        "title":       "Deploy Web Application Firewall",
        "priority":    "critical",
        "description": "A WAF filters malicious HTTP traffic before it reaches the application.",
        "script": """#!/bin/bash
# Install and configure ModSecurity WAF with OWASP CRS
echo "[ARDF] Installing ModSecurity..."
apt-get install -y libapache2-mod-security2 || apt-get install -y libnginx-mod-http-modsecurity
# Enable OWASP Core Rule Set
if [ -d /etc/modsecurity ]; then
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
    echo "[ARDF] ModSecurity enabled in enforcement mode"
fi
# Install OWASP CRS
if [ ! -d /etc/modsecurity/crs ]; then
    git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
    cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
    echo "[ARDF] OWASP CRS installed"
fi""",
        "config_snippet": """# Nginx ModSecurity block (add to server block)
modsecurity on;
modsecurity_rules_file /etc/modsecurity/crs/crs-setup.conf;
modsecurity_rules_file /etc/modsecurity/crs/rules/*.conf;""",
        "references": ["https://owasp.org/www-project-modsecurity-core-rule-set/"],
    },

    {
        "triggers":    ["sqli", "sql", "injectable"],
        "category":    "web",
        "title":       "Enforce Parameterised Queries / Prepared Statements",
        "priority":    "critical",
        "description": "SQL injection is eliminated by using prepared statements in all database queries.",
        "script": """#!/bin/bash
# Audit codebase for dynamic SQL query construction
echo "[ARDF] Scanning for unsafe SQL patterns..."
grep -rn "execute.*%s\|query.*format\|SELECT.*+.*request\|INSERT.*+.*input" \
    /var/www/ --include="*.php" --include="*.py" --include="*.js" \
    > /tmp/ardf_sql_audit.txt 2>/dev/null
COUNT=$(wc -l < /tmp/ardf_sql_audit.txt)
echo "[ARDF] Found $COUNT potential unsafe SQL patterns — review /tmp/ardf_sql_audit.txt"
echo "[ARDF] ACTION REQUIRED: Replace dynamic queries with prepared statements"
cat /tmp/ardf_sql_audit.txt""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    },

    {
        "triggers":    ["xss"],
        "category":    "web",
        "title":       "Set Security Headers — CSP, X-Frame-Options, HSTS",
        "priority":    "high",
        "description": "HTTP security headers mitigate XSS, clickjacking, and protocol downgrade attacks.",
        "script": """#!/bin/bash
# Add security headers to Nginx config
NGINX_CONF="/etc/nginx/conf.d/security_headers.conf"
cat > "$NGINX_CONF" << 'EOF'
# ARDF Generated Security Headers
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOF
echo "[ARDF] Security headers configured at $NGINX_CONF"
nginx -t && systemctl reload nginx""",
        "config_snippet": """# Apache equivalent (.htaccess or httpd.conf)
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin" """,
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },

    # ── Network ───────────────────────────────────────────────
    {
        "triggers":    ["port", "nmap", "masscan", "open", "portscan"],
        "category":    "network",
        "title":       "Restrict Exposed Ports with UFW Firewall",
        "priority":    "high",
        "description": "Reduce the attack surface by allowing only required ports through the firewall.",
        "script": """#!/bin/bash
echo "[ARDF] Configuring UFW firewall rules..."
# Install UFW if not present
apt-get install -y ufw 2>/dev/null

# Reset to defaults
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow only essential services — modify as needed
ufw allow 22/tcp    comment 'SSH'
ufw allow 80/tcp    comment 'HTTP'
ufw allow 443/tcp   comment 'HTTPS'

# Rate-limit SSH to prevent brute force
ufw limit 22/tcp comment 'SSH rate limit'

# Enable firewall
ufw --force enable
ufw status verbose
echo "[ARDF] UFW configured. Review rules above and add application-specific ports."
""",
        "references": ["https://help.ubuntu.com/community/UFW"],
    },

    {
        "triggers":    ["smb", "smbmap", "enum4linux", "netbios"],
        "category":    "network",
        "title":       "Restrict SMB Access and Disable NetBIOS",
        "priority":    "high",
        "description": "SMB exposure enables enumeration and lateral movement. Restrict access to authorised hosts only.",
        "script": """#!/bin/bash
echo "[ARDF] Restricting SMB access..."
# Block SMB ports from internet (allow only internal range)
ufw deny 139/tcp
ufw deny 445/tcp
ufw deny 137/udp
ufw deny 138/udp

# Disable NetBIOS over TCP/IP
if command -v nmbd &>/dev/null; then
    systemctl stop nmbd
    systemctl disable nmbd
    echo "[ARDF] NetBIOS/nmbd disabled"
fi

# Restrict Samba config if present
SAMBA_CONF="/etc/samba/smb.conf"
if [ -f "$SAMBA_CONF" ]; then
    sed -i '/\[global\]/a \\thosts allow = 192.168.1. 127.0.0.1' "$SAMBA_CONF"
    echo "[ARDF] Samba host restriction applied — update IP range as needed"
fi""",
        "references": ["https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html"],
    },

    {
        "triggers":    ["snmp", "onesixtyone", "community"],
        "category":    "network",
        "title":       "Secure SNMP Configuration",
        "priority":    "high",
        "description": "Default SNMP community strings expose device configuration to attackers.",
        "script": """#!/bin/bash
echo "[ARDF] Securing SNMP configuration..."
SNMP_CONF="/etc/snmp/snmpd.conf"
if [ -f "$SNMP_CONF" ]; then
    # Backup original
    cp "$SNMP_CONF" "${SNMP_CONF}.ardf_backup"
    # Remove default community strings
    sed -i '/^rocommunity public/d'  "$SNMP_CONF"
    sed -i '/^rwcommunity private/d' "$SNMP_CONF"
    # Add restricted community (change string before use)
    echo "rocommunity CHANGEME_TO_RANDOM_STRING 127.0.0.1" >> "$SNMP_CONF"
    systemctl restart snmpd 2>/dev/null
    echo "[ARDF] Default SNMP community strings removed"
    echo "[ARDF] ACTION REQUIRED: Set a strong random community string in $SNMP_CONF"
fi
# Block SNMP from internet
ufw deny 161/udp
ufw deny 162/udp
echo "[ARDF] SNMP ports blocked at firewall"
""",
        "references": ["https://www.cisecurity.org/benchmark/distribution_independent_linux"],
    },

    # ── TLS / SSL ─────────────────────────────────────────────
    {
        "triggers":    ["ssl", "tls", "sslv2", "sslv3", "weak cipher", "rc4"],
        "category":    "tls",
        "title":       "Enforce Strong TLS Configuration",
        "priority":    "high",
        "description": "Disable deprecated SSL/TLS versions and weak cipher suites.",
        "script": """#!/bin/bash
echo "[ARDF] Applying strong TLS configuration..."
NGINX_TLS="/etc/nginx/conf.d/tls_hardening.conf"
cat > "$NGINX_TLS" << 'EOF'
# ARDF TLS Hardening Configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
EOF
echo "[ARDF] TLS hardening config written to $NGINX_TLS"
nginx -t && systemctl reload nginx
echo "[ARDF] Nginx reloaded with strong TLS settings"
""",
        "references": ["https://ssl-config.mozilla.org/", "https://cipherlist.eu/"],
    },

    # ── SSH ───────────────────────────────────────────────────
    {
        "triggers":    ["ssh", "ssh-audit", "ssh_audit"],
        "category":    "ssh",
        "title":       "Harden SSH Configuration",
        "priority":    "high",
        "description": "Disable password authentication, restrict algorithms, and enable key-based auth only.",
        "script": """#!/bin/bash
echo "[ARDF] Hardening SSH configuration..."
SSHD_CONF="/etc/ssh/sshd_config"
cp "$SSHD_CONF" "${SSHD_CONF}.ardf_backup"

# Apply hardening settings
declare -A SSH_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["PermitEmptyPasswords"]="no"
    ["ChallengeResponseAuthentication"]="no"
    ["X11Forwarding"]="no"
    ["MaxAuthTries"]="3"
    ["LoginGraceTime"]="20"
    ["AllowAgentForwarding"]="no"
    ["Protocol"]="2"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
)

for key in "${!SSH_SETTINGS[@]}"; do
    value="${SSH_SETTINGS[$key]}"
    if grep -q "^$key" "$SSHD_CONF"; then
        sed -i "s/^$key.*/$key $value/" "$SSHD_CONF"
    else
        echo "$key $value" >> "$SSHD_CONF"
    fi
done

# Restrict ciphers to modern algorithms
cat >> "$SSHD_CONF" << 'EOF'
# ARDF Cipher Hardening
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
EOF

sshd -t && systemctl restart sshd
echo "[ARDF] SSH hardening applied. Ensure key-based auth is configured before disconnecting."
""",
        "references": ["https://www.ssh-audit.com/hardening_guides.html"],
    },

    # ── Authentication ────────────────────────────────────────
    {
        "triggers":    ["brute", "bruteforce", "brute-force", "hydra", "medusa", "credentials"],
        "category":    "auth",
        "title":       "Install and Configure Fail2Ban",
        "priority":    "high",
        "description": "Fail2Ban blocks IPs after repeated failed authentication attempts.",
        "script": """#!/bin/bash
echo "[ARDF] Installing and configuring Fail2Ban..."
apt-get install -y fail2ban

# Create local jail configuration
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10

[apache-auth]
enabled  = true
port     = http,https
logpath  = /var/log/apache2/error.log
EOF

systemctl enable fail2ban
systemctl restart fail2ban
fail2ban-client status
echo "[ARDF] Fail2Ban configured. Check /etc/fail2ban/jail.local to customise."
""",
        "references": ["https://www.fail2ban.org/wiki/index.php/MANUAL_0_8"],
    },

    # ── Kernel / OS ───────────────────────────────────────────
    {
        "triggers":    ["privesc", "suid", "sudo", "kernel"],
        "category":    "os",
        "title":       "Apply Kernel Hardening via sysctl",
        "priority":    "medium",
        "description": "Kernel parameter hardening reduces the impact of privilege escalation and network attacks.",
        "script": """#!/bin/bash
echo "[ARDF] Applying kernel hardening parameters..."
SYSCTL_CONF="/etc/sysctl.d/99-ardf-hardening.conf"

cat > "$SYSCTL_CONF" << 'EOF'
# ARDF Kernel Hardening Configuration
# Network hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# Memory hardening
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
# Filesystem hardening
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl -p "$SYSCTL_CONF"
echo "[ARDF] Kernel hardening parameters applied from $SYSCTL_CONF"
""",
        "references": ["https://www.cisecurity.org/benchmark/distribution_independent_linux"],
    },

    # ── Secrets ───────────────────────────────────────────────
    {
        "triggers":    ["secret", "api_key", "token", "trufflehog", "secretfinder"],
        "category":    "secrets",
        "title":       "Rotate Exposed Credentials and Secrets",
        "priority":    "critical",
        "description": "Any exposed API keys, tokens, or passwords must be immediately rotated.",
        "script": """#!/bin/bash
echo "[ARDF] Auditing for exposed secrets in common locations..."
# Scan for common secret patterns
grep -rn "api_key\|apikey\|api-key\|secret_key\|password\|passwd\|token\|private_key" \
    /var/www/ /opt/ /home/ \
    --include="*.env" --include="*.json" --include="*.yaml" \
    --include="*.yml" --include="*.conf" --include="*.config" \
    --include="*.js" --include="*.py" --include="*.php" \
    2>/dev/null | grep -v ".git" > /tmp/ardf_secret_audit.txt

COUNT=$(wc -l < /tmp/ardf_secret_audit.txt)
echo "[ARDF] Found $COUNT potential secret references"
echo "[ARDF] Review: /tmp/ardf_secret_audit.txt"
echo ""
echo "[ARDF] IMMEDIATE ACTIONS REQUIRED:"
echo "  1. Rotate any exposed API keys with the issuing service"
echo "  2. Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager)"
echo "  3. Add .env files to .gitignore"
echo "  4. Run: git log --all --full-history -- '*.env' to check git history"
echo "  5. Consider using pre-commit hooks (detect-secrets, gitleaks)"
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://github.com/Yelp/detect-secrets",
        ],
    },

    # ── Cloud ─────────────────────────────────────────────────
    {
        "triggers":    ["s3", "cloud", "bucket", "cloudbrute"],
        "category":    "cloud",
        "title":       "Restrict Cloud Storage Bucket Access",
        "priority":    "critical",
        "description": "Publicly accessible cloud buckets expose sensitive data to anyone on the internet.",
        "script": """#!/bin/bash
echo "[ARDF] Cloud Storage Hardening Checklist"
echo "============================================"
echo ""
echo "AWS S3 — Run these commands to audit and fix bucket ACLs:"
echo ""
echo "  # List all buckets and their public access status"
echo "  aws s3api list-buckets --query 'Buckets[].Name' --output text | \\"
echo "    xargs -I{} aws s3api get-bucket-acl --bucket {}"
echo ""
echo "  # Block all public access on a bucket"
echo "  aws s3api put-public-access-block --bucket BUCKET_NAME \\"
echo "    --public-access-block-configuration \\"
echo "    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
echo ""
echo "  # Enable bucket versioning (ransomware protection)"
echo "  aws s3api put-bucket-versioning --bucket BUCKET_NAME \\"
echo "    --versioning-configuration Status=Enabled"
echo ""
echo "  # Enable server-side encryption"
echo "  aws s3api put-bucket-encryption --bucket BUCKET_NAME \\"
echo "    --server-side-encryption-configuration \\"
echo "    '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
""",
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        ],
    },
]


# ─────────────────────────────────────────────────────────────
# HardeningEngine
# ─────────────────────────────────────────────────────────────

class HardeningEngine:
    """
    Generates targeted hardening scripts from session findings.

    Each finding maps to one or more hardening rules.
    Rules are deduplicated and rendered as executable bash scripts.
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("defense.hardening")

    # ── Public API ────────────────────────────────────────────

    def generate_hardening_report(self) -> Dict:
        """
        Generate full hardening report from all session findings.
        Returns dict with scripts, recommendations, and patch list.
        """
        findings = self.session.get_findings()
        if not findings:
            self.logger.warning("No findings to generate hardening from")
            return {}

        matched_rules = self._match_rules(findings)
        scripts       = self._build_scripts(matched_rules)
        patch_list    = self._build_patch_list(findings)
        summary       = self._build_summary(matched_rules, findings)

        report = {
            "session_id":    self.session.meta.session_id,
            "target":        self.session.meta.target,
            "generated_at":  datetime.utcnow().isoformat(),
            "rules_matched": len(matched_rules),
            "summary":       summary,
            "scripts":       scripts,
            "patch_list":    patch_list,
            "categories":    list({r["category"] for r in matched_rules}),
        }

        # Save to session
        out_dir  = self.session.dir("report") / "hardening"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Save combined script
        combined_script = self._build_combined_script(scripts)
        script_path     = out_dir / "ardf_hardening.sh"
        script_path.write_text(combined_script, encoding="utf-8")
        script_path.chmod(0o750)

        # Save JSON report
        report_path = out_dir / "hardening_report.json"
        report_path.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )

        self.logger.success(
            f"Hardening report saved → {out_dir} "
            f"({len(matched_rules)} rules, {len(scripts)} scripts)"
        )
        return report

    def get_recommendations(self, findings: List[Finding]) -> List[Dict]:
        """Return list of hardening recommendations for given findings."""
        return self._match_rules(findings)

    # ── Internal ──────────────────────────────────────────────

    def _match_rules(self, findings: List[Finding]) -> List[Dict]:
        """Match findings to hardening rules."""
        matched  = []
        seen_titles = set()

        for finding in findings:
            finding_tags = [t.lower() for t in finding.tags]
            title_lower  = finding.title.lower()

            for rule in HARDENING_RULES:
                if rule["title"] in seen_titles:
                    continue
                triggers = rule["triggers"]
                if any(
                    t in finding_tags or t in title_lower
                    for t in triggers
                ):
                    matched.append({**rule, "triggered_by": finding.id})
                    seen_titles.add(rule["title"])

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matched.sort(key=lambda r: priority_order.get(r["priority"], 99))
        return matched

    def _build_scripts(self, rules: List[Dict]) -> List[Dict]:
        """Build individual script entries."""
        scripts = []
        for i, rule in enumerate(rules, 1):
            scripts.append({
                "index":       i,
                "title":       rule["title"],
                "priority":    rule["priority"],
                "category":    rule["category"],
                "description": rule["description"],
                "script":      rule["script"],
                "config":      rule.get("config_snippet", ""),
                "references":  rule.get("references", []),
            })
        return scripts

    def _build_combined_script(self, scripts: List[Dict]) -> str:
        """Combine all scripts into one executable file."""
        header = f"""#!/bin/bash
# ============================================================
# ARDF Automated Hardening Script
# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
# Target   : {self.session.meta.target}
# Session  : {self.session.meta.session_id}
# ============================================================
# WARNING: Review each section before executing on production.
# Run individual sections manually if preferred.
# ============================================================

set -e
ARDF_LOG="/var/log/ardf_hardening.log"
exec > >(tee -a "$ARDF_LOG") 2>&1
echo "[ARDF] Hardening started at $(date)"
echo "[ARDF] {len(scripts)} hardening actions to apply"
echo ""

"""
        sections = []
        for s in scripts:
            section = (
                f"# ── [{s['priority'].upper()}] {s['title']} ──\n"
                f"echo '[ARDF] Applying: {s['title']}'\n"
                f"{s['script'].strip()}\n"
                f"echo '[ARDF] Done: {s['title']}'\n"
                f"echo ''\n"
            )
            sections.append(section)

        footer = (
            f'\necho "[ARDF] Hardening complete at $(date)"\n'
            f'echo "[ARDF] Log saved to $ARDF_LOG"\n'
        )
        return header + "\n\n".join(sections) + footer

    def _build_patch_list(self, findings: List[Finding]) -> List[Dict]:
        """Extract CVEs and map to patch recommendations."""
        patches = []
        seen    = set()
        for f in findings:
            if f.cve and f.cve not in seen:
                patches.append({
                    "cve":         f.cve,
                    "title":       f.title,
                    "severity":    f.severity.value,
                    "host":        f.host,
                    "action":      f"Apply security patch for {f.cve}",
                    "remediation": f.remediation or "Check vendor advisory",
                })
                seen.add(f.cve)
        patches.sort(key=lambda p: {"critical":0,"high":1,"medium":2,"low":3}.get(p["severity"],9))
        return patches

    def _build_summary(
        self,
        rules:    List[Dict],
        findings: List[Finding],
    ) -> Dict:
        category_counts: Dict[str, int] = {}
        for r in rules:
            cat = r["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

        critical_count = sum(1 for r in rules if r["priority"] == "critical")
        high_count     = sum(1 for r in rules if r["priority"] == "high")
        cve_count      = sum(1 for f in findings if f.cve)

        return {
            "total_rules":       len(rules),
            "critical_actions":  critical_count,
            "high_actions":      high_count,
            "cves_to_patch":     cve_count,
            "categories":        category_counts,
        }
