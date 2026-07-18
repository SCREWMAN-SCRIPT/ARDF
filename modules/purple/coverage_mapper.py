"""
modules/purple/coverage_mapper.py
──────────────────────────────────
CoverageMapper — maps observed attack techniques against
detection coverage and produces MITRE ATT&CK heatmaps.

Outputs
───────
  - MITRE technique coverage percentage
  - Detection gap list
  - Coverage heatmap data for report
  - Recommendations for detection improvement
"""

import json
from datetime import datetime
from pathlib  import Path
from typing   import Dict, List, Optional, Tuple

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK technique registry
# ─────────────────────────────────────────────────────────────

MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1595": {"name": "Active Scanning",              "tactic": "Reconnaissance"},
    "T1596": {"name": "Search Open Sources",          "tactic": "Reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing App",    "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts",               "tactic": "Initial Access"},
    "T1059": {"name": "Command & Scripting",          "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task / Job",         "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control",      "tactic": "Privilege Escalation"},
    "T1046": {"name": "Network Service Scan",         "tactic": "Discovery"},
    "T1135": {"name": "Network Share Discovery",      "tactic": "Discovery"},
    "T1083": {"name": "File & Directory Discovery",   "tactic": "Discovery"},
    "T1021": {"name": "Remote Services",              "tactic": "Lateral Movement"},
    "T1110": {"name": "Brute Force",                  "tactic": "Credential Access"},
    "T1558": {"name": "Steal Kerberos Tickets",       "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping",        "tactic": "Credential Access"},
    "T1552": {"name": "Unsecured Credentials",        "tactic": "Credential Access"},
    "T1530": {"name": "Data from Cloud Storage",      "tactic": "Collection"},
    "T1041": {"name": "Exfiltration over C2",         "tactic": "Exfiltration"},
    "T1071": {"name": "App Layer Protocol",           "tactic": "Command & Control"},
    "T1584": {"name": "Compromise Infrastructure",    "tactic": "Resource Development"},
    "T1090": {"name": "Proxy",                        "tactic": "Command & Control"},
    "T1040": {"name": "Network Sniffing",             "tactic": "Credential Access"},
    "T1557": {"name": "Adversary-in-the-Middle",      "tactic": "Credential Access"},
    "T1574": {"name": "Hijack Execution Flow",        "tactic": "Privilege Escalation"},
    "T1059.007": {"name": "JavaScript",               "tactic": "Execution"},
    "T1505": {"name": "Server Software Component",   "tactic": "Persistence"},
}

# Tactic colours for heatmap
TACTIC_COLOURS: Dict[str, str] = {
    "Reconnaissance":       "#3498db",
    "Resource Development": "#9b59b6",
    "Initial Access":       "#e74c3c",
    "Execution":            "#e67e22",
    "Persistence":          "#f39c12",
    "Privilege Escalation": "#e74c3c",
    "Defense Evasion":      "#1abc9c",
    "Credential Access":    "#e74c3c",
    "Discovery":            "#3498db",
    "Lateral Movement":     "#e67e22",
    "Collection":           "#9b59b6",
    "Exfiltration":         "#e74c3c",
    "Command & Control":    "#e67e22",
}

# Finding tag → MITRE technique mapping
TAG_TO_MITRE: Dict[str, str] = {
    "sqli":         "T1190",
    "xss":          "T1059.007",
    "rce":          "T1059",
    "lfi":          "T1083",
    "ssrf":         "T1090",
    "ssti":         "T1059",
    "xxe":          "T1059",
    "brute":        "T1110",
    "brute-force":  "T1110",
    "kerberoast":   "T1558",
    "asrep":        "T1558",
    "credentials":  "T1078",
    "smb":          "T1135",
    "nmap":         "T1046",
    "masscan":      "T1046",
    "port":         "T1046",
    "subdomain":    "T1596",
    "passive":      "T1596",
    "secret":       "T1552",
    "api_key":      "T1552",
    "s3":           "T1530",
    "bucket":       "T1530",
    "cloud":        "T1530",
    "takeover":     "T1584",
    "privesc":      "T1548",
    "suid":         "T1548",
    "ssh":          "T1021",
    "rdp":          "T1021",
    "ssl":          "T1040",
    "tls":          "T1040",
    "snmp":         "T1046",
    "nuclei":       "T1190",
    "cve":          "T1190",
}

# Detection recommendations per technique
DETECTION_RECOMMENDATIONS: Dict[str, str] = {
    "T1190": "Enable WAF logging with OWASP CRS; monitor for 400/500 error spikes in web logs",
    "T1059": "Enable process creation logging (auditd/Sysmon); alert on unusual interpreter spawns",
    "T1078": "Enable MFA; alert on logins from new geolocations or at unusual hours",
    "T1110": "Deploy Fail2Ban; alert on >5 failed logins/minute per source IP",
    "T1046": "Enable network flow logging; alert on sequential port connection attempts",
    "T1596": "Monitor DNS query rates; alert on >100 unique subdomain queries/minute",
    "T1552": "Scan code repositories for secret patterns; enable secret scanning in CI/CD",
    "T1530": "Enable S3/GCS access logging; alert on public bucket access from unknown IPs",
    "T1558": "Enable Kerberos logging on domain controllers; alert on TGS requests for service accounts",
    "T1548": "Enable auditd SUID monitoring; alert on unexpected setuid binary execution",
    "T1135": "Enable SMB access logging; alert on share enumeration from non-admin hosts",
    "T1021": "Enable lateral movement detection; alert on new admin logins across multiple hosts",
    "T1584": "Monitor DNS CNAME records for dangling references to third-party services",
    "T1090": "Enable proxy logging; inspect and alert on tunnel/relay tool signatures",
    "T1040": "Enable promiscuous mode detection on network interfaces",
    "T1083": "Enable file access auditing; alert on traversal patterns in web requests",
}


# ─────────────────────────────────────────────────────────────
# CoverageMapper
# ─────────────────────────────────────────────────────────────

class CoverageMapper:
    """
    Maps observed attack techniques against detection coverage.
    Produces MITRE heatmap data and detection gap analysis.
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session = session
        self.logger  = logger or get_logger("purple.coverage")

    # ── Public API ────────────────────────────────────────────

    def map_coverage(
        self,
        sigma_rules:   Optional[List[Dict]] = None,
        phase_results: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Generate full coverage map from session findings.

        Returns:
            Dict with mitre_map, gaps, coverage_pct, recommendations
        """
        findings     = self.session.get_findings()
        red_findings = [f for f in findings if "defense" not in f.source]
        blue_findings= [f for f in findings if "defense" in f.source or "monitor" in f.source]

        # Map techniques observed by red team
        observed_techniques = self._map_findings_to_mitre(red_findings)

        # Map techniques detected by blue team
        detected_techniques = self._map_findings_to_mitre(blue_findings)

        # Add techniques from sigma rules
        if sigma_rules:
            for rule in sigma_rules:
                for tag in rule.get("tags", []):
                    if tag.startswith("attack.t"):
                        tid = tag.replace("attack.", "").upper()
                        detected_techniques.add(tid)

        # Calculate coverage
        gaps             = observed_techniques - detected_techniques
        covered          = observed_techniques & detected_techniques
        coverage_pct     = (
            len(covered) / max(len(observed_techniques), 1) * 100
        )

        # Build heatmap data
        heatmap = self._build_heatmap(
            observed_techniques, detected_techniques
        )

        # Build gap analysis
        gap_analysis = self._build_gap_analysis(gaps)

        # Build tactic summary
        tactic_summary = self._build_tactic_summary(
            observed_techniques, detected_techniques
        )

        # Recommendations
        recommendations = self._build_recommendations(gaps)

        result = {
            "session_id":         self.session.meta.session_id,
            "target":             self.session.meta.target,
            "generated_at":       datetime.utcnow().isoformat(),
            "observed_count":     len(observed_techniques),
            "detected_count":     len(detected_techniques),
            "gap_count":          len(gaps),
            "coverage_pct":       round(coverage_pct, 1),
            "observed":           sorted(observed_techniques),
            "detected":           sorted(detected_techniques),
            "gaps":               sorted(gaps),
            "heatmap":            heatmap,
            "gap_analysis":       gap_analysis,
            "tactic_summary":     tactic_summary,
            "recommendations":    recommendations,
        }

        self._save(result)
        self.logger.success(
            f"Coverage map complete | "
            f"observed={len(observed_techniques)} "
            f"detected={len(detected_techniques)} "
            f"coverage={coverage_pct:.0f}%"
        )
        return result

    def get_mitre_heatmap_data(self) -> List[Dict]:
        """Return heatmap cell data for report rendering."""
        findings            = self.session.get_findings()
        observed_techniques = self._map_findings_to_mitre(findings)
        return self._build_heatmap(observed_techniques, set())

    # ── Internal ──────────────────────────────────────────────

    def _map_findings_to_mitre(self, findings: List[Finding]) -> set:
        """Extract MITRE technique IDs from findings."""
        techniques = set()
        for finding in findings:
            # Check tags
            for tag in finding.tags:
                # Direct MITRE tag
                if tag.upper().startswith("T1") or tag.upper().startswith("TA"):
                    techniques.add(tag.upper())
                    continue
                # Keyword mapping
                tid = TAG_TO_MITRE.get(tag.lower())
                if tid:
                    techniques.add(tid)

            # Check title and description keywords
            combined = (finding.title + " " + finding.description).lower()
            for keyword, tid in TAG_TO_MITRE.items():
                if keyword in combined:
                    techniques.add(tid)

            # Check CVE → default to T1190
            if finding.cve:
                techniques.add("T1190")

        return techniques

    def _build_heatmap(
        self,
        observed: set,
        detected: set,
    ) -> List[Dict]:
        """Build heatmap cell data for all known techniques."""
        cells = []
        for tid, info in MITRE_TECHNIQUES.items():
            is_observed = tid in observed
            is_detected = tid in detected
            tactic      = info["tactic"]
            colour      = TACTIC_COLOURS.get(tactic, "#444444")

            if is_observed and is_detected:
                status = "detected"
                cell_colour = "#3fb950"  # green
            elif is_observed and not is_detected:
                status = "gap"
                cell_colour = "#e74c3c"  # red
            else:
                status = "not_observed"
                cell_colour = "#21262d"  # dark

            cells.append({
                "id":      tid,
                "name":    info["name"],
                "tactic":  tactic,
                "status":  status,
                "colour":  cell_colour,
                "tactic_colour": colour,
                "observed": is_observed,
                "detected": is_detected,
            })

        # Sort by tactic then technique ID
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration",
            "Command & Control",
        ]
        cells.sort(key=lambda c: (
            tactic_order.index(c["tactic"]) if c["tactic"] in tactic_order else 99,
            c["id"]
        ))
        return cells

    def _build_gap_analysis(self, gaps: set) -> List[Dict]:
        """Build structured gap analysis for each undetected technique."""
        analysis = []
        for tid in sorted(gaps):
            info = MITRE_TECHNIQUES.get(tid, {})
            analysis.append({
                "technique_id":    tid,
                "technique_name":  info.get("name", tid),
                "tactic":          info.get("tactic", "Unknown"),
                "detection_gap":   True,
                "recommendation":  DETECTION_RECOMMENDATIONS.get(tid, "Review logging and alerting for this technique"),
                "log_sources":     self._suggest_log_sources(tid),
                "sigma_available": self._has_sigma_template(tid),
            })
        return analysis

    def _build_tactic_summary(
        self,
        observed: set,
        detected: set,
    ) -> List[Dict]:
        """Summarise coverage by MITRE tactic."""
        tactic_data: Dict[str, Dict] = {}

        for tid in observed:
            info   = MITRE_TECHNIQUES.get(tid, {})
            tactic = info.get("tactic", "Unknown")
            if tactic not in tactic_data:
                tactic_data[tactic] = {
                    "tactic":    tactic,
                    "observed":  0,
                    "detected":  0,
                    "colour":    TACTIC_COLOURS.get(tactic, "#444"),
                }
            tactic_data[tactic]["observed"] += 1
            if tid in detected:
                tactic_data[tactic]["detected"] += 1

        result = []
        for tactic, data in tactic_data.items():
            obs  = data["observed"]
            det  = data["detected"]
            pct  = round(det / max(obs, 1) * 100, 1)
            result.append({**data, "coverage_pct": pct})

        result.sort(key=lambda t: t["coverage_pct"])
        return result

    def _build_recommendations(self, gaps: set) -> List[Dict]:
        """Build prioritised detection improvement recommendations."""
        recs = []
        # Prioritise high-impact gaps
        priority_techniques = {
            "T1190": "critical", "T1059": "critical", "T1078": "high",
            "T1110": "high",     "T1548": "high",     "T1558": "high",
            "T1552": "high",     "T1530": "high",
        }
        for tid in sorted(gaps):
            info     = MITRE_TECHNIQUES.get(tid, {})
            priority = priority_techniques.get(tid, "medium")
            recs.append({
                "technique_id":   tid,
                "technique_name": info.get("name", tid),
                "tactic":         info.get("tactic", "Unknown"),
                "priority":       priority,
                "action":         DETECTION_RECOMMENDATIONS.get(
                    tid, "Implement logging and alerting for this technique"
                ),
                "log_sources":    self._suggest_log_sources(tid),
            })

        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recs.sort(key=lambda r: priority_order.get(r["priority"], 9))
        return recs

    def _suggest_log_sources(self, tid: str) -> List[str]:
        """Suggest log sources needed to detect a technique."""
        log_source_map: Dict[str, List[str]] = {
            "T1190": ["Web server access logs", "WAF logs", "Application logs"],
            "T1059": ["Process creation logs (auditd/Sysmon)", "Shell history logs"],
            "T1078": ["Authentication logs", "Active Directory logs", "VPN logs"],
            "T1110": ["Authentication logs", "SSH logs (/var/log/auth.log)"],
            "T1046": ["Network flow logs (NetFlow/IPFIX)", "Firewall logs"],
            "T1596": ["DNS query logs", "Passive DNS"],
            "T1552": ["File access logs", "Git commit logs", "CI/CD pipeline logs"],
            "T1530": ["Cloud storage access logs (S3/GCS/Azure)"],
            "T1558": ["Kerberos logs (Windows Event 4769)", "Domain controller logs"],
            "T1548": ["auditd logs", "Sysmon Event ID 1", "sudo logs"],
            "T1135": ["Windows Event 5140", "SMB access logs"],
            "T1021": ["Authentication logs", "Network connection logs"],
            "T1040": ["Network interface logs", "Promiscuous mode detection"],
            "T1083": ["File access audit logs (auditd)", "Web server logs"],
        }
        return log_source_map.get(tid, ["System logs", "Network logs"])

    def _has_sigma_template(self, tid: str) -> bool:
        """Check if a Sigma template exists for this technique."""
        tid_tag_map: Dict[str, str] = {
            "T1190": "sqli",       "T1059.007": "xss",
            "T1059": "rce",        "T1083": "lfi",
            "T1090": "ssrf",       "T1110": "brute_force",
            "T1046": "port_scan",  "T1596": "subdomain_enum",
            "T1552": "secret_in_code", "T1530": "cloud_bucket",
            "T1135": "smb_enum",   "T1040": "weak_tls",
            "T1584": "dns_takeover", "T1548": "privesc",
        }
        return tid in tid_tag_map

    def _save(self, result: Dict):
        """Save coverage map to session output."""
        out_dir = self.session.dir("report") / "purple"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "coverage_map.json"
        path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        self.logger.info(f"Coverage map saved → {path}")
