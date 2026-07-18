"""
ai/analyst.py
─────────────
FindingAnalyst — interprets raw tool output and session findings.

Responsibilities
────────────────
  - Parse tool stdout/stderr into structured findings
  - Correlate findings across modules into attack chains
  - Score risk and prioritise exploitation paths
  - Detect defensive responses (WAF, IDS, rate-limit)
  - Generate AI-assisted remediation per finding
  - Identify pivot and lateral movement opportunities
"""

import re
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from ai.local_model  import LocalModel, get_model, load_prompt
from modules.logger  import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Defensive response signatures
# ─────────────────────────────────────────────────────────────

WAF_SIGNATURES = [
    r"cloudflare", r"mod_security", r"waf", r"web application firewall",
    r"403 forbidden", r"406 not acceptable", r"access denied",
    r"blocked", r"security policy", r"malicious request",
    r"request rejected", r"incapsula", r"sucuri", r"barracuda",
    r"f5 big-ip", r"imperva", r"akamai", r"aws waf",
]

RATE_LIMIT_SIGNATURES = [
    r"429 too many requests", r"rate limit", r"too many requests",
    r"slow down", r"throttle", r"quota exceeded", r"retry after",
]

AUTH_REQUIRED_SIGNATURES = [
    r"401 unauthorized", r"403 forbidden", r"authentication required",
    r"login required", r"session expired", r"invalid token",
    r"access denied", r"not authenticated",
]

TIMEOUT_SIGNATURES = [
    r"timeout", r"timed out", r"connection refused",
    r"no route to host", r"network unreachable",
    r"connection reset", r"eof", r"broken pipe",
]

IDS_SIGNATURES = [
    r"intrusion detected", r"snort", r"suricata", r"blocked by ids",
    r"signature matched", r"alert tcp",
]


# ─────────────────────────────────────────────────────────────
# Attack chain patterns
# ─────────────────────────────────────────────────────────────

CHAIN_PATTERNS = [
    {
        "name":     "Web to Shell",
        "requires": ["sqli", "rce", "lfi"],
        "severity": SeverityLevel.CRITICAL,
        "description": "SQL injection or LFI combined with RCE enables full shell access",
        "mitre":    ["T1190", "T1059"],
    },
    {
        "name":     "Credential Reuse",
        "requires": ["credentials", "smb", "ssh"],
        "severity": SeverityLevel.CRITICAL,
        "description": "Harvested credentials enable lateral movement via SMB or SSH",
        "mitre":    ["T1078", "T1021"],
    },
    {
        "name":     "Domain Compromise",
        "requires": ["kerberoast", "asrep", "secretsdump"],
        "severity": SeverityLevel.CRITICAL,
        "description": "Kerberos attacks chain into domain credential dumping",
        "mitre":    ["T1558", "T1003"],
    },
    {
        "name":     "Cloud Bucket Exposure",
        "requires": ["s3", "cloud", "bucket"],
        "severity": SeverityLevel.HIGH,
        "description": "Exposed cloud storage enables data exfiltration",
        "mitre":    ["T1530"],
    },
    {
        "name":     "Subdomain Takeover",
        "requires": ["takeover", "cname", "subdomain"],
        "severity": SeverityLevel.HIGH,
        "description": "Dangling CNAME enables subdomain takeover for phishing",
        "mitre":    ["T1584"],
    },
    {
        "name":     "Secret Leak to Pivot",
        "requires": ["secret", "api_key", "token"],
        "severity": SeverityLevel.HIGH,
        "description": "Leaked secrets in JS/git enable direct API access",
        "mitre":    ["T1552", "T1078"],
    },
]


# ─────────────────────────────────────────────────────────────
# FindingAnalyst
# ─────────────────────────────────────────────────────────────

class FindingAnalyst:
    """
    Interprets tool output and session findings.
    Builds attack chains and prioritises next actions.
    """

    def __init__(
        self,
        session:  Session,
        logger:   Optional[ARDFLogger] = None,
        ai_model: Optional[LocalModel] = None,
    ):
        self.session  = session
        self.logger   = logger or get_logger("ai.analyst")
        self.ai       = ai_model or get_model(role="analysis", logger=self.logger)
        self._analyse_prompt   = load_prompt("analyse_output")

    # ── Tool output classification ────────────────────────────

    def classify_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Classify tool output to determine what happened.
        Returns classification dict used by decision_engine.
        """
        combined = (stdout + " " + stderr).lower()

        waf          = self._match_any(combined, WAF_SIGNATURES)
        rate_limited = self._match_any(combined, RATE_LIMIT_SIGNATURES)
        auth_blocked = self._match_any(combined, AUTH_REQUIRED_SIGNATURES)
        timed_out    = self._match_any(combined, TIMEOUT_SIGNATURES)
        ids_blocked  = self._match_any(combined, IDS_SIGNATURES)

        # Positive result indicators
        has_findings = any(k in combined for k in [
            "vulnerable", "injectable", "confirmed", "found", "open",
            "valid", "cracked", "success", "[+]", "critical", "high",
        ])
        has_results  = len(stdout.strip()) > 50

        return {
            "waf_detected":    waf,
            "rate_limited":    rate_limited,
            "auth_required":   auth_blocked,
            "timed_out":       timed_out,
            "ids_detected":    ids_blocked,
            "has_findings":    has_findings,
            "has_results":     has_results,
            "blocked":         waf or ids_blocked or auth_blocked,
            "needs_retry":     timed_out or rate_limited,
            "output_length":   len(stdout),
            "error_only":      not stdout.strip() and bool(stderr.strip()),
        }

    def classify_response_code(self, code: int) -> str:
        if code == 200: return "success"
        if code == 301: return "redirect"
        if code == 401: return "auth_required"
        if code == 403: return "forbidden"
        if code == 404: return "not_found"
        if code == 429: return "rate_limited"
        if code == 500: return "server_error"
        if code == 502: return "bad_gateway"
        return "unknown"

    # ── Finding interpretation ────────────────────────────────

    def interpret_findings(
        self,
        findings:     List[Finding],
        use_ai:       bool = True,
    ) -> Dict[str, Any]:
        """
        Interpret a list of findings and produce:
          - attack chains
          - prioritised targets
          - AI-generated summary
          - next action recommendations
        """
        if not findings:
            return {"chains": [], "priorities": [], "summary": "", "next_actions": []}

        chains      = self.find_chains(findings)
        priorities  = self.prioritise(findings)
        next_actions= self.recommend_next_actions(findings, chains)

        summary = ""
        if use_ai:
            summary = self._ai_interpret(findings, chains)

        return {
            "chains":       chains,
            "priorities":   priorities,
            "summary":      summary,
            "next_actions": next_actions,
            "critical_count": sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
            "high_count":     sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
        }

    def interpret_tool_output(
        self,
        tool_name: str,
        stdout:    str,
        stderr:    str,
        context:   Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Ask AI to interpret tool output and extract structured insights.
        Used by orchestrator after each tool run.
        """
        if not stdout.strip() or not self._analyse_prompt:
            return {"classification": self.classify_output(stdout, stderr)}

        prompt = self._analyse_prompt.format(
            tool_name = tool_name,
            target    = self.session.meta.target,
            stdout    = stdout[:2000],
            stderr    = stderr[:500],
            context   = json.dumps(context or {}, indent=2)[:500],
        )

        result = self.ai.json_generate(prompt=prompt, temperature=0.1)

        classification = self.classify_output(stdout, stderr)

        if result:
            return {
                "classification":   classification,
                "key_findings":     result.get("key_findings", []),
                "severity":         result.get("severity", "info"),
                "next_tools":       result.get("next_tools", []),
                "attack_vectors":   result.get("attack_vectors", []),
                "ai_summary":       result.get("summary", ""),
                "should_escalate":  result.get("should_escalate", False),
            }

        return {"classification": classification}

    # ── Attack chain detection ────────────────────────────────

    def find_chains(self, findings: List[Finding]) -> List[Dict]:
        """
        Detect multi-step attack chains from finding combinations.
        Returns list of chain dicts with severity and MITRE mappings.
        """
        all_tags = set()
        for f in findings:
            all_tags.update(f.tags)
            # Also check title/description keywords
            combined = (f.title + " " + f.description).lower()
            for keyword in ["sqli", "xss", "rce", "lfi", "ssrf", "xxe", "ssti",
                            "credentials", "smb", "ssh", "kerberoast", "asrep",
                            "secretsdump", "s3", "bucket", "takeover", "secret",
                            "api_key", "token"]:
                if keyword in combined:
                    all_tags.add(keyword)

        chains = []
        for pattern in CHAIN_PATTERNS:
            matched = [req for req in pattern["requires"] if req in all_tags]
            if len(matched) >= max(1, len(pattern["requires"]) // 2):
                # Find supporting findings
                supporting = [
                    f for f in findings
                    if any(
                        req in " ".join(f.tags).lower() or
                        req in (f.title + f.description).lower()
                        for req in pattern["requires"]
                    )
                ]
                chains.append({
                    "name":        pattern["name"],
                    "severity":    pattern["severity"].value,
                    "description": pattern["description"],
                    "mitre":       pattern["mitre"],
                    "matched_on":  matched,
                    "supporting_findings": [f.id for f in supporting[:5]],
                    "confidence":  len(matched) / len(pattern["requires"]),
                })

        chains.sort(key=lambda c: c["confidence"], reverse=True)
        return chains

    # ── Prioritisation ────────────────────────────────────────

    def prioritise(self, findings: List[Finding]) -> List[Dict]:
        """
        Score and rank findings for exploitation priority.
        Returns top findings with exploit score.
        """
        scored = []
        for f in findings:
            score = 0.0
            # Severity weight
            sev_weights = {
                "critical": 10.0,
                "high":     7.0,
                "medium":   4.0,
                "low":      1.5,
                "info":     0.0,
            }
            score += sev_weights.get(f.severity.value, 0)

            # Boost for confirmed exploits
            boost_keywords = ["confirmed", "injectable", "cracked", "valid", "[+]"]
            if any(k in f.title.lower() or k in f.description.lower() for k in boost_keywords):
                score += 5.0

            # Boost for CVE presence
            if f.cve:
                score += 2.0

            # Boost for evidence
            if f.evidence and len(f.evidence) > 20:
                score += 1.0

            # Boost for exploitable tags
            exploit_tags = {"rce", "sqli", "xss", "lfi", "ssrf", "credentials",
                            "takeover", "secret", "shell", "privesc"}
            tag_overlap = exploit_tags.intersection(set(f.tags))
            score += len(tag_overlap) * 1.5

            scored.append({
                "finding_id":  f.id,
                "title":       f.title,
                "host":        f.host,
                "severity":    f.severity.value,
                "score":       round(score, 2),
                "cve":         f.cve,
                "tags":        f.tags[:5],
                "has_remediation": bool(f.remediation),
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:20]

    # ── Next action recommendations ───────────────────────────

    def recommend_next_actions(
        self,
        findings:   List[Finding],
        chains:     List[Dict],
    ) -> List[Dict]:
        """
        Recommend next exploitation or investigation steps
        based on current findings and detected chains.
        """
        actions = []

        # Critical findings → immediate exploitation
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                actions.append({
                    "priority":    1,
                    "action":      "exploit",
                    "reason":      f"Critical finding: {f.title}",
                    "target":      f.host,
                    "finding_id":  f.id,
                    "suggested_tools": self._suggest_tools(f),
                })

        # Chains → coordinated exploitation
        for chain in chains[:3]:
            if chain["confidence"] > 0.6:
                actions.append({
                    "priority":    2,
                    "action":      "chain_exploit",
                    "reason":      f"Attack chain detected: {chain['name']}",
                    "target":      self.session.meta.target,
                    "chain":       chain["name"],
                    "mitre":       chain["mitre"],
                    "suggested_tools": [],
                })

        # Credentials found → expand
        cred_findings = [f for f in findings if "credentials" in " ".join(f.tags)]
        if cred_findings:
            actions.append({
                "priority":    1,
                "action":      "credential_expansion",
                "reason":      f"Credentials found — attempt lateral movement",
                "target":      self.session.meta.target,
                "finding_ids": [f.id for f in cred_findings],
                "suggested_tools": ["crackmapexec", "impacket-psexec", "evil-winrm"],
            })

        # Subdomains → expand surface
        sub_count = sum(1 for f in findings if "subdomain" in f.tags)
        if sub_count > 10:
            actions.append({
                "priority":    3,
                "action":      "expand_surface",
                "reason":      f"{sub_count} subdomains found — run depth recon",
                "target":      self.session.meta.target,
                "suggested_tools": ["nuclei", "httpx", "ffuf"],
            })

        actions.sort(key=lambda a: a["priority"])
        return actions[:10]

    # ── AI interpretation ─────────────────────────────────────

    def _ai_interpret(
        self,
        findings: List[Finding],
        chains:   List[Dict],
    ) -> str:
        """Generate AI narrative summary of findings."""
        top = findings[:10]
        summary_data = {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
            "high":     sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
            "chains":   [c["name"] for c in chains],
            "top_findings": [
                {"title": f.title, "severity": f.severity.value, "host": f.host}
                for f in top
            ],
        }

        prompt = (
            f"You are a senior penetration tester. "
            f"Analyse these findings for {self.session.meta.target} and write "
            f"a 2-sentence tactical summary focusing on the highest-impact paths. "
            f"Be specific. No fluff.\n\n"
            f"Data: {json.dumps(summary_data, indent=2)}"
        )

        return self.ai.generate(prompt=prompt, temperature=0.2, max_tokens=256)

    # ── Utilities ─────────────────────────────────────────────

    def _match_any(self, text: str, patterns: List[str]) -> bool:
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False

    def _suggest_tools(self, finding: Finding) -> List[str]:
        tag_tool_map = {
            "sqli":         ["sqlmap", "ghauri"],
            "xss":          ["dalfox", "xsstrike"],
            "rce":          ["commix", "metasploit"],
            "lfi":          ["lfimap", "ffuf"],
            "ssrf":         ["ssrfmap", "gopherus"],
            "ssti":         ["tplmap"],
            "xxe":          ["xxeinjector"],
            "smb":          ["crackmapexec", "impacket-psexec"],
            "ssh":          ["hydra", "medusa"],
            "kerberoast":   ["impacket-GetUserSPNs", "hashcat"],
            "credentials":  ["crackmapexec", "evil-winrm"],
            "subdomain":    ["subjack", "nuclei"],
            "secret":       ["trufflehog", "secretfinder"],
            "wordpress":    ["wpscan"],
            "ssl":          ["sslscan", "testssl.sh"],
        }
        tools = set()
        for tag in finding.tags:
            tools.update(tag_tool_map.get(tag.lower(), []))
        return list(tools)[:5]

    def finding_delta(
        self,
        before_count: int,
        after_count:  int,
        new_findings: List[Finding],
    ) -> Dict:
        """Summarise what changed after a task ran."""
        return {
            "new_count":     after_count - before_count,
            "critical_new":  sum(1 for f in new_findings if f.severity == SeverityLevel.CRITICAL),
            "high_new":      sum(1 for f in new_findings if f.severity == SeverityLevel.HIGH),
            "new_hosts":     list({f.host for f in new_findings if f.host}),
            "new_cves":      list({f.cve for f in new_findings if f.cve}),
        }
