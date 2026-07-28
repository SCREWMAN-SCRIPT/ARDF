"""
ai/analyst.py
─────────────
AI Analyst module for ARDF.

Enhanced with Cloudflare-aware analysis:
  - Interprets Cloudflare findings
  - Identifies bypass opportunities
  - Correlates origin candidates with vulnerabilities
  - Suggests attack paths based on WAF type

The analyst uses local Qwen2.5 to interpret findings and
provide context-aware recommendations.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.intel import QwenAnalyst


# ─────────────────────────────────────────────────────────────
# Analyst Class
# ─────────────────────────────────────────────────────────────

class FindingAnalyst:
    """
    AI-driven analysis of findings with Cloudflare awareness.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("analyst")
        self.ai = QwenAnalyst()

    # ── Cloudflare-specific analysis ─────────────────────────

    def analyse_cloudflare_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Analyse Cloudflare-related findings and identify bypass opportunities.
        """
        cf_findings = [f for f in findings if "cloudflare" in f.tags or "waf" in f.tags]
        if not cf_findings:
            return {"detected": False}

        analysis = {
            "detected": True,
            "version": None,
            "origin_candidates": [],
            "bypass_techniques": [],
            "risk_assessment": "medium",
            "recommendations": []
        }

        # Extract version info
        for f in cf_findings:
            if "version" in f.title.lower():
                match = re.search(r'version[:]?\s*([^\s,]+)', f.title, re.I)
                if match:
                    analysis["version"] = match.group(1)

            # Extract origin candidates from evidence
            if f.evidence:
                ip_matches = re.findall(r'[\d.]+', f.evidence)
                for ip in ip_matches:
                    if len(ip.split('.')) == 4:
                        analysis["origin_candidates"].append(ip)

        # Deduplicate candidates
        analysis["origin_candidates"] = list(dict.fromkeys(analysis["origin_candidates"]))

        # Determine bypass techniques
        if analysis["origin_candidates"]:
            analysis["bypass_techniques"] = [
                "direct_origin_attack",
                "host_header_manipulation"
            ]
            analysis["risk_assessment"] = "high"
            analysis["recommendations"].append(
                f"Origin IP exposed: {', '.join(analysis['origin_candidates'][:3])}. "
                "Direct attack possible."
            )
        else:
            analysis["bypass_techniques"] = [
                "dns_history",
                "ssl_cert_history",
                "subdomain_enumeration",
                "mx_record",
                "cloudflare_worker_exploit",
                "cache_poisoning"
            ]
            analysis["recommendations"].append(
                "Run Cloudflare bypass techniques to discover origin IP."
            )

        # Add AI-generated analysis if available
        ai_analysis = self.ai.analyse_finding(cf_findings[0]) if cf_findings else ""
        if ai_analysis:
            analysis["ai_analysis"] = ai_analysis

        return analysis

    def interpret_bypass_results(self, bypass_data: Dict) -> Dict[str, Any]:
        """
        Interpret Cloudflare bypass results and suggest next steps.
        """
        if not bypass_data:
            return {"status": "no_bypass_data"}

        interpretation = {
            "bypass_achieved": bypass_data.get("bypass_achieved", False),
            "origin_candidates": bypass_data.get("origin_candidates", []),
            "successful_techniques": [],
            "next_steps": [],
            "risk": "low"
        }

        techniques = bypass_data.get("techniques", {})
        for tech_name, tech_result in techniques.items():
            if tech_result.get("success"):
                interpretation["successful_techniques"].append(tech_name)
                ip = tech_result.get("origin_ip")
                if ip:
                    interpretation["next_steps"].append(
                        f"Attack origin directly at {ip} using host header manipulation"
                    )

        if interpretation["bypass_achieved"]:
            interpretation["risk"] = "critical"
            interpretation["next_steps"].insert(0,
                f"Origin found: {', '.join(interpretation['origin_candidates'][:3])}. "
                "Proceed with direct exploitation."
            )
        else:
            interpretation["next_steps"].append(
                "Run additional bypass techniques or use social engineering/phishing vectors."
            )

        return interpretation

    def correlate_with_vulnerabilities(
        self,
        origin_ips: List[str],
        findings: List[Finding]
    ) -> Dict[str, List[Finding]]:
        """
        Correlate origin IPs with vulnerabilities.
        """
        correlation = {ip: [] for ip in origin_ips}

        for ip in origin_ips:
            for f in findings:
                if f.host == ip or ip in f.evidence:
                    correlation[ip].append(f)

        # Sort by severity
        for ip in correlation:
            correlation[ip] = sorted(
                correlation[ip],
                key=lambda f: f.severity.value,
                reverse=True
            )

        return correlation

    def suggest_attack_path(
        self,
        target: str,
        findings: List[Finding],
        bypass_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Suggest optimal attack path based on findings.
        """
        path = {
            "target": target,
            "phases": [],
            "confidence": 0.0,
            "estimated_time": "unknown"
        }

        # Phase 1: Bypass (if Cloudflare detected)
        cf_findings = [f for f in findings if "cloudflare" in f.tags or "waf" in f.tags]
        if cf_findings:
            phase = {
                "name": "Bypass Cloudflare",
                "actions": ["dns_history", "ssl_cert_history", "subdomain_enumeration"],
                "confidence": 0.6,
                "duration": "30-60 minutes"
            }

            # If bypass already achieved
            if bypass_data and bypass_data.get("bypass_achieved"):
                phase["status"] = "completed"
                phase["result"] = bypass_data.get("origin_candidates", [])
                path["phases"].append(phase)

                # Phase 2: Direct Attack
                origin = bypass_data.get("origin_candidates", [None])[0]
                if origin:
                    path["phases"].append({
                        "name": "Direct Origin Attack",
                        "actions": ["nmap_full", "web_vulnerability_scan", "exploit"],
                        "target_ip": origin,
                        "confidence": 0.8,
                        "duration": "1-2 hours",
                        "status": "ready"
                    })
            else:
                path["phases"].append(phase)

        # Phase 3: Post-Exploitation
        if any(f.severity == SeverityLevel.CRITICAL for f in findings):
            path["phases"].append({
                "name": "Post-Exploitation",
                "actions": ["persistence", "lateral_movement", "credential_dumping"],
                "confidence": 0.7,
                "duration": "2-4 hours",
                "status": "pending"
            })

        # Overall confidence
        completed = len([p for p in path["phases"] if p.get("status") == "completed"])
        total = len(path["phases"])
        path["confidence"] = completed / max(total, 1)

        return path

    # ── Full session analysis ────────────────────────────────

    def analyse_session(self) -> Dict[str, Any]:
        """
        Run full analysis on session findings with Cloudflare focus.
        """
        findings = self.session.get_findings()

        analysis = {
            "summary": {},
            "cloudflare": self.analyse_cloudflare_findings(findings),
            "critical_findings": [],
            "attack_paths": [],
            "recommendations": []
        }

        # Critical findings
        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical:
            analysis["critical_findings"] = [
                {
                    "title": f.title,
                    "host": f.host,
                    "cve": f.cve,
                    "remediation": f.remediation
                }
                for f in critical[:10]
            ]

        # Attack paths
        bypass_path = self.session.dir("bypass") / "bypass_report.json"
        bypass_data = None
        if bypass_path.exists():
            try:
                bypass_data = json.loads(bypass_path.read_text())
            except Exception:
                pass

        analysis["attack_paths"].append(
            self.suggest_attack_path(self.session.meta.target, findings, bypass_data)
        )

        # AI recommendations
        if findings:
            ai_summary = self.ai.summarise_session(findings)
            if ai_summary:
                analysis["ai_summary"] = ai_summary

            ai_next = self.ai.suggest_next_steps(
                self.session.meta.target,
                self.session.meta.modules_done,
                findings
            )
            if ai_next:
                analysis["ai_next_steps"] = ai_next

        # Add recommendations from Cloudflare analysis
        cf = analysis["cloudflare"]
        if cf.get("detected"):
            analysis["recommendations"].extend(cf.get("recommendations", []))

        return analysis


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def analyse_findings(
    session: Session,
    logger: Optional[ARDFLogger] = None,
) -> Dict[str, Any]:
    """
    Convenience function to run analyst on session.
    """
    if logger is None:
        logger = get_logger("analyst")

    logger.banner("AI FINDING ANALYSIS", style="bold yellow")
    analyst = FindingAnalyst(session, logger)
    results = analyst.analyse_session()

    # Save results
    report_path = session.dir("ai") / "analysis_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2, default=str))

    logger.success(f"Analysis complete → {report_path}")
    return results