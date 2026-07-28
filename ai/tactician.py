"""
ai/tactician.py
───────────────
AI Tactician module for ARDF.

Enhanced with Cloudflare-aware tactical decisions:
  - Suggests bypass techniques when Cloudflare detected
  - Recommends fallback strategies on failure
  - Chooses optimal attack vectors based on WAF type
  - Provides evasion recommendations

The tactician is the decision-making layer that adapts
based on real-time findings and tool outputs.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.intel import QwenAnalyst


# ─────────────────────────────────────────────────────────────
# Tactician Class
# ─────────────────────────────────────────────────────────────

class Tactician:
    """
    AI-driven tactical decision maker with Cloudflare awareness.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("tactician")
        self.ai = QwenAnalyst()
        self._bypass_cache: Dict[str, Any] = {}
        self._fallback_stack: List[str] = []

    # ── Cloudflare bypass suggestions ────────────────────────

    def suggest_bypass_techniques(self, target: str, context: Dict) -> Dict[str, Any]:
        """
        Suggest optimal bypass techniques for Cloudflare target.
        """
        suggestions = {
            "target": target,
            "bypass_techniques": [],
            "priority_order": [],
            "fallback_strategies": [],
            "estimated_success_rate": 0.0,
            "ai_reasoning": ""
        }

        # Determine which techniques are likely to work
        techniques = {
            "dns_history": {
                "priority": 1,
                "description": "Query DNS history for origin IP",
                "success_rate": 0.4,
                "time": "2-5 min",
                "requires_api": True
            },
            "ssl_cert_history": {
                "priority": 2,
                "description": "Extract IPs from SSL certificate history",
                "success_rate": 0.35,
                "time": "3-5 min",
                "requires_api": False
            },
            "subdomain_enumeration": {
                "priority": 3,
                "description": "Enumerate subdomains that may bypass Cloudflare",
                "success_rate": 0.25,
                "time": "10-15 min",
                "requires_api": False
            },
            "mx_record": {
                "priority": 4,
                "description": "Check MX records for origin IP",
                "success_rate": 0.2,
                "time": "1-2 min",
                "requires_api": False
            },
            "worker_exploit": {
                "priority": 5,
                "description": "Exploit misconfigured Cloudflare Workers",
                "success_rate": 0.15,
                "time": "5-10 min",
                "requires_api": False
            },
            "cache_poisoning": {
                "priority": 6,
                "description": "Poison Cloudflare cache to reveal origin",
                "success_rate": 0.1,
                "time": "5-10 min",
                "requires_api": False
            }
        }

        # Sort by priority and success rate
        sorted_techniques = sorted(
            techniques.items(),
            key=lambda x: (x[1]["priority"], -x[1]["success_rate"])
        )

        suggestions["bypass_techniques"] = [
            {"name": name, **data}
            for name, data in sorted_techniques
        ]

        suggestions["priority_order"] = [name for name, _ in sorted_techniques]

        # Fallback strategies
        suggestions["fallback_strategies"] = [
            "Use social engineering to obtain origin IP",
            "Look for public security.txt or exposed endpoints",
            "Check GitHub for leaked API keys that may reveal origin",
            "Use Shodan/Censys to find other IPs on same network",
            "Consider phishing or credential harvesting"
        ]

        # Estimate success rate
        suggestions["estimated_success_rate"] = sum(
            data["success_rate"] for _, data in sorted_techniques[:3]
        ) / 3

        # AI reasoning
        if self.ai._ollama_available():
            prompt = (
                f"Target: {target}\n"
                f"Cloudflare detected. Suggest the most effective bypass strategy.\n"
                f"Available techniques: {', '.join(suggestions['priority_order'])}\n"
                f"Provide 2-3 sentences of tactical reasoning."
            )
            suggestions["ai_reasoning"] = self.ai._ask(prompt)

        return suggestions

    def suggest_fallback_on_failure(
        self,
        target: str,
        failed_techniques: List[str],
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Suggest fallback strategy when bypass techniques fail.
        """
        suggestions = {
            "target": target,
            "failed_techniques": failed_techniques,
            "fallback": [],
            "alternative_vectors": [],
            "recommendation": ""
        }

        # Check if any findings suggest alternative paths
        for f in findings:
            if "subdomain" in f.tags and f.host:
                suggestions["alternative_vectors"].append({
                    "type": "subdomain",
                    "value": f.host,
                    "reason": "Subdomain may have different WAF configuration"
                })
            if "cloud" in f.tags and f.evidence:
                suggestions["alternative_vectors"].append({
                    "type": "cloud_resource",
                    "value": f.evidence[:100],
                    "reason": "Cloud resource may be outside Cloudflare"
                })

        # Fallback strategies
        suggestions["fallback"] = [
            "Try host header manipulation with all origin candidates",
            "Use Cloudflare Worker exploit if not already attempted",
            "Check for misconfigured subdomains (dev, test, staging)",
            "Look for exposed .env or configuration files",
            "Try cache poisoning with different host headers",
            "Use third-party services (Shodan/Censys) for additional OSINT"
        ]

        # Add AI recommendation
        if self.ai._ollama_available():
            prompt = (
                f"All Cloudflare bypass techniques failed for {target}.\n"
                f"Failed techniques: {', '.join(failed_techniques)}\n"
                f"Available alternative vectors: {json.dumps(suggestions['alternative_vectors'])}\n"
                f"Suggest the next best action (1-2 sentences)."
            )
            suggestions["recommendation"] = self.ai._ask(prompt)

        return suggestions

    # ── Attack vector selection ──────────────────────────────

    def select_attack_vector(
        self,
        target: str,
        bypass_data: Optional[Dict],
        services: List[str],
        cves: List[str]
    ) -> Dict[str, Any]:
        """
        Select optimal attack vector based on current state.
        """
        selection = {
            "target": target,
            "bypass_achieved": bypass_data.get("bypass_achieved", False) if bypass_data else False,
            "selected_vector": None,
            "alternatives": [],
            "confidence": 0.0,
            "reasoning": ""
        }

        # Prioritize vectors
        vectors = []

        if bypass_data and bypass_data.get("bypass_achieved"):
            origin = bypass_data.get("origin_candidates", [None])[0]
            if origin:
                vectors.append({
                    "name": "direct_origin_attack",
                    "priority": 1,
                    "confidence": 0.8,
                    "description": f"Direct attack on origin IP {origin}",
                    "requires": ["bypass_completed"]
                })

        # Service-based vectors
        for service in services:
            if "nginx" in service.lower():
                vectors.append({
                    "name": "nginx_cve_exploit",
                    "priority": 2,
                    "confidence": 0.6,
                    "description": f"Exploit nginx CVEs on {target}",
                    "requires": ["service_identified"]
                })
            elif "apache" in service.lower():
                vectors.append({
                    "name": "apache_cve_exploit",
                    "priority": 2,
                    "confidence": 0.6,
                    "description": f"Exploit Apache CVEs on {target}",
                    "requires": ["service_identified"]
                })
            elif "tomcat" in service.lower():
                vectors.append({
                    "name": "tomcat_exploit",
                    "priority": 2,
                    "confidence": 0.5,
                    "description": f"Exploit Tomcat on {target}",
                    "requires": ["service_identified"]
                })

        # CVE-based vectors
        for cve in cves[:5]:
            vectors.append({
                "name": f"cve_{cve}",
                "priority": 3,
                "confidence": 0.5,
                "description": f"Exploit {cve} on {target}",
                "requires": ["cve_identified"]
            })

        # Sort by priority
        vectors.sort(key=lambda x: x["priority"])

        if vectors:
            selection["selected_vector"] = vectors[0]
            selection["alternatives"] = vectors[1:]
            selection["confidence"] = vectors[0]["confidence"]

        # AI reasoning
        if self.ai._ollama_available():
            prompt = (
                f"Target: {target}\n"
                f"Bypass achieved: {selection['bypass_achieved']}\n"
                f"Available services: {', '.join(services)}\n"
                f"CVEs: {', '.join(cves[:5])}\n"
                f"Selected vector: {selection['selected_vector']}\n"
                f"Provide tactical reasoning for this selection (2-3 sentences)."
            )
            selection["reasoning"] = self.ai._ask(prompt)

        return selection

    # ── Evasion recommendations ──────────────────────────────

    def suggest_evasion(self, target: str, waf_type: Optional[str]) -> Dict[str, Any]:
        """
        Suggest evasion techniques based on WAF type.
        """
        suggestions = {
            "target": target,
            "waf_type": waf_type,
            "techniques": [],
            "rate_limiting": {},
            "user_agent_rotation": True,
            "ip_rotation": False
        }

        if waf_type == "cloudflare":
            suggestions["techniques"] = [
                "Use HTTP/2 connection reuse",
                "Rotate User-Agent per request",
                "Add random query parameters to each request",
                "Use keep-alive connections",
                "Slow down rate to 1-2 requests per second"
            ]
            suggestions["rate_limiting"] = {
                "requests_per_second": 2,
                "burst": 5,
                "delay_between_requests": 0.5
            }
        elif waf_type in ("akamai", "cloudfront"):
            suggestions["techniques"] = [
                "Use HTTP/1.1 with connection: close",
                "Rotate IP via proxy",
                "Use TLS fingerprint spoofing"
            ]
            suggestions["rate_limiting"] = {
                "requests_per_second": 5,
                "burst": 10,
                "delay_between_requests": 0.2
            }
        else:
            suggestions["techniques"] = [
                "Standard rate limiting (5-10 req/sec)",
                "Random delays between requests",
                "Use common user agents"
            ]
            suggestions["rate_limiting"] = {
                "requests_per_second": 10,
                "burst": 20,
                "delay_between_requests": 0.1
            }

        return suggestions

    # ── Full tactical decision ───────────────────────────────

    def make_decision(self) -> Dict[str, Any]:
        """
        Full tactical decision based on session state.
        """
        findings = self.session.get_findings()
        target = self.session.meta.target

        # Load bypass data if exists
        bypass_path = self.session.dir("bypass") / "bypass_report.json"
        bypass_data = None
        if bypass_path.exists():
            try:
                bypass_data = json.loads(bypass_path.read_text())
            except Exception:
                pass

        # Detect Cloudflare
        cf_findings = [f for f in findings if "cloudflare" in f.tags or "waf" in f.tags]
        cloudflare_detected = bool(cf_findings)

        # Extract services and CVEs
        services = set()
        cves = set()
        for f in findings:
            if f.tags:
                if "tech" in f.tags:
                    services.add(f.title.lower())
                if "cve" in f.tags and f.cve:
                    cves.add(f.cve)

        decision = {
            "target": target,
            "timestamp": self.session.meta.created_at,
            "cloudflare_detected": cloudflare_detected,
            "bypass_data": bypass_data,
            "decision": {}
        }

        if cloudflare_detected:
            # Suggest bypass
            context = {"findings": [{"title": f.title, "severity": f.severity.value} for f in cf_findings[:5]]}
            decision["decision"]["bypass"] = self.suggest_bypass_techniques(target, context)

            if bypass_data and bypass_data.get("bypass_achieved"):
                decision["decision"]["attack_vector"] = self.select_attack_vector(
                    target, bypass_data, list(services), list(cves)
                )
            else:
                # Suggest fallback
                failed = bypass_data.get("techniques", {}).keys() if bypass_data else []
                decision["decision"]["fallback"] = self.suggest_fallback_on_failure(
                    target, list(failed), findings
                )
        else:
            decision["decision"]["attack_vector"] = self.select_attack_vector(
                target, None, list(services), list(cves)
            )

        # Evasion recommendations
        waf_type = "cloudflare" if cloudflare_detected else None
        decision["decision"]["evasion"] = self.suggest_evasion(target, waf_type)

        # Overall recommendation
        if cloudflare_detected and not (bypass_data and bypass_data.get("bypass_achieved")):
            decision["decision"]["recommendation"] = "Prioritize Cloudflare bypass before exploitation."
        elif decision["decision"].get("attack_vector", {}).get("selected_vector"):
            vec = decision["decision"]["attack_vector"]["selected_vector"]
            decision["decision"]["recommendation"] = (
                f"Proceed with {vec.get('name', 'unknown vector')}. "
                f"Confidence: {vec.get('confidence', 0) * 100}%"
            )
        else:
            decision["decision"]["recommendation"] = "Run additional reconnaissance before proceeding."

        # Save decision
        decision_path = self.session.dir("ai") / "tactical_decision.json"
        decision_path.parent.mkdir(parents=True, exist_ok=True)
        decision_path.write_text(json.dumps(decision, indent=2, default=str))

        return decision


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def make_tactical_decision(
    session: Session,
    logger: Optional[ARDFLogger] = None,
) -> Dict[str, Any]:
    """
    Convenience function to make tactical decision.
    """
    if logger is None:
        logger = get_logger("tactician")

    logger.banner("TACTICAL DECISION", style="bold magenta")
    tactician = Tactician(session, logger)
    decision = tactician.make_decision()

    rec = decision.get("decision", {}).get("recommendation", "No recommendation")
    logger.success(f"Decision: {rec}")

    return decision