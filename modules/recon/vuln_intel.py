"""
modules/recon/vuln_intel.py
───────────────────────────
Vulnerability intelligence reconnaissance.

Provides:
  - NVD (National Vulnerability Database) lookup
  - CVSS scoring & severity assessment
  - Exploit availability (Exploit-DB, GitHub POCs)
  - CVE timeline & patch status
  - Known vulnerable versions detection
"""

import re
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode
from modules.intel import CVEClient


class VulnIntelRecon:
    """
    Vulnerability intelligence reconnaissance.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.vuln_intel")
        self.out_dir = session.dir("recon") / "vuln_intel"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)
        self.cve_client = CVEClient()

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Look up a CVE in NVD database.
        """
        self.logger.info(f"CVE lookup: {cve_id}")

        result = {
            "cve_id": cve_id,
            "found": False,
            "description": None,
            "cvss_score": None,
            "severity": None,
            "published": None,
            "modified": None,
            "references": [],
            "exploits": []
        }

        try:
            record = self.cve_client.lookup(cve_id, logger=self.logger)
            if record:
                result["found"] = True
                result["description"] = record.get("description")
                result["cvss_score"] = record.get("cvss_score")
                result["severity"] = record.get("severity")
                result["published"] = record.get("published")
                result["modified"] = record.get("modified")
                result["references"] = record.get("references", [])

                # Check for exploits in Exploit-DB
                result["exploits"] = self.search_exploitdb(cve_id)

                self.logger.success(f"CVE {cve_id}: CVSS {result['cvss_score']} ({result['severity']})")

        except Exception as e:
            self.logger.warning(f"CVE lookup failed: {e}")

        return result

    def search_exploitdb(self, query: str) -> List[Dict[str, str]]:
        """
        Search Exploit-DB for exploits.
        """
        self.logger.info(f"Exploit-DB search: {query}")

        results = []
        try:
            import subprocess
            cmd = ["searchsploit", "--json", query]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                for item in data.get("RESULTS_EXPLOIT", [])[:10]:
                    results.append({
                        "title": item.get("Title", ""),
                        "edb_id": item.get("EDB-ID", ""),
                        "type": item.get("Type", ""),
                        "platform": item.get("Platform", ""),
                        "path": item.get("Path", ""),
                    })

            self.logger.success(f"Exploit-DB: {len(results)} results")

        except Exception as e:
            self.logger.warning(f"Exploit-DB search failed: {e}")

        return results

    def search_cves_by_product(self, product: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search CVEs for a specific product/version.
        """
        self.logger.info(f"CVE search: {product} {version or ''}")

        results = []
        try:
            keyword = product if not version else f"{product} {version}"
            results = self.cve_client.search_by_keyword(keyword, max_results=20, logger=self.logger)
            self.logger.success(f"Found {len(results)} CVEs for {product}")
        except Exception as e:
            self.logger.warning(f"CVE search failed: {e}")

        return results

    def cvss_analyze(self, cve_record: Dict) -> Dict[str, Any]:
        """
        Analyze CVSS score and provide risk assessment.
        """
        score = cve_record.get("cvss_score")
        severity = cve_record.get("severity", "unknown")

        analysis = {
            "score": score,
            "severity": severity,
            "risk_level": "unknown",
            "priority": "unknown",
            "recommendation": "Monitor"
        }

        if score is not None:
            if score >= 9.0:
                analysis["risk_level"] = "critical"
                analysis["priority"] = "immediate"
                analysis["recommendation"] = "Patch immediately. High impact."
            elif score >= 7.0:
                analysis["risk_level"] = "high"
                analysis["priority"] = "high"
                analysis["recommendation"] = "Patch within 48 hours."
            elif score >= 4.0:
                analysis["risk_level"] = "medium"
                analysis["priority"] = "medium"
                analysis["recommendation"] = "Patch within 2 weeks."
            else:
                analysis["risk_level"] = "low"
                analysis["priority"] = "low"
                analysis["recommendation"] = "Monitor and plan for future patching."

        return analysis

    def vulnerable_version_check(self, service: str, version: str) -> List[Dict]:
        """
        Check if a service version has known vulnerabilities.
        """
        self.logger.info(f"Vulnerable version check: {service} {version}")

        results = []

        # Search for CVEs matching service and version
        cves = self.search_cves_by_product(service, version)

        for cve in cves:
            analysis = self.cvss_analyze(cve)
            results.append({
                "cve_id": cve.get("cve_id"),
                "description": cve.get("description")[:200],
                "cvss_score": cve.get("cvss_score"),
                "severity": cve.get("severity"),
                "analysis": analysis
            })

        if results:
            high_severity = [r for r in results if r.get("severity") in ("critical", "high")]
            self.logger.finding(f"{service} {version}: {len(results)} CVEs ({len(high_severity)} critical/high)", severity="info")

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full vulnerability intelligence reconnaissance.
        """
        self.logger.banner(f"VULN INTEL RECON: {target}", style="bold yellow")

        self.stealth.config.scan_mode = ScanMode.PASSIVE

        results = {
            "target": target,
            "cves": [],
            "exploits": [],
            "vulnerable_services": []
        }

        # Extract services from existing findings
        findings = self.session.get_findings()
        services = {}

        for f in findings:
            if f.port and f.host:
                service = f.tags or []
                # Check for version info in description
                version_match = re.search(r'version[=:]?\s*([\d.]+)', f.description or "", re.I)
                version = version_match.group(1) if version_match else "unknown"

                service_key = f"{f.port}:{f.host}"
                if service_key not in services:
                    services[service_key] = {
                        "host": f.host,
                        "port": f.port,
                        "service": service,
                        "version": version,
                        "findings": []
                    }
                services[service_key]["findings"].append(f)

        # Check each service for vulnerabilities
        for svc in list(services.values())[:20]:
            service_name = " ".join(svc["service"]) if svc["service"] else f"port_{svc['port']}"
            if service_name and svc["version"] != "unknown":
                vulns = self.vulnerable_version_check(service_name, svc["version"])
                if vulns:
                    results["vulnerable_services"].append({
                        "host": svc["host"],
                        "port": svc["port"],
                        "service": service_name,
                        "version": svc["version"],
                        "vulnerabilities": vulns
                    })
                    for v in vulns:
                        self.session.add_finding(Finding(
                            source="recon.vuln_intel",
                            title=f"{service_name} {svc['version']}: {v.get('cve_id', 'CVE')}",
                            description=v.get("description", ""),
                            severity=SeverityLevel.CRITICAL if v.get("severity") == "critical" else SeverityLevel.HIGH,
                            host=svc["host"],
                            port=svc["port"],
                            cve=v.get("cve_id"),
                            tags=["vulnerability", "cve", "recon"],
                            evidence=json.dumps(v),
                            remediation=v.get("analysis", {}).get("recommendation", "Patch the affected service.")
                        ))

        # Save results
        report_path = self.out_dir / f"vuln_intel_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Vuln intel: {len(results['vulnerable_services'])} services with vulnerabilities")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]