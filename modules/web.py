"""
modules/web.py
───────────────
Web application scanning module.

Enumerates directories, detects WAF, fingerprints CMS,
and runs vulnerability checks against web targets.
"""

import os
import requests
import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


class WebScanner:
    def __init__(self, session: Session, logger: ARDFLogger = None):
        self.session = session
        self.logger = logger or get_logger("web")
        self.out_dir = session.dir("web")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.wordlist = Path("/usr/share/wordlists/dirb/common.txt")

    def dir_bruteforce(self, url: str, wordlist: str = None) -> List[Dict]:
        """Brute-force directories using ffuf or wfuzz."""
        results = []
        wl = wordlist or str(self.wordlist)
        if not Path(wl).exists():
            self.logger.warning(f"Wordlist not found: {wl}")
            return results

        # Try ffuf first
        output = self.out_dir / f"ffuf_{hash(url)}.json"
        try:
            subprocess.run([
                "ffuf", "-u", f"{url}/FUZZ", "-w", wl,
                "-fc", "404", "-t", "50", "-ac",
                "-json", "-o", str(output)
            ], timeout=120, capture_output=True)

            if output.exists():
                data = json.loads(output.read_text())
                for entry in data.get("results", []):
                    path = entry.get("input", {}).get("FUZZ", "")
                    status = entry.get("status", 0)
                    size = entry.get("length", 0)
                    results.append({"path": path, "status": status, "size": size})
        except:
            # Fallback: curl check common paths
            common = ["admin", "login", "wp-admin", "api", "dashboard", "cms", "upload", "backup", "config", "sql"]
            for path in common:
                try:
                    resp = requests.get(f"{url}/{path}", timeout=5, verify=False)
                    if resp.status_code not in [404, 403]:
                        results.append({"path": path, "status": resp.status_code, "size": len(resp.text)})
                except:
                    pass

        self.logger.success(f"Directory enumeration: {len(results)} found")
        return results

    def waf_detect(self, url: str) -> Dict:
        """Detect WAF using wafw00f."""
        try:
            result = subprocess.run(
                ["wafw00f", url, "-a"],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout
            for line in output.splitlines():
                if "is behind" in line:
                    waf_name = re.search(r"is behind (.*?)(?: \(|$)", line)
                    if waf_name:
                        return {"waf": True, "name": waf_name.group(1), "info": line.strip()}
        except:
            pass
        return {"waf": False}

    def cms_detect(self, url: str) -> List[str]:
        """Detect CMS using whatweb."""
        cms = []
        try:
            result = subprocess.run(
                ["whatweb", "--log-json", "-", url],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.stdout:
                try:
                    data = json.loads(result.stdout.splitlines()[0])
                    cms_list = data.get("plugins", {})
                    for name in cms_list:
                        if "wordpress" in name.lower():
                            cms.append("WordPress")
                        elif "drupal" in name.lower():
                            cms.append("Drupal")
                        elif "joomla" in name.lower():
                            cms.append("Joomla")
                        elif "magento" in name.lower():
                            cms.append("Magento")
                        elif "shopify" in name.lower():
                            cms.append("Shopify")
                except:
                    pass
        except:
            pass
        return list(set(cms))

    def nikto_scan(self, url: str) -> Dict:
        """Run nikto scan."""
        results = {"findings": []}
        try:
            nikto_json = self.out_dir / f"nikto_{hash(url)}.json"
            subprocess.run([
                "nikto", "-h", url, "-Format", "json",
                "-o", str(nikto_json), "-nointeractive"
            ], timeout=600, capture_output=True)

            if nikto_json.exists():
                data = json.loads(nikto_json.read_text())
                for vuln in data.get("vulnerabilities", []):
                    results["findings"].append({
                        "id": vuln.get("id", ""),
                        "msg": vuln.get("msg", ""),
                        "method": vuln.get("method", "")
                    })
        except:
            pass
        return results

    def nuclei_scan(self, url: str) -> List[Dict]:
        """Run nuclei scan on web target."""
        results = []
        try:
            nuclei_json = self.out_dir / f"nuclei_{hash(url)}.jsonl"
            subprocess.run([
                "nuclei", "-u", url,
                "-tags", "cve,misconfig,exposed,default-login,tech",
                "-severity", "medium,high,critical",
                "-json-export", str(nuclei_json),
                "-silent", "-retries", "2"
            ], timeout=600, capture_output=True)

            if nuclei_json.exists():
                for line in nuclei_json.read_text().splitlines():
                    try:
                        d = json.loads(line)
                        results.append({
                            "title": d.get("info", {}).get("name", ""),
                            "severity": d.get("info", {}).get("severity", "medium"),
                            "matched": d.get("matched-at", ""),
                            "cve": d.get("info", {}).get("classification", {}).get("cve-id", [""])[0]
                        })
                    except:
                        pass
        except:
            pass
        return results

    def scan(self, url: str) -> Dict:
        """Full web scan."""
        self.logger.info(f"Web scan: {url}")
        results = {
            "directories": self.dir_bruteforce(url),
            "waf": self.waf_detect(url),
            "cms": self.cms_detect(url),
            "nikto": self.nikto_scan(url),
            "nuclei": self.nuclei_scan(url)
        }

        # Add findings for directories
        for d in results["directories"]:
            if d["status"] in [200, 301, 302]:
                sev = SeverityLevel.MEDIUM if any(k in d["path"].lower() for k in ["admin", "login", "wp-admin", "backup", "config", "sql"]) else SeverityLevel.INFO
                self.session.add_finding(Finding(
                    source="web.dir",
                    title=f"Directory found: {d['path']}",
                    description=f"status={d['status']} size={d['size']}",
                    severity=sev,
                    host=url,
                    tags=["web", "directory", "ffuf"],
                    evidence=d["path"]
                ))

        # Add findings for WAF
        if results["waf"]["waf"]:
            self.session.add_finding(Finding(
                source="web.waf",
                title=f"WAF detected: {results['waf'].get('name', 'Unknown')}",
                description=results["waf"].get("info", ""),
                severity=SeverityLevel.INFO,
                host=url,
                tags=["waf", "detection"],
                evidence=results["waf"].get("info", "")
            ))

        # Add findings for CMS
        if results["cms"]:
            self.session.add_finding(Finding(
                source="web.cms",
                title=f"CMS detected: {', '.join(results['cms'])}",
                severity=SeverityLevel.INFO,
                host=url,
                tags=["cms", "fingerprint"]
            ))

        # Add findings for Nikto
        for vuln in results["nikto"].get("findings", []):
            self.session.add_finding(Finding(
                source="web.nikto",
                title=f"Nikto: {vuln.get('id', '?')}",
                description=vuln.get("msg", "")[:200],
                severity=SeverityLevel.MEDIUM,
                host=url,
                tags=["nikto", "web", "vulnerability"],
                evidence=vuln.get("msg", "")
            ))

        # Add findings for Nuclei
        for vuln in results["nuclei"]:
            sev_map = {"critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM}
            sev = sev_map.get(vuln.get("severity", "medium").lower(), SeverityLevel.MEDIUM)
            self.session.add_finding(Finding(
                source="web.nuclei",
                title=f"Nuclei: {vuln.get('title', '')[:60]}",
                description=vuln.get("title", ""),
                severity=sev,
                host=url,
                cve=vuln.get("cve", ""),
                tags=["nuclei", "vulnerability"],
                evidence=vuln.get("matched", "")
            ))

        return results
