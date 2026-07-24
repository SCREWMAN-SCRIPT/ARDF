"""
modules/active.py
──────────────────
Active scanning and service enumeration.

Performs port scanning, service detection, and web enumeration
on target systems. Always gated behind confirmation.
"""

import os
import socket
import subprocess
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


class ActiveScanner:
    """
    Active scanning engine — port scan, service detection,
    web enumeration, and SSL/TLS audit.
    """

    def __init__(self, session: Session, logger: ARDFLogger = None):
        self.session = session
        self.logger = logger or get_logger("active")
        self.out_dir = session.dir("active")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.tool_paths = self._find_tools()

    def _find_tools(self) -> Dict[str, str]:
        tools = {}
        for name in ["nmap", "masscan", "curl", "openssl", "sslscan", "whatweb", "testssl", "nikto", "nuclei"]:
            try:
                result = subprocess.run(
                    ["which", name],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if result.returncode == 0:
                    tools[name] = result.stdout.strip()
            except:
                pass
        return tools

    def port_scan(self, target: str, ports: str = "1-1000", rate: int = 1000) -> Dict:
        """Scan for open ports using masscan or nmap fallback."""
        results = {"open_ports": [], "services": {}, "raw": ""}

        # Try masscan first (faster)
        if "masscan" in self.tool_paths:
            self.logger.info(f"masscan {target}:{ports} (rate={rate})")
            stdout, stderr = self._run_cmd([
                "masscan", target, "-p", ports,
                "--rate", str(rate),
                "-oJ", "-"
            ], timeout=300)

            try:
                data = json.loads(stdout)
                if data:
                    for entry in data:
                        for port in entry.get("ports", []):
                            results["open_ports"].append(port["port"])
                    self.logger.success(f"masscan found {len(results['open_ports'])} open ports")
            except:
                # Fallback to nmap
                if "nmap" in self.tool_paths:
                    return self._nmap_scan(target, ports)

        elif "nmap" in self.tool_paths:
            return self._nmap_scan(target, ports)

        return results

    def _nmap_scan(self, target: str, ports: str) -> Dict:
        """Nmap port scan with service detection."""
        results = {"open_ports": [], "services": {}, "raw": ""}

        nmap_xml = self.out_dir / f"nmap_{target.replace('.', '_')}.xml"
        self.logger.info(f"nmap -sS -sV -p {ports} {target}")

        stdout, stderr = self._run_cmd([
            "nmap", "-sS", "-sV", "-p", ports,
            "--open", "--version-intensity", "5",
            target, "-oX", str(nmap_xml)
        ], timeout=600)

        if nmap_xml.exists():
            try:
                import xml.etree.ElementTree as ET
                root = ET.parse(nmap_xml).getroot()
                for host in root.findall("host"):
                    for port_el in host.findall(".//port"):
                        port = int(port_el.get("portid"))
                        state = port_el.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        service = port_el.find("service")
                        svc_name = service.get("name", "") if service is not None else ""
                        product = service.get("product", "") if service is not None else ""
                        version = service.get("version", "") if service is not None else ""
                        results["open_ports"].append(port)
                        results["services"][port] = {
                            "name": svc_name,
                            "product": product,
                            "version": version
                        }
                        self.session.add_finding(Finding(
                            source=f"active.nmap",
                            title=f"Open port: {port}/{svc_name}",
                            description=f"product={product} version={version}",
                            severity=SeverityLevel.INFO,
                            host=target,
                            port=port,
                            tags=["port", "nmap", svc_name]
                        ))
            except Exception as e:
                self.logger.warning(f"nmap XML parse error: {e}")

        results["raw"] = stdout[:2000]
        return results

    def web_enum(self, target: str, ports: List[int] = [80, 443, 8080, 8443, 8000]) -> Dict:
        """Enumerate web services on target."""
        results = {"urls": [], "technologies": [], "findings": []}

        for port in ports:
            for protocol in ["http", "https"]:
                url = f"{protocol}://{target}:{port}"
                self.logger.info(f"Checking {url}")

                try:
                    response = self._fetch_url(url, timeout=5)
                    if response:
                        results["urls"].append(url)
                        results["technologies"].extend(self._detect_tech(response))
                        self.session.add_finding(Finding(
                            source="active.web",
                            title=f"Web service at {url}",
                            description=f"status={response['status_code']} {response['title']}",
                            severity=SeverityLevel.INFO,
                            host=target,
                            port=port,
                            tags=["web", "http", "https"],
                            evidence=response["title"]
                        ))
                except:
                    pass

        return results

    def _fetch_url(self, url: str, timeout: int = 5) -> Optional[Dict]:
        """Fetch URL and return basic info."""
        import requests
        try:
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            title = "No title"
            if "text/html" in response.headers.get("Content-Type", ""):
                import re
                match = re.search(r"<title>(.*?)</title>", response.text, re.I)
                if match:
                    title = match.group(1).strip()[:100]
            return {
                "status_code": response.status_code,
                "server": response.headers.get("Server", ""),
                "content_type": response.headers.get("Content-Type", ""),
                "title": title,
                "headers": dict(response.headers)
            }
        except:
            return None

    def _detect_tech(self, response: Dict) -> List[str]:
        """Detect web technologies from response."""
        techs = []
        server = response.get("server", "").lower()
        headers = response.get("headers", {})

        if "iis" in server:
            techs.append("IIS")
        if "apache" in server:
            techs.append("Apache")
        if "nginx" in server:
            techs.append("Nginx")
        if "cloudflare" in server or "cloudflare" in str(headers):
            techs.append("Cloudflare")
        if "x-powered-by" in headers:
            techs.append(headers["x-powered-by"])
        if "x-aspnet-version" in headers:
            techs.append("ASP.NET")
        if "asp.net" in server:
            techs.append("ASP.NET")

        return techs

    def ssl_audit(self, target: str, port: int = 443) -> Dict:
        """Audit SSL/TLS configuration."""
        results = {"protocols": [], "ciphers": [], "weak": [], "findings": []}

        # Try sslscan first
        if "sslscan" in self.tool_paths:
            self.logger.info(f"sslscan {target}:{port}")
            stdout, stderr = self._run_cmd([
                "sslscan", "--no-colour", f"{target}:{port}"
            ], timeout=120)

            weak_indicators = {
                "sslv2": "SSLv2 enabled",
                "sslv3": "SSLv3 enabled",
                "tls 1.0": "TLS 1.0 enabled",
                "tls 1.1": "TLS 1.1 enabled",
                "rc4": "RC4 cipher suite enabled",
                "null": "NULL cipher suite available",
                "export": "EXPORT cipher available",
            }

            for line in stdout.splitlines():
                line_lower = line.lower()
                for keyword, desc in weak_indicators.items():
                    if keyword in line_lower:
                        results["weak"].append(desc)
                        self.session.add_finding(Finding(
                            source="active.ssl",
                            title=f"SSL/TLS weakness: {desc}",
                            severity=SeverityLevel.HIGH if "SSLv" in keyword else SeverityLevel.MEDIUM,
                            host=target,
                            port=port,
                            tags=["ssl", "tls", "sslscan", keyword],
                            evidence=line.strip()
                        ))

        # Try testssl.sh
        if "testssl" in self.tool_paths:
            self.logger.info(f"testssl {target}:{port}")
            testssl_json = self.out_dir / f"testssl_{target.replace('.', '_')}.json"
            stdout, stderr = self._run_cmd([
                "testssl.sh", "--jsonfile", str(testssl_json),
                "--severity", "MEDIUM", f"{target}:{port}"
            ], timeout=300)

            if testssl_json.exists():
                try:
                    data = json.loads(testssl_json.read_text())
                    for finding in data:
                        sev = finding.get("severity", "INFO").upper()
                        if sev in ("HIGH", "CRITICAL", "MEDIUM"):
                            self.session.add_finding(Finding(
                                source="active.ssl",
                                title=f"testssl: {finding.get('id', '')} — {finding.get('finding', '')[:60]}",
                                severity=SeverityLevel.HIGH if sev in ("HIGH", "CRITICAL") else SeverityLevel.MEDIUM,
                                host=target,
                                port=port,
                                tags=["ssl", "tls", "testssl"],
                                evidence=json.dumps(finding)[:300]
                            ))
                except:
                    pass

        return results

    def _run_cmd(self, cmd: List[str], timeout: int = 60) -> Tuple[str, str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except Exception as e:
            return "", str(e)


def run_active(target: str, session: Session, logger: Optional[ARDFLogger] = None) -> Dict:
    """Entry point for active scanning."""
    if logger is None:
        logger = get_logger("active")

    scanner = ActiveScanner(session, logger)

    results = {}

    # 1. Port scan
    logger.info(f"Port scanning {target}")
    port_results = scanner.port_scan(target, ports="1-1000")
    results["ports"] = port_results

    # 2. Web enumeration
    web_results = {}
    open_ports = port_results.get("open_ports", [])
    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000]]
    if web_ports:
        logger.info(f"Web enumeration on ports: {web_ports}")
        web_results = scanner.web_enum(target, web_ports)
    results["web"] = web_results

    # 3. SSL audit
    ssl_results = {}
    if 443 in open_ports:
        logger.info(f"SSL audit on {target}:443")
        ssl_results = scanner.ssl_audit(target)
    results["ssl"] = ssl_results

    return results
