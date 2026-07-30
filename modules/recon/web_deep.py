"""
modules/recon/web_deep.py
─────────────────────────
Deep web application reconnaissance.

Provides:
  - HTTP Verb Testing (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
  - Directory & File Enumeration (ffuf/gobuster)
  - Parameter Discovery (paramspider, arjun)
  - API Reconnaissance (Swagger, GraphQL, REST)
  - Content Analysis (JS, CSS, metadata)
  - Error Page Analysis
  - Session & Cookie Analysis
"""

import re
import json
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
from urllib.parse import urlparse, urljoin

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class WebDeepRecon:
    """
    Deep web application reconnaissance.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.web_deep")
        self.out_dir = session.dir("recon") / "web_deep"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # Common directory wordlist paths
        self.wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        ]

    def http_verb_testing(self, url: str) -> Dict[str, Any]:
        """
        Test for allowed HTTP methods.
        """
        self.logger.info(f"HTTP verb testing: {url}")

        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
        results = {"allowed": [], "denied": [], "methods": []}

        for method in methods:
            try:
                status, headers, content = self.stealth.request(url, method=method, timeout=5)

                if status in [200, 204, 301, 302, 303, 307, 308]:
                    results["allowed"].append(method)
                    self.logger.debug(f"{method}: {status}")
                else:
                    results["denied"].append(method)

                # Check for TRACE/XST vulnerability
                if method == "TRACE" and status == 200:
                    self.session.add_finding(Finding(
                        source="recon.web_deep",
                        title="TRACE method enabled (XST vulnerability)",
                        severity=SeverityLevel.HIGH,
                        host=url,
                        tags=["http", "trace", "xst", "misconfiguration"],
                        evidence=f"TRACE returned {status}",
                        remediation="Disable TRACE method on the web server.",
                    ))

                self.stealth.sleep(0.3)

            except Exception as e:
                self.logger.debug(f"{method} failed: {e}")

        results["methods"] = results["allowed"] + results["denied"]

        return results

    def directory_enumeration(self, url: str, depth: int = 2) -> List[str]:
        """
        Enumerate directories and files using wordlist.
        """
        self.logger.info(f"Directory enumeration: {url}")

        found = []
        wordlist = None

        for wl in self.wordlists:
            if Path(wl).exists():
                wordlist = wl
                break

        if not wordlist:
            self.logger.warning("No wordlist found for directory enumeration")
            return found

        # Use ffuf if available, else gobuster
        ffuf_available = self._check_tool("ffuf")
        gobuster_available = self._check_tool("gobuster")

        if ffuf_available:
            found = self._ffuf_enum(url, wordlist)
        elif gobuster_available:
            found = self._gobuster_enum(url, wordlist)
        else:
            found = self._simple_enum(url, wordlist)

        # Add findings
        for path in found[:50]:
            self.session.add_finding(Finding(
                source="recon.web_deep",
                title=f"Directory discovered: {path}",
                severity=SeverityLevel.LOW,
                host=url,
                tags=["directory", "enumeration", "web"],
                evidence=path,
            ))

        return found

    def _ffuf_enum(self, url: str, wordlist: str) -> List[str]:
        """Use ffuf for directory enumeration."""
        found = []
        ffuf_json = self.out_dir / f"ffuf_{_safe(url)}.json"

        try:
            cmd = [
                "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
                "-of", "json", "-o", str(ffuf_json),
                "-mc", "200,201,204,301,302,303,307,401,403",
                "-t", "20", "-silent", "-c", "10"
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if ffuf_json.exists():
                data = json.loads(ffuf_json.read_text())
                for result in data.get("results", []):
                    path = result.get("input", {}).get("FUZZ", "")
                    if path:
                        found.append(path)

        except Exception as e:
            self.logger.warning(f"ffuf failed: {e}")

        return found

    def _gobuster_enum(self, url: str, wordlist: str) -> List[str]:
        """Use gobuster for directory enumeration."""
        found = []
        gobuster_out = self.out_dir / f"gobuster_{_safe(url)}.txt"

        try:
            cmd = [
                "gobuster", "dir", "-u", url, "-w", wordlist,
                "-o", str(gobuster_out), "-t", "20",
                "-s", "200,204,301,302,307,401,403"
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if gobuster_out.exists():
                for line in gobuster_out.read_text().splitlines():
                    if "Status:" in line:
                        parts = line.split()
                        if parts:
                            found.append(parts[0])

        except Exception as e:
            self.logger.warning(f"gobuster failed: {e}")

        return found

    def _simple_enum(self, url: str, wordlist: str) -> List[str]:
        """Simple directory enumeration with requests."""
        found = []
        count = 0

        try:
            with open(wordlist, "r") as f:
                for line in f:
                    if count > 500:  # Limit for simple mode
                        break
                    path = line.strip()
                    if not path:
                        continue

                    test_url = f"{url.rstrip('/')}/{path}"
                    status, headers, content = self.stealth.get(test_url, timeout=3)

                    if status in [200, 204, 301, 302, 303, 307, 401, 403]:
                        found.append(path)

                    count += 1
                    self.stealth.sleep(0.2)

        except Exception as e:
            self.logger.warning(f"Simple enum failed: {e}")

        return found

    def parameter_discovery(self, url: str) -> List[Dict[str, str]]:
        """
        Discover parameters using paramspider or arjun.
        """
        self.logger.info(f"Parameter discovery: {url}")

        results = []
        paramspider_available = self._check_tool("paramspider")
        arjun_available = self._check_tool("arjun")

        if paramspider_available:
            results = self._paramspider_discover(url)
        elif arjun_available:
            results = self._arjun_discover(url)

        return results

    def _paramspider_discover(self, url: str) -> List[Dict[str, str]]:
        """Use paramspider for parameter discovery."""
        results = []
        paramspider_out = self.out_dir / f"paramspider_{_safe(url)}.txt"

        try:
            cmd = ["paramspider", "-d", url, "-o", str(paramspider_out), "--quiet"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if paramspider_out.exists():
                for line in paramspider_out.read_text().splitlines():
                    if "?" in line:
                        params = line.split("?")[1].split("&")
                        for p in params:
                            if "=" in p:
                                name = p.split("=")[0]
                                results.append({
                                    "url": line,
                                    "parameter": name,
                                    "source": "paramspider"
                                })

        except Exception as e:
            self.logger.warning(f"paramspider failed: {e}")

        return results

    def _arjun_discover(self, url: str) -> List[Dict[str, str]]:
        """Use arjun for parameter discovery."""
        results = []
        arjun_json = self.out_dir / f"arjun_{_safe(url)}.json"

        try:
            cmd = ["arjun", "-u", url, "-o", str(arjun_json), "--quiet"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if arjun_json.exists():
                data = json.loads(arjun_json.read_text())
                for param in data.get("parameters", []):
                    results.append({
                        "url": url,
                        "parameter": param,
                        "source": "arjun"
                    })

        except Exception as e:
            self.logger.warning(f"arjun failed: {e}")

        return results

    def api_reconnaissance(self, url: str) -> Dict[str, Any]:
        """
        Discover API endpoints (Swagger, GraphQL, REST).
        """
        self.logger.info(f"API reconnaissance: {url}")

        results = {
            "swagger": [],
            "graphql": [],
            "rest_endpoints": [],
            "detected": False
        }

        # Check for Swagger/OpenAPI
        swagger_paths = [
            "/swagger/v1/swagger.json",
            "/swagger-ui.html",
            "/api-docs",
            "/api/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json"
        ]

        for path in swagger_paths:
            try:
                test_url = url.rstrip("/") + path
                status, headers, content = self.stealth.get(test_url, timeout=5)

                if status == 200:
                    results["swagger"].append(path)
                    results["detected"] = True
                    self.logger.finding(f"Swagger endpoint: {path}", severity="info", host=url)
                    self.session.add_finding(Finding(
                        source="recon.web_deep",
                        title=f"Swagger/OpenAPI endpoint: {path}",
                        severity=SeverityLevel.HIGH,
                        host=url,
                        tags=["api", "swagger", "openapi", "exposure"],
                        evidence=test_url,
                        remediation="Restrict access to Swagger documentation in production.",
                    ))
                self.stealth.sleep(0.3)

            except Exception:
                pass

        # Check for GraphQL
        graphql_paths = ["/graphql", "/graphiql", "/gql", "/api/graphql"]

        for path in graphql_paths:
            try:
                test_url = url.rstrip("/") + path
                status, headers, content = self.stealth.post(
                    test_url,
                    b'{"query":"{__typename}"}',
                    timeout=5
                )

                if status == 200 and "__typename" in content:
                    results["graphql"].append(path)
                    results["detected"] = True
                    self.logger.finding(f"GraphQL endpoint: {path}", severity="info", host=url)
                    self.session.add_finding(Finding(
                        source="recon.web_deep",
                        title=f"GraphQL endpoint: {path}",
                        severity=SeverityLevel.MEDIUM,
                        host=url,
                        tags=["api", "graphql", "endpoint"],
                        evidence=test_url,
                        remediation="Disable GraphQL introspection in production.",
                    ))
                self.stealth.sleep(0.3)

            except Exception:
                pass

        return results

    def error_page_analysis(self, url: str) -> Dict[str, Any]:
        """
        Analyze error pages for information disclosure.
        """
        self.logger.info(f"Error page analysis: {url}")

        results = {
            "error_pages": [],
            "information_disclosure": []
        }

        error_paths = [
            "/nonexistent",
            "/does-not-exist",
            "/404",
            "/error",
            "/test-error",
            "/../",
            "/../../",
            "/....//",
        ]

        for path in error_paths:
            try:
                test_url = url.rstrip("/") + path
                status, headers, content = self.stealth.get(test_url, timeout=5)

                if status >= 400:
                    results["error_pages"].append({
                        "path": path,
                        "status": status,
                        "content_length": len(content)
                    })

                    # Check for information disclosure
                    disclosure_patterns = [
                        "stack trace", "exception", "warning", "error on line",
                        "file:", "path:", "line:", "function:", "class:",
                        "mysql", "postgres", "oracle", "mssql",
                        "/etc/", "C:\\", "/home/", "/var/log/",
                        "debug", "dev", "test", "staging"
                    ]

                    for pattern in disclosure_patterns:
                        if pattern in content.lower():
                            results["information_disclosure"].append({
                                "path": path,
                                "pattern": pattern,
                                "evidence": content[:200]
                            })

                            self.session.add_finding(Finding(
                                source="recon.web_deep",
                                title=f"Information disclosure in error page: {pattern}",
                                severity=SeverityLevel.MEDIUM,
                                host=url,
                                tags=["error", "disclosure", "information_leak"],
                                evidence=content[:300],
                                remediation="Implement custom error pages. Disable detailed error messages.",
                            ))

                self.stealth.sleep(0.3)

            except Exception:
                pass

        return results

    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            proc = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full deep web reconnaissance.
        """
        self.logger.banner(f"WEB DEEP RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "http_verbs": {},
            "directories": [],
            "parameters": [],
            "api": {},
            "error_analysis": {}
        }

        for url in urls[:2]:
            # HTTP verb testing
            results["http_verbs"][url] = self.http_verb_testing(url)

            # Directory enumeration (limited)
            if not results["directories"]:
                results["directories"] = self.directory_enumeration(url)

            # Parameter discovery
            if not results["parameters"]:
                results["parameters"] = self.parameter_discovery(target)

            # API reconnaissance
            results["api"] = self.api_reconnaissance(url)

            # Error page analysis
            results["error_analysis"] = self.error_page_analysis(url)

        # Add parameters as findings
        for param in results["parameters"]:
            self.session.add_finding(Finding(
                source="recon.web_deep",
                title=f"Parameter discovered: {param.get('parameter', 'unknown')}",
                severity=SeverityLevel.LOW,
                host=target,
                tags=["parameter", "web", "discovery"],
                evidence=param.get("url", ""),
            ))

        # Save results
        report_path = self.out_dir / f"web_deep_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Web deep recon: {len(results['directories'])} directories, {len(results['parameters'])} parameters")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]