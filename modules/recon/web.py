"""
modules/recon/web.py
────────────────────
Web intelligence reconnaissance.

Provides:
  - HTTP headers analysis (Server, X-Powered-By, etc.)
  - HTML comments & meta tags
  - JavaScript analysis (URLs, endpoints, API calls)
  - SSL/TLS certificate analysis (crt.sh, SANs, validity)
  - Tech stack identification
  - Favicon hashing
"""

import re
import json
import hashlib
import base64
from urllib.parse import urlparse, urljoin
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class WebRecon:
    """
    Web intelligence reconnaissance.
    Passive and low-impact web analysis.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.web")
        self.out_dir = session.dir("recon") / "web"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def headers_analysis(self, url: str) -> Dict[str, Any]:
        """
        Analyze HTTP headers for fingerprinting.
        """
        self.logger.info(f"Headers analysis: {url}")
        result = {
            "url": url,
            "headers": {},
            "server": None,
            "powered_by": None,
            "frameworks": [],
            "security_headers": {},
            "cookies": [],
            "cors": None,
            "hsts": False,
            "xss_protection": None
        }

        try:
            status, headers, content = self.stealth.get(url)

            result["headers"] = headers
            result["server"] = headers.get("server")
            result["powered_by"] = headers.get("x-powered-by")

            # Security headers
            result["security_headers"] = {
                "strict-transport-security": headers.get("strict-transport-security"),
                "content-security-policy": headers.get("content-security-policy"),
                "x-frame-options": headers.get("x-frame-options"),
                "x-content-type-options": headers.get("x-content-type-options"),
                "x-xss-protection": headers.get("x-xss-protection"),
                "referrer-policy": headers.get("referrer-policy"),
            }
            result["hsts"] = bool(headers.get("strict-transport-security"))

            # Cookies
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                for cookie in set_cookie.split(","):
                    result["cookies"].append(cookie.strip())

            # CORS
            result["cors"] = headers.get("access-control-allow-origin")

            # Framework detection from headers
            if "x-powered-by" in headers:
                result["frameworks"].append(headers["x-powered-by"])

            if "x-aspnet-version" in headers:
                result["frameworks"].append(f"ASP.NET {headers['x-aspnet-version']}")

            if "x-gitlab" in headers:
                result["frameworks"].append("GitLab")

            if "x-nginx" in headers:
                result["frameworks"].append("Nginx")

            # Add findings
            if result["server"]:
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Web server: {result['server']}",
                    severity=SeverityLevel.LOW,
                    host=url,
                    tags=["web", "server", "fingerprint"],
                    evidence=result["server"],
                ))

            if result["frameworks"]:
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Framework detected: {', '.join(result['frameworks'])}",
                    severity=SeverityLevel.INFO,
                    host=url,
                    tags=["web", "framework", "fingerprint"],
                    evidence=json.dumps(result["frameworks"]),
                ))

            # Security header issues
            missing_headers = []
            for header, value in result["security_headers"].items():
                if not value:
                    missing_headers.append(header)

            if missing_headers:
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Missing security headers: {', '.join(missing_headers[:3])}",
                    severity=SeverityLevel.MEDIUM,
                    host=url,
                    tags=["web", "security", "misconfiguration"],
                    evidence=json.dumps(missing_headers),
                    remediation="Implement missing security headers.",
                ))

        except Exception as e:
            self.logger.warning(f"Headers analysis failed: {e}")
            result["error"] = str(e)

        return result

    def html_analysis(self, url: str) -> Dict[str, Any]:
        """
        Analyze HTML content for intelligence.
        """
        self.logger.info(f"HTML analysis: {url}")
        result = {
            "url": url,
            "title": None,
            "meta": {},
            "comments": [],
            "scripts": [],
            "links": [],
            "forms": [],
            "emails": [],
            "social_links": [],
            "tech_indicators": []
        }

        try:
            status, headers, content = self.stealth.get(url)

            if status != 200:
                self.logger.warning(f"HTML analysis failed: status {status}")
                return result

            # Title
            title_match = re.search(r'<title>(.*?)</title>', content, re.I)
            if title_match:
                result["title"] = title_match.group(1).strip()

            # Meta tags
            meta_pattern = r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\'][^>]*>'
            for match in re.finditer(meta_pattern, content, re.I):
                name, value = match.group(1), match.group(2)
                result["meta"][name] = value

            # Alternative meta pattern (content first)
            meta_pattern2 = r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\'][^>]*>'
            for match in re.finditer(meta_pattern2, content, re.I):
                value, name = match.group(1), match.group(2)
                result["meta"][name] = value

            # Comments (may contain sensitive info)
            comment_pattern = r'<!--(.*?)-->'
            for match in re.finditer(comment_pattern, content, re.I):
                comment = match.group(1).strip()
                if comment:
                    result["comments"].append(comment)
                    # Check for sensitive info in comments
                    sensitive_patterns = ["TODO", "FIXME", "KEY", "SECRET", "PASSWORD", "CREDENTIAL", "API"]
                    if any(p in comment.upper() for p in sensitive_patterns):
                        self.session.add_finding(Finding(
                            source="recon.web",
                            title="Sensitive information in HTML comment",
                            severity=SeverityLevel.MEDIUM,
                            host=url,
                            tags=["web", "information_disclosure"],
                            evidence=comment[:200],
                            remediation="Remove sensitive information from HTML comments.",
                        ))

            # Script tags
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            for match in re.finditer(script_pattern, content, re.I):
                result["scripts"].append(match.group(1))

            # Inline scripts for API endpoints
            inline_script_pattern = r'<script[^>]*>(.*?)</script>'
            for match in re.finditer(inline_script_pattern, content, re.I):
                script_content = match.group(1)
                # Look for API endpoints in inline scripts
                api_patterns = [r'["\']/(api|v1|v2|graphql)/[^"\']+["\']']
                for pattern in api_patterns:
                    for api_match in re.finditer(pattern, script_content, re.I):
                        result["tech_indicators"].append({"type": "api_endpoint", "value": api_match.group(0)})

            # Links
            link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
            for match in re.finditer(link_pattern, content, re.I):
                link = match.group(1)
                if link:
                    result["links"].append(link)

            # Forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>'
            for match in re.finditer(form_pattern, content, re.I):
                action, method = match.group(1), match.group(2)
                result["forms"].append({"action": action, "method": method})

            # Email addresses
            email_pattern = r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}'
            for match in re.finditer(email_pattern, content):
                result["emails"].append(match.group())

            # Social links
            social_domains = ["linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com", "github.com"]
            for link in result["links"]:
                for domain in social_domains:
                    if domain in link.lower():
                        result["social_links"].append(link)

            # Tech indicators from meta
            generator = result["meta"].get("generator", "")
            if generator:
                result["tech_indicators"].append({"type": "generator", "value": generator})

            if "wp-content" in content or "wp-includes" in content:
                result["tech_indicators"].append({"type": "cms", "value": "WordPress"})

            if "drupal" in content.lower():
                result["tech_indicators"].append({"type": "cms", "value": "Drupal"})

            if "joomla" in content.lower():
                result["tech_indicators"].append({"type": "cms", "value": "Joomla"})

            # Add findings
            if result["title"]:
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Page title: {result['title']}",
                    severity=SeverityLevel.LOW,
                    host=url,
                    tags=["web", "title"],
                    evidence=result["title"],
                ))

            if result["emails"]:
                for email in set(result["emails"])[:5]:
                    self.session.add_finding(Finding(
                        source="recon.web",
                        title=f"Email found: {email}",
                        severity=SeverityLevel.LOW,
                        host=url,
                        tags=["web", "email", "osint"],
                        evidence=email,
                    ))

            if result["social_links"]:
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Social media links found",
                    severity=SeverityLevel.LOW,
                    host=url,
                    tags=["web", "social", "osint"],
                    evidence=json.dumps(result["social_links"][:5]),
                ))

            # Tech stack
            if result["tech_indicators"]:
                tech_names = [t["value"] for t in result["tech_indicators"]]
                self.session.add_finding(Finding(
                    source="recon.web",
                    title=f"Tech stack: {', '.join(tech_names[:5])}",
                    severity=SeverityLevel.INFO,
                    host=url,
                    tags=["web", "tech", "fingerprint"],
                    evidence=json.dumps(result["tech_indicators"][:5]),
                ))

        except Exception as e:
            self.logger.warning(f"HTML analysis failed: {e}")
            result["error"] = str(e)

        return result

    def ssl_certificate(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate.
        """
        self.logger.info(f"SSL certificate analysis: {host}:{port}")
        result = {
            "host": host,
            "port": port,
            "subject": None,
            "issuer": None,
            "san": [],
            "valid_from": None,
            "valid_to": None,
            "serial": None,
            "fingerprint_sha256": None,
            "fingerprint_sha1": None,
            "certificate_chain": [],
            "error": None
        }

        try:
            import ssl
            import socket
            import datetime

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["san"] = cert.get("subjectAltName", [])
                    result["valid_from"] = cert.get("notBefore")
                    result["valid_to"] = cert.get("notAfter")
                    result["serial"] = cert.get("serialNumber")

                    # Get certificate chain
                    for cert_der in ssock.getpeercert(binary_form=True):
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                            fingerprint = cert_obj.fingerprint(hashlib.sha256())
                            result["fingerprint_sha256"] = fingerprint.hex()
                            result["certificate_chain"].append({
                                "subject": str(cert_obj.subject),
                                "issuer": str(cert_obj.issuer),
                                "serial": str(cert_obj.serial_number),
                            })
                            break
                        except Exception:
                            pass

            # Add findings
            if result["san"]:
                san_domains = [san[1] for san in result["san"] if san[0] == "DNS"]
                if san_domains:
                    self.session.add_finding(Finding(
                        source="recon.web",
                        title=f"SSL SANs: {', '.join(san_domains[:5])}",
                        severity=SeverityLevel.INFO,
                        host=host,
                        tags=["ssl", "tls", "san"],
                        evidence=json.dumps(san_domains[:5]),
                    ))

            # Check certificate expiry
            if result["valid_to"]:
                expiry = datetime.datetime.strptime(result["valid_to"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.now()).days
                if days_left < 30:
                    self.session.add_finding(Finding(
                        source="recon.web",
                        title=f"SSL certificate expires in {days_left} days",
                        severity=SeverityLevel.HIGH if days_left < 7 else SeverityLevel.MEDIUM,
                        host=host,
                        tags=["ssl", "tls", "expiry"],
                        evidence=f"Expires: {result['valid_to']}",
                        remediation="Renew SSL certificate before expiry.",
                    ))

        except Exception as e:
            self.logger.debug(f"SSL certificate analysis failed: {e}")
            result["error"] = str(e)

        return result

    def favicon_hash(self, url: str) -> Optional[str]:
        """
        Calculate favicon hash for Shodan fingerprinting.
        """
        try:
            favicon_urls = [
                url.rstrip("/") + "/favicon.ico",
                url.rstrip("/") + "/favicon.png",
                url.rstrip("/") + "/assets/favicon.ico",
            ]

            for fav_url in favicon_urls:
                try:
                    status, headers, content = self.stealth.get(fav_url)
                    if status == 200 and content:
                        # Calculate MMH3 hash (Shodan compatible)
                        import mmh3
                        hash_value = mmh3.hash(base64.b64encode(content.encode()))
                        return str(hash_value)
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full web intelligence reconnaissance.
        """
        self.logger.banner(f"WEB RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        # Build URLs
        urls = []
        if target.startswith("http"):
            urls.append(target)
            # Try HTTPS if HTTP
            parsed = urlparse(target)
            if parsed.scheme == "http":
                urls.append(target.replace("http://", "https://"))
        else:
            urls.append(f"https://{target}")
            urls.append(f"http://{target}")

        results = {
            "target": target,
            "urls": urls,
            "headers": {},
            "html": {},
            "ssl": {},
            "favicon_hash": None
        }

        for url in urls[:2]:
            try:
                # Headers
                results["headers"][url] = self.headers_analysis(url)

                # HTML
                results["html"][url] = self.html_analysis(url)

                # SSL
                parsed = urlparse(url)
                if parsed.scheme == "https":
                    results["ssl"][parsed.hostname] = self.ssl_certificate(parsed.hostname)

                # Favicon
                if not results["favicon_hash"]:
                    results["favicon_hash"] = self.favicon_hash(url)

            except Exception as e:
                self.logger.warning(f"Web recon failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"web_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Web recon completed: {len(urls)} URLs analyzed")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]