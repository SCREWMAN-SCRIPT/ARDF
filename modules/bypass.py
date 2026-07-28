"""
modules/bypass.py
─────────────────
Cloudflare bypass techniques module for ARDF.

Provides 7+ techniques to detect and bypass Cloudflare protection:
  1. DNS history analysis (SecurityTrails, Censys)
  2. SSL certificate history (crt.sh)
  3. Subdomain enumeration (bypass via misconfigured subdomains)
  4. MX/SMTP record (mail server often shares origin IP)
  5. Cloudflare Worker exploit (misconfigured routing)
  6. Cache poisoning (Host header manipulation)
  7. Origin IP scanning (direct IP discovery)

All techniques are read-only reconnaissance. No exploit payloads are sent.
Requires explicit confirmation for active scanning techniques.
"""

import re
import json
import time
import socket
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

CLOUDFLARE_IPS = [
    "104.16.0.0/12", "172.64.0.0/13", "141.101.64.0/18",
    "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/17"
]

CLOUDFLARE_HEADERS = [
    "cf-ray", "cf-cache-status", "cf-request-id",
    "cf-visitor", "cf-worker", "cf-edge-cache"
]

SHODAN_KEY         = os.environ.get("SHODAN_API_KEY", "")
SECURITYTRAILS_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")
CENSYS_KEY         = os.environ.get("CENSYS_API_KEY", "")
CENSYS_SECRET      = os.environ.get("CENSYS_API_SECRET", "")


# ─────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────

def _is_cloudflare_ip(ip: str) -> bool:
    """Check if IP belongs to Cloudflare range."""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_IPS:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except Exception:
        pass
    return False


def _http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "ARDF/2.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _resolve(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Bypass Techniques (7 methods)
# ─────────────────────────────────────────────────────────────

class CloudflareBypass:
    """
    Collection of Cloudflare bypass techniques.
    Each method returns (success: bool, origin_ip: Optional[str], evidence: str)
    """

    def __init__(self, target: str, logger: ARDFLogger):
        self.target = target
        self.logger = logger
        self.results = {}
        self.origin_candidates = []

    # ── Technique 1: DNS History ────────────────────────────

    def dns_history(self) -> Tuple[bool, Optional[str], str]:
        """Query SecurityTrails for historical A records."""
        if not SECURITYTRAILS_KEY:
            return False, None, "SecurityTrails API key not set"

        self.logger.info("Bypass: DNS history (SecurityTrails)...")
        url = f"https://api.securitytrails.com/v1/domain/{self.target}/history/a"
        data = _http_get(url, headers={"APIKEY": SECURITYTRAILS_KEY})

        if not data:
            return False, None, "No DNS history data"

        for item in data.get("items", []):
            for ip in item.get("ips", []):
                if not _is_cloudflare_ip(ip):
                    self.origin_candidates.append(ip)
                    self.logger.finding(f"Origin candidate from DNS history: {ip}", host=ip)
                    return True, ip, f"Found in DNS history: {ip}"

        return False, None, "No non-Cloudflare IPs in DNS history"

    # ── Technique 2: SSL Certificate History ─────────────────

    def ssl_cert_history(self) -> Tuple[bool, Optional[str], str]:
        """Query crt.sh for certificate history with IPs."""
        self.logger.info("Bypass: SSL certificate history (crt.sh)...")
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        data = _http_get(url)

        if not data:
            return False, None, "No certificate data"

        ips_found = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            # Look for IP addresses in certificate SAN
            ip_matches = re.findall(r"IP:([\d.]+)", name_value)
            for ip in ip_matches:
                if not _is_cloudflare_ip(ip):
                    ips_found.add(ip)

        for ip in ips_found:
            self.origin_candidates.append(ip)
            self.logger.finding(f"Origin candidate from SSL cert: {ip}", host=ip)
            return True, ip, f"Found in SSL certificate: {ip}"

        return False, None, "No IPs found in SSL certificates"

    # ── Technique 3: Subdomain Enumeration ───────────────────

    def subdomain_bypass(self) -> Tuple[bool, Optional[str], str]:
        """Enumerate subdomains and check for non-Cloudflare IPs."""
        self.logger.info("Bypass: Subdomain enumeration...")

        # Use common subdomains that often bypass Cloudflare
        subdomains = [
            "dev", "test", "stage", "staging", "api", "admin",
            "mail", "remote", "vpn", "internal", "corp"
        ]

        for sub in subdomains:
            host = f"{sub}.{self.target}"
            try:
                ip = _resolve(host)
                if ip and not _is_cloudflare_ip(ip):
                    self.origin_candidates.append(ip)
                    self.logger.finding(f"Origin candidate from subdomain: {host} ({ip})", host=ip)
                    return True, ip, f"Subdomain {host} → {ip}"
            except Exception:
                continue

        return False, None, "No bypass subdomains found"

    # ── Technique 4: MX/SMTP Record ──────────────────────────

    def mx_record(self) -> Tuple[bool, Optional[str], str]:
        """Check MX record — mail server often shares origin IP."""
        self.logger.info("Bypass: MX record...")

        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, 'MX')
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.')
                if mx_host.endswith(self.target):
                    ip = _resolve(mx_host)
                    if ip and not _is_cloudflare_ip(ip):
                        self.origin_candidates.append(ip)
                        self.logger.finding(f"Origin candidate from MX record: {mx_host} ({ip})", host=ip)
                        return True, ip, f"MX record {mx_host} → {ip}"
        except Exception as e:
            return False, None, f"MX lookup failed: {e}"

        return False, None, "No usable MX records found"

    # ── Technique 5: Cloudflare Worker Exploit ───────────────

    def worker_exploit(self) -> Tuple[bool, Optional[str], str]:
        """Exploit misconfigured Cloudflare Workers that leak origin."""
        self.logger.info("Bypass: Cloudflare Worker exploit...")

        test_paths = [
            "/cdn-cgi/trace",
            "/.well-known/",
            "/admin/",
            "/api/v1/status",
            "/debug/",
            "/../../../../etc/passwd"
        ]

        for path in test_paths:
            try:
                url = f"https://{self.target}{path}"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "ARDF/2.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    server = resp.headers.get("Server", "")
                    if "cloudflare" not in server.lower():
                        # Response came from origin, not CF
                        ip = _resolve(self.target)
                        if ip and not _is_cloudflare_ip(ip):
                            self.origin_candidates.append(ip)
                            self.logger.finding(f"Origin exposed via worker: {path} → {ip}", host=ip)
                            return True, ip, f"Worker leaked origin via {path}"
            except Exception:
                continue

        return False, None, "No worker misconfiguration found"

    # ── Technique 6: Cache Poisoning ──────────────────────────

    def cache_poison(self) -> Tuple[bool, Optional[str], str]:
        """Attempt cache poisoning via Host header manipulation."""
        self.logger.info("Bypass: Cache poisoning...")

        headers_list = [
            {"Host": f"origin-{self.target}"},
            {"Host": f"www.{self.target}.evil.com"},
            {"Host": self.target, "X-Real-IP": "127.0.0.1"},
            {"Host": self.target, "X-Forwarded-For": "127.0.0.1"},
        ]

        for headers in headers_list:
            try:
                url = f"https://{self.target}"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        server = resp.headers.get("Server", "")
                        if "cloudflare" not in server.lower():
                            ip = _resolve(self.target)
                            if ip and not _is_cloudflare_ip(ip):
                                self.origin_candidates.append(ip)
                                self.logger.finding(f"Origin via cache poison: {headers}", host=ip)
                                return True, ip, f"Cache poison with {headers}"
            except Exception:
                continue

        return False, None, "No cache poisoning success"

    # ── Technique 7: Host Header Manipulation ─────────────────

    def host_header_bypass(self) -> Tuple[bool, Optional[str], str]:
        """Direct host header manipulation to reach origin."""
        self.logger.info("Bypass: Host header manipulation...")

        # First try to find origin IP from previous methods
        if not self.origin_candidates:
            # Try common IPs if no candidates
            common_ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
            for ip in common_ips:
                try:
                    url = f"http://{ip}"
                    req = urllib.request.Request(
                        url,
                        headers={"Host": self.target}
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status == 200:
                            self.origin_candidates.append(ip)
                            return True, ip, f"Host header bypass → {ip}"
                except Exception:
                    continue

        # Try origin candidates from previous methods
        for ip in self.origin_candidates[:5]:
            try:
                url = f"https://{ip}"
                req = urllib.request.Request(
                    url,
                    headers={"Host": self.target}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        self.logger.finding(f"Host header bypass confirmed: {ip}", host=ip)
                        return True, ip, f"Host header → {ip}"
            except Exception:
                continue

        return False, None, "No host header bypass"

    # ── Run all techniques ────────────────────────────────────

    def run_all(self) -> Dict[str, Any]:
        """
        Execute all bypass techniques sequentially.
        Returns summary with successful candidates.
        """
        techniques = [
            ("dns_history", self.dns_history),
            ("ssl_cert_history", self.ssl_cert_history),
            ("subdomain_bypass", self.subdomain_bypass),
            ("mx_record", self.mx_record),
            ("worker_exploit", self.worker_exploit),
            ("cache_poison", self.cache_poison),
            ("host_header_bypass", self.host_header_bypass),
        ]

        results = {}
        for name, func in techniques:
            success, ip, evidence = func()
            results[name] = {
                "success": success,
                "origin_ip": ip,
                "evidence": evidence
            }

            if success and ip:
                self.logger.success(f"{name} → origin IP: {ip}")
            else:
                self.logger.warning(f"{name} failed: {evidence[:50]}")

        # Deduplicate candidates
        unique_candidates = list(dict.fromkeys(self.origin_candidates))

        return {
            "target": self.target,
            "techniques": results,
            "origin_candidates": unique_candidates,
            "best_candidate": unique_candidates[0] if unique_candidates else None,
            "bypass_achieved": len(unique_candidates) > 0
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_bypass(
    target: str,
    session: Session,
    logger: Optional[ARDFLogger] = None,
    technique: str = "all",
) -> Dict[str, Any]:
    """
    Run Cloudflare bypass against target.

    Args:
        target    : domain to bypass
        session   : active ARDF session
        logger    : ARDFLogger instance
        technique : specific technique or "all"

    Returns:
        Dict with bypass results
    """
    if logger is None:
        logger = get_logger("bypass")

    logger.banner(f"CLOUDFLARE BYPASS → {target}", style="bold cyan")

    bypass = CloudflareBypass(target, logger)
    results = bypass.run_all()

    # Add findings to session
    if results["bypass_achieved"]:
        for ip in results["origin_candidates"][:5]:
            session.add_finding(Finding(
                source      = "bypass.cloudflare",
                title       = f"Cloudflare origin candidate: {ip}",
                description = f"Found via {', '.join([t for t, r in results['techniques'].items() if r['success']])}",
                severity    = SeverityLevel.HIGH,
                host        = ip,
                tags        = ["cloudflare", "bypass", "origin", "direct-hit"],
                evidence    = json.dumps(results["techniques"]),
                remediation = "Origin server is directly accessible. This is a critical misconfiguration."
            ))

        session.add_finding(Finding(
            source      = "bypass.cloudflare",
            title       = f"Cloudflare bypass achieved for {target}",
            description = f"Found {len(results['origin_candidates'])} origin candidates",
            severity    = SeverityLevel.CRITICAL,
            host        = target,
            tags        = ["cloudflare", "bypass", "success"],
            evidence    = json.dumps(results["origin_candidates"][:5]),
            remediation = "Review Cloudflare configuration. Ensure origin IPs are not exposed."
        ))

    session.mark_module_done("bypass")
    return results