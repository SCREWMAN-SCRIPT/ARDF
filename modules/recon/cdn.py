"""
modules/recon/cdn.py
────────────────────
CDN detection reconnaissance.

Provides:
  - CDN provider identification (Cloudflare, Akamai, CloudFront, Fastly)
  - Edge network detection
  - CDN version fingerprinting
  - Origin IP discovery hints
"""

import re
import socket
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class CDNRecon:
    """
    CDN detection and fingerprinting.
    """

    # Known CDN header patterns
    CDN_HEADERS = {
        "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-visitor", "cf-worker"],
        "akamai": ["x-akamai-transformed", "x-akamai-request-id", "x-akamai-request-id", "akamai"],
        "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "fastly": ["x-served-by", "x-cache", "x-cache-hits", "x-fastly-request-id"],
        "incapsula": ["x-incapsula-cache", "x-incapsula-id", "x-cdn"],
        "cloudways": ["x-cloudways"],
        "keycdn": ["x-keycdn-cache"],
        "bunny": ["x-bunny-cache", "x-bunny-cache-status"],
        "stackpath": ["x-ppe", "x-sp-cache"],
        "azure": ["x-azure-ref", "x-azure-cache"],
        "gcp": ["x-cloud-trace-context"],
    }

    CDN_IP_RANGES = {
        "cloudflare": [
            "104.16.0.0/12", "172.64.0.0/13", "141.101.64.0/18",
            "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
            "198.41.128.0/17"
        ],
        "cloudfront": [
            "13.32.0.0/15", "13.224.0.0/14", "13.248.0.0/14",
            "13.32.0.0/15", "52.84.0.0/15", "54.192.0.0/16",
            "99.84.0.0/16", "108.156.0.0/14", "143.204.0.0/16",
            "144.220.0.0/16", "205.251.192.0/18"
        ],
        "akamai": [
            "2.16.0.0/13", "2.20.0.0/14", "23.0.0.0/12",
            "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/12",
            "23.216.0.0/14", "23.224.0.0/15", "23.226.0.0/16",
            "23.227.0.0/16", "23.228.0.0/17", "23.228.128.0/18",
            "43.224.0.0/13", "43.240.0.0/14", "43.244.0.0/16"
        ],
        "fastly": [
            "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
            "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
            "146.75.0.0/16", "151.101.0.0/16"
        ],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.cdn")
        self.out_dir = session.dir("recon") / "cdn"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_by_headers(self, url: str) -> Dict[str, Any]:
        """
        Detect CDN by analyzing HTTP headers.
        """
        self.logger.info(f"CDN detection by headers: {url}")
        result = {"detected": False, "providers": [], "evidence": {}}

        try:
            status, headers, content = self.stealth.get(url)

            for provider, patterns in CDNRecon.CDN_HEADERS.items():
                for pattern in patterns:
                    if pattern in headers:
                        result["detected"] = True
                        if provider not in result["providers"]:
                            result["providers"].append(provider)
                        result["evidence"][provider] = result["evidence"].get(provider, []) + [f"{pattern}: {headers[pattern][:50]}"]

        except Exception as e:
            self.logger.warning(f"CDN header detection failed: {e}")

        return result

    def detect_by_ip_range(self, target: str) -> Dict[str, Any]:
        """
        Detect CDN by checking if resolved IP is in CDN ranges.
        """
        self.logger.info(f"CDN detection by IP range: {target}")
        result = {"detected": False, "providers": [], "ip": None}

        try:
            ip = socket.gethostbyname(target)
            result["ip"] = ip

            import ipaddress
            ip_obj = ipaddress.ip_address(ip)

            for provider, ranges in CDNRecon.CDN_IP_RANGES.items():
                for cidr in ranges:
                    if ip_obj in ipaddress.ip_network(cidr):
                        result["detected"] = True
                        result["providers"].append(provider)
                        break

        except Exception as e:
            self.logger.warning(f"CDN IP range detection failed: {e}")

        return result

    def detect_by_challenge(self, url: str) -> Dict[str, Any]:
        """
        Detect CDN by challenge page patterns.
        """
        self.logger.info(f"CDN detection by challenge: {url}")
        result = {"detected": False, "providers": [], "challenge_type": None}

        challenge_paths = [
            "/cdn-cgi/challenge-platform",
            "/__cf_challenge",
            "/_incapsula",
        ]

        for path in challenge_paths:
            try:
                test_url = url.rstrip("/") + path
                status, headers, content = self.stealth.get(test_url)

                if status in [403, 503]:
                    if "cloudflare" in content.lower():
                        result["detected"] = True
                        result["providers"].append("cloudflare")
                        result["challenge_type"] = "cloudflare"

                    if "incapsula" in content.lower():
                        result["detected"] = True
                        result["providers"].append("incapsula")
                        result["challenge_type"] = "incapsula"

            except Exception:
                continue

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full CDN detection.
        """
        self.logger.banner(f"CDN RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "detected": False,
            "providers": [],
            "evidence": {},
            "ip": None
        }

        # Try each URL
        for url in urls[:2]:
            try:
                # Header detection
                header_result = self.detect_by_headers(url)
                if header_result["detected"]:
                    results["detected"] = True
                    results["providers"].extend(header_result["providers"])
                    results["evidence"]["headers"] = header_result["evidence"]

                # Challenge detection
                challenge_result = self.detect_by_challenge(url)
                if challenge_result["detected"]:
                    results["detected"] = True
                    results["providers"].extend(challenge_result["providers"])
                    results["evidence"]["challenge"] = challenge_result

            except Exception as e:
                self.logger.warning(f"CDN detection failed for {url}: {e}")

        # IP range detection (always runs)
        ip_result = self.detect_by_ip_range(target)
        results["ip"] = ip_result.get("ip")
        if ip_result["detected"]:
            results["detected"] = True
            results["providers"].extend(ip_result["providers"])
            results["evidence"]["ip_range"] = ip_result

        # Deduplicate providers
        results["providers"] = list(set(results["providers"]))

        # Add findings
        if results["detected"]:
            self.session.add_finding(Finding(
                source="recon.cdn",
                title=f"CDN detected: {', '.join(results['providers'])}",
                severity=SeverityLevel.INFO,
                host=target,
                tags=["cdn", "waf", "detection"],
                evidence=json.dumps(results["evidence"]),
                remediation=f"CDN: {', '.join(results['providers'])}. Consider bypass techniques if needed.",
            ))

        # Save results
        report_path = self.out_dir / f"cdn_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"CDN recon: {'detected' if results['detected'] else 'not detected'} -> {', '.join(results['providers']) if results['providers'] else 'none'}")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]