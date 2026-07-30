"""
modules/recon/cloud.py
──────────────────────
Cloud intelligence reconnaissance.

Provides:
  - Cloud provider detection (AWS, Azure, GCP, Alibaba)
  - IP geolocation & ownership
  - ASN & BGP hijacking risks
  - Cloud storage bucket naming patterns
  - Container registry detection
"""

import re
import json
import socket
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class CloudRecon:
    """
    Cloud infrastructure detection and enumeration.
    """

    # Cloud provider IP ranges (simplified)
    CLOUD_IP_RANGES = {
        "aws": [
            "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "16.0.0.0/8",
            "18.0.0.0/8", "35.0.0.0/8", "43.0.0.0/8", "44.0.0.0/8",
            "52.0.0.0/8", "54.0.0.0/8", "56.0.0.0/8", "63.0.0.0/8",
            "65.0.0.0/8", "75.0.0.0/8", "76.0.0.0/8", "94.0.0.0/8",
            "96.0.0.0/8", "99.0.0.0/8", "103.0.0.0/8", "106.0.0.0/8",
            "108.0.0.0/8", "109.0.0.0/8", "111.0.0.0/8", "118.0.0.0/8"
        ],
        "azure": [
            "13.64.0.0/11", "13.104.0.0/14", "13.248.0.0/13",
            "20.0.0.0/8", "23.96.0.0/13", "40.0.0.0/10",
            "51.0.0.0/8", "52.0.0.0/8", "65.52.0.0/14",
            "70.37.0.0/16", "72.14.0.0/16", "75.126.0.0/16",
            "94.245.0.0/16", "104.40.0.0/13", "104.146.0.0/14",
            "104.208.0.0/13", "107.23.0.0/16", "111.221.0.0/16"
        ],
        "gcp": [
            "8.34.208.0/20", "8.35.192.0/20", "8.35.192.0/21",
            "34.0.0.0/8", "35.0.0.0/8", "104.154.0.0/15",
            "104.196.0.0/14", "107.167.160.0/19", "107.178.192.0/18",
            "108.170.192.0/18", "108.59.80.0/20", "130.211.0.0/16",
            "136.144.192.0/18", "146.148.0.0/17", "162.216.148.0/22",
            "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16"
        ],
        "alibaba": [
            "8.129.0.0/16", "8.130.0.0/16", "8.131.0.0/16",
            "8.132.0.0/16", "8.133.0.0/16", "8.134.0.0/16",
            "8.135.0.0/16", "8.136.0.0/16", "8.137.0.0/16",
            "8.138.0.0/16", "8.139.0.0/16", "8.140.0.0/16",
            "8.141.0.0/16", "8.142.0.0/16", "8.143.0.0/16"
        ]
    }

    # Cloud storage bucket patterns
    BUCKET_PATTERNS = {
        "s3": r"s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com|([a-z0-9.-]+)\.s3\.amazonaws\.com",
        "gcs": r"storage\.googleapis\.com|([a-z0-9.-]+)\.storage\.googleapis\.com",
        "azure": r"blob\.core\.windows\.net|([a-z0-9.-]+)\.blob\.core\.windows\.net",
        "digitalocean": r"([a-z0-9.-]+)\.digitaloceanspaces\.com",
        "backblaze": r"([a-z0-9.-]+)\.s3\.backblazeb2\.com",
        "wasabi": r"([a-z0-9.-]+)\.s3\.wasabisys\.com",
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.cloud")
        self.out_dir = session.dir("recon") / "cloud"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_provider(self, target: str) -> Dict[str, Any]:
        """
        Detect cloud provider by IP range or headers.
        """
        self.logger.info(f"Cloud provider detection: {target}")
        result = {
            "detected": False,
            "providers": [],
            "ip": None,
            "evidence": {}
        }

        try:
            ip = socket.gethostbyname(target)
            result["ip"] = ip

            import ipaddress
            ip_obj = ipaddress.ip_address(ip)

            for provider, ranges in CloudRecon.CLOUD_IP_RANGES.items():
                for cidr in ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr):
                            result["detected"] = True
                            result["providers"].append(provider)
                            result["evidence"][provider] = f"IP {ip} in range {cidr}"
                            break
                    except Exception:
                        continue

        except Exception as e:
            self.logger.warning(f"Cloud provider detection failed: {e}")

        return result

    def detect_buckets(self, target: str) -> List[Dict[str, str]]:
        """
        Detect cloud storage buckets from URLs and patterns.
        """
        self.logger.info(f"Cloud bucket detection: {target}")
        results = []

        # Check for bucket patterns in URLs from session findings
        findings = self.session.get_findings(source="recon.passive")
        urls = []

        for f in findings:
            if f.evidence and "http" in f.evidence:
                urls.append(f.evidence)

        # Also check from reconnaissance data
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            try:
                data = json.loads(recon_path.read_text())
                for url in data.get("urls", []):
                    urls.append(url)
            except Exception:
                pass

        for url in set(urls[:50]):
            for provider, pattern in CloudRecon.BUCKET_PATTERNS.items():
                match = re.search(pattern, url, re.I)
                if match:
                    bucket_name = match.group(1) if match.groups() else "unknown"
                    result = {
                        "provider": provider,
                        "bucket": bucket_name,
                        "url": url,
                        "status": "found"
                    }
                    results.append(result)
                    self.session.add_finding(Finding(
                        source="recon.cloud",
                        title=f"Cloud bucket found: {bucket_name} ({provider})",
                        severity=SeverityLevel.INFO,
                        host=target,
                        tags=["cloud", "bucket", provider],
                        evidence=url,
                    ))
                    break

        # Try to guess bucket names from domain
        domain_parts = target.replace(".", "-")
        guess_patterns = [
            f"{domain_parts}.s3.amazonaws.com",
            f"{target}.s3.amazonaws.com",
            f"{target.replace('.', '-')}.s3.amazonaws.com",
            f"{target}-data.s3.amazonaws.com",
            f"{target}-assets.s3.amazonaws.com",
        ]

        for guess in guess_patterns:
            try:
                status, headers, content = self.stealth.get(f"https://{guess}")
                if status != 404:
                    # Bucket exists
                    result = {
                        "provider": "s3",
                        "bucket": guess.split(".")[0],
                        "url": f"https://{guess}",
                        "status": "exists",
                        "accessible": status == 200
                    }
                    results.append(result)
                    self.logger.finding(f"Cloud bucket guess: {guess}", severity="info")
            except Exception:
                pass

        return results

    def detect_container_registry(self, target: str) -> Dict[str, Any]:
        """
        Detect container registries (ECR, GCR, ACR, DockerHub).
        """
        self.logger.info(f"Container registry detection: {target}")
        result = {
            "detected": False,
            "registries": [],
            "evidence": {}
        }

        # Check for registry patterns in URLs
        findings = self.session.get_findings()
        urls = []
        for f in findings:
            if f.evidence and "http" in f.evidence:
                urls.append(f.evidence)

        registry_patterns = {
            "ecr": r"([a-zA-Z0-9-]+)\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com",
            "gcr": r"([a-zA-Z0-9-]+)\.gcr\.io",
            "acr": r"([a-zA-Z0-9-]+)\.azurecr\.io",
            "dockerhub": r"docker\.io|hub\.docker\.com",
        }

        for url in set(urls[:30]):
            for registry, pattern in registry_patterns.items():
                if re.search(pattern, url, re.I):
                    result["detected"] = True
                    result["registries"].append(registry)
                    result["evidence"][registry] = url

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full cloud reconnaissance.
        """
        self.logger.banner(f"CLOUD RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "provider": {},
            "buckets": [],
            "container_registries": {},
        }

        # Detect cloud provider
        results["provider"] = self.detect_provider(target)

        # Detect buckets
        results["buckets"] = self.detect_buckets(target)

        # Detect container registries
        results["container_registries"] = self.detect_container_registry(target)

        # Add findings
        if results["provider"]["detected"]:
            self.session.add_finding(Finding(
                source="recon.cloud",
                title=f"Cloud provider: {', '.join(results['provider']['providers'])}",
                severity=SeverityLevel.INFO,
                host=target,
                tags=["cloud", "provider"],
                evidence=json.dumps(results["provider"]["evidence"]),
            ))

        if results["buckets"]:
            bucket_summary = []
            for b in results["buckets"][:10]:
                bucket_summary.append(f"{b['provider']}:{b['bucket']}")

            self.session.add_finding(Finding(
                source="recon.cloud",
                title=f"Cloud buckets found: {len(results['buckets'])}",
                severity=SeverityLevel.MEDIUM,
                host=target,
                tags=["cloud", "bucket", "storage"],
                evidence=json.dumps(bucket_summary),
                remediation="Review cloud bucket permissions. Ensure no public access.",
            ))

        if results["container_registries"]["detected"]:
            self.session.add_finding(Finding(
                source="recon.cloud",
                title=f"Container registries: {', '.join(results['container_registries']['registries'])}",
                severity=SeverityLevel.LOW,
                host=target,
                tags=["cloud", "container", "registry"],
                evidence=json.dumps(results["container_registries"]["evidence"]),
            ))

        # Save results
        report_path = self.out_dir / f"cloud_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Cloud recon: provider={results['provider']['providers'] if results['provider']['providers'] else 'none'}, buckets={len(results['buckets'])}")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]