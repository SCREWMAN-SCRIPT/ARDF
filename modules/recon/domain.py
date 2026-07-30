"""
modules/recon/domain.py
───────────────────────
Domain intelligence reconnaissance.

Provides:
  - WHOIS enumeration (registrant, nameserver, ASN)
  - DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME)
  - Zone transfer attempts (AXFR, IXFR)
  - Wildcard DNS detection
  - Reverse DNS lookups (PTR records)
"""

import re
import json
import socket
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class DomainRecon:
    """
    Domain intelligence reconnaissance.
    Passive and active DNS enumeration.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.domain")
        self.out_dir = session.dir("recon") / "domain"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup on target domain.
        """
        self.logger.info(f"WHOIS lookup: {target}")
        result = {
            "domain": target,
            "registrar": None,
            "registrant": None,
            "nameservers": [],
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "status": [],
            "raw": "",
            "error": None
        }

        try:
            import whois
            w = whois.whois(target)
            result["registrar"] = str(w.registrar) if w.registrar else None
            result["registrant"] = str(w.name) if w.name else None
            result["nameservers"] = w.name_servers if w.name_servers else []
            result["creation_date"] = str(w.creation_date) if w.creation_date else None
            result["expiration_date"] = str(w.expiration_date) if w.expiration_date else None
            result["updated_date"] = str(w.updated_date) if w.updated_date else None
            result["status"] = w.status if w.status else []
            result["raw"] = str(w)

            # Add findings
            if result["nameservers"]:
                self.session.add_finding(Finding(
                    source="recon.domain",
                    title=f"Nameservers discovered for {target}",
                    description=f"NS: {', '.join(result['nameservers'][:5])}",
                    severity=SeverityLevel.INFO,
                    host=target,
                    tags=["dns", "whois", "nameserver"],
                    evidence=json.dumps(result["nameservers"][:5]),
                ))

            if result["registrant"]:
                self.session.add_finding(Finding(
                    source="recon.domain",
                    title=f"Registrant: {result['registrant']}",
                    severity=SeverityLevel.LOW,
                    host=target,
                    tags=["whois", "registrant", "osint"],
                    evidence=result["registrant"],
                ))

            self.logger.success(f"WHOIS done: {len(result['nameservers'])} NS, {result['registrant'] or 'unknown'}")

        except ImportError:
            self.logger.warning("whois module not installed, falling back to system whois")
            result = self._whois_system(target)
        except Exception as e:
            self.logger.warning(f"WHOIS failed: {e}")
            result["error"] = str(e)
            result = self._whois_system(target)

        return result

    def _whois_system(self, target: str) -> Dict[str, Any]:
        """Fallback WHOIS using system command."""
        import subprocess
        result = {
            "domain": target,
            "registrar": None,
            "registrant": None,
            "nameservers": [],
            "raw": "",
            "error": None
        }
        try:
            proc = subprocess.run(["whois", target], capture_output=True, text=True, timeout=10)
            result["raw"] = proc.stdout

            # Extract nameservers
            ns_match = re.findall(r"Name Server:\s*([^\n]+)", proc.stdout, re.I)
            if ns_match:
                result["nameservers"] = [ns.strip() for ns in ns_match]

            # Extract registrar
            reg_match = re.search(r"Registrar:\s*([^\n]+)", proc.stdout, re.I)
            if reg_match:
                result["registrar"] = reg_match.group(1).strip()

            # Extract registrant
            org_match = re.search(r"Registrant Organization:\s*([^\n]+)", proc.stdout, re.I)
            if org_match:
                result["registrant"] = org_match.group(1).strip()

        except Exception as e:
            result["error"] = str(e)

        return result

    def dns_records(self, target: str) -> Dict[str, List[str]]:
        """
        Enumerate DNS records: A, AAAA, MX, TXT, NS, SOA, CNAME.
        """
        self.logger.info(f"DNS records: {target}")
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "SOA": [],
            "CNAME": [],
            "PTR": []
        }

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(target, rtype)
                for answer in answers:
                    records[rtype].append(str(answer))
                self.logger.debug(f"Found {len(records[rtype])} {rtype} records")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.exception.Timeout:
                self.logger.warning(f"DNS {rtype} lookup timeout")
            except Exception as e:
                self.logger.debug(f"DNS {rtype} lookup error: {e}")

        # Add findings for significant records
        if records["MX"]:
            self.session.add_finding(Finding(
                source="recon.domain",
                title=f"MX records for {target}",
                description=f"Mail servers: {', '.join(records['MX'][:5])}",
                severity=SeverityLevel.LOW,
                host=target,
                tags=["dns", "mx", "email"],
                evidence=json.dumps(records["MX"][:5]),
            ))

        if records["TXT"]:
            for txt in records["TXT"]:
                if any(k in txt.lower() for k in ["spf", "dkim", "dmarc"]):
                    self.session.add_finding(Finding(
                        source="recon.domain",
                        title=f"Email security record: {txt[:80]}",
                        severity=SeverityLevel.INFO,
                        host=target,
                        tags=["dns", "txt", "email-security"],
                        evidence=txt[:200],
                    ))

        if records["SOA"]:
            self.session.add_finding(Finding(
                source="recon.domain",
                title=f"SOA record for {target}",
                description=f"Primary NS: {records['SOA'][0][:100]}",
                severity=SeverityLevel.INFO,
                host=target,
                tags=["dns", "soa"],
                evidence=records["SOA"][0][:200],
            ))

        self.logger.success(f"DNS records: A={len(records['A'])}, MX={len(records['MX'])}, NS={len(records['NS'])}")
        return records

    def zone_transfer(self, target: str, ns_server: Optional[str] = None) -> List[str]:
        """
        Attempt AXFR/IXFR zone transfer.
        """
        self.logger.info(f"Zone transfer attempt: {target}")

        zones = []
        ns_servers = []

        if ns_server:
            ns_servers.append(ns_server)
        else:
            # Get NS records
            try:
                answers = dns.resolver.resolve(target, "NS")
                for answer in answers:
                    ns_servers.append(str(answer).rstrip("."))
            except Exception:
                pass

        if not ns_servers:
            self.logger.warning("No NS servers found for zone transfer")
            return zones

        for ns in ns_servers[:5]:
            try:
                self.logger.info(f"Attempting zone transfer from {ns}")
                zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=10))
                for name, node in zone.nodes.items():
                    zones.append(str(name))
                if zones:
                    self.logger.finding(f"Zone transfer SUCCESS from {ns}: {len(zones)} records", severity="critical", host=target)
                    self.session.add_finding(Finding(
                        source="recon.domain",
                        title=f"Zone transfer successful from {ns}",
                        description=f"Retrieved {len(zones)} DNS records from {ns}",
                        severity=SeverityLevel.CRITICAL,
                        host=target,
                        tags=["dns", "zone-transfer", "axfr", "misconfiguration"],
                        evidence=f"NS: {ns}\nRecords: {', '.join(zones[:20])}",
                        remediation="Restrict zone transfers to authorised secondary nameservers only."
                    ))
                    break
            except dns.exception.DNSException as e:
                self.logger.debug(f"Zone transfer failed from {ns}: {e}")
            except Exception as e:
                self.logger.debug(f"Zone transfer error from {ns}: {e}")

        return zones

    def wildcard_detect(self, target: str) -> Dict[str, bool]:
        """
        Detect wildcard DNS entries.
        """
        self.logger.info(f"Wildcard DNS detection: {target}")
        result = {"wildcard_detected": False, "test_subdomains": []}

        test_subdomains = ["test", "random12345", "nonexistent", "aaaaaaaa"]
        responses = {}

        for sub in test_subdomains:
            fqdn = f"{sub}.{target}"
            try:
                answers = dns.resolver.resolve(fqdn, "A")
                responses[fqdn] = [str(a) for a in answers]
            except dns.resolver.NXDOMAIN:
                responses[fqdn] = []
            except Exception:
                responses[fqdn] = []

        # Check if all test subdomains resolve to the same IP
        if responses:
            ips = [set(ips) for ips in responses.values() if ips]
            if ips and len(ips) > 1:
                common_ips = set.intersection(*ips) if len(ips) > 1 else set()
                if common_ips and len(common_ips) < 3:
                    result["wildcard_detected"] = True
                    self.logger.finding(f"Wildcard DNS detected for {target} -> {common_ips}", severity="info", host=target)
                    self.session.add_finding(Finding(
                        source="recon.domain",
                        title=f"Wildcard DNS detected for {target}",
                        description=f"Wildcard resolves to: {', '.join(common_ips)}",
                        severity=SeverityLevel.LOW,
                        host=target,
                        tags=["dns", "wildcard"],
                        evidence=json.dumps(responses),
                        remediation="Consider if wildcard DNS is intended. It may expose internal hosts."
                    ))

        return result

    def reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup (PTR record).
        """
        try:
            ptr = socket.gethostbyaddr(ip)
            self.logger.debug(f"PTR for {ip}: {ptr[0]}")
            return ptr[0]
        except socket.herror:
            return None
        except Exception:
            return None

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full domain reconnaissance.
        """
        self.logger.banner(f"DOMAIN RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "whois": {},
            "dns_records": {},
            "zone_transfer": [],
            "wildcard": {},
        }

        # WHOIS
        results["whois"] = self.whois_lookup(target)

        # DNS records
        results["dns_records"] = self.dns_records(target)

        # Zone transfer
        nameservers = results["dns_records"].get("NS", [])
        for ns in nameservers[:3]:
            zones = self.zone_transfer(target, ns)
            if zones:
                results["zone_transfer"].extend(zones)

        # Wildcard detection
        results["wildcard"] = self.wildcard_detect(target)

        # Reverse DNS for discovered IPs
        ips = results["dns_records"].get("A", []) + results["dns_records"].get("AAAA", [])
        ptr_results = {}
        for ip in ips[:20]:
            ptr = self.reverse_dns(ip)
            if ptr:
                ptr_results[ip] = ptr

        if ptr_results:
            results["ptr_records"] = ptr_results
            self.session.add_finding(Finding(
                source="recon.domain",
                title=f"Reverse DNS: {len(ptr_results)} records",
                severity=SeverityLevel.LOW,
                host=target,
                tags=["dns", "ptr", "reverse"],
                evidence=json.dumps(ptr_results),
            ))

        # Save results
        report_path = self.out_dir / f"domain_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Domain recon completed: {len(results['dns_records'].get('A', []))} A records, {len(results['dns_records'].get('NS', []))} NS")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]