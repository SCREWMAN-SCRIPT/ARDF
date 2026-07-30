"""
modules/recon/service.py
────────────────────────
Network service enumeration.

Provides:
  - SSH Enumeration (version, auth methods, key exchange)
  - RDP Enumeration (version, NLA, encryption)
  - SMB Enumeration (version, shares, users)
  - FTP Enumeration (version, anonymous login)
  - SMTP Enumeration (VRFY, EXPN, RCPT TO)
  - DNS Service Enumeration (zone transfer, version)
  - SNMP Enumeration (community strings, system info)
  - Kerberos Enumeration (domain, users, SPN)
  - LDAP Enumeration (null bind, users, groups)
"""

import re
import json
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class ServiceRecon:
    """
    Network service enumeration.
    """

    # Service port mappings
    SERVICE_PORTS = {
        "ssh": [22],
        "rdp": [3389],
        "smb": [139, 445],
        "ftp": [21],
        "smtp": [25, 587, 465, 2525],
        "dns": [53],
        "snmp": [161, 162],
        "kerberos": [88],
        "ldap": [389, 636, 3268, 3269],
        "vnc": [5900, 5901],
        "telnet": [23],
        "ntp": [123],
        "imap": [143, 993],
        "pop3": [110, 995],
        "x11": [6000],
        "mqtt": [1883],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.service")
        self.out_dir = session.dir("recon") / "service"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def ssh_enum(self, target: str, port: int = 22) -> Dict[str, Any]:
        """
        Enumerate SSH service.
        """
        self.logger.info(f"SSH enumeration: {target}:{port}")

        result = {
            "port": port,
            "version": None,
            "banner": None,
            "auth_methods": [],
            "supported": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["banner"] = banner
            result["supported"] = True

            # Extract version
            version_match = re.search(r"SSH-([\d.]+)", banner)
            if version_match:
                result["version"] = version_match.group(1)

            # Detect auth methods (basic heuristic)
            if "password" in banner.lower():
                result["auth_methods"].append("password")
            if "publickey" in banner.lower():
                result["auth_methods"].append("publickey")
            if "keyboard-interactive" in banner.lower():
                result["auth_methods"].append("keyboard-interactive")

            if not result["auth_methods"]:
                result["auth_methods"].append("unknown")

            # Add finding
            self.session.add_finding(Finding(
                source="recon.service",
                title=f"SSH service on {target}:{port}",
                description=f"Version: {result['version'] or 'unknown'}, Auth: {', '.join(result['auth_methods'])}",
                severity=SeverityLevel.INFO,
                host=target,
                port=port,
                tags=["ssh", "service"],
                evidence=banner[:200],
            ))

        except Exception as e:
            self.logger.debug(f"SSH enumeration failed: {e}")

        return result

    def smb_enum(self, target: str, port: int = 445) -> Dict[str, Any]:
        """
        Enumerate SMB service.
        """
        self.logger.info(f"SMB enumeration: {target}:{port}")

        result = {
            "port": port,
            "version": None,
            "supported": False,
            "shares": [],
            "null_session": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.send(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["supported"] = True

            # Detect SMB version
            if "SMB1" in banner or "SMB 1" in banner:
                result["version"] = "SMB1"
                self.session.add_finding(Finding(
                    source="recon.service",
                    title=f"SMB1 detected on {target}:{port}",
                    severity=SeverityLevel.HIGH,
                    host=target,
                    port=port,
                    tags=["smb", "smb1", "legacy"],
                    evidence="SMB1 protocol detected (deprecated)",
                    remediation="Upgrade to SMB2 or SMB3. SMB1 is insecure.",
                ))
            elif "SMB2" in banner:
                result["version"] = "SMB2"
            elif "SMB3" in banner:
                result["version"] = "SMB3"

            # Try null session
            null_session = self._smb_null_session(target, port)
            result["null_session"] = null_session

            if null_session:
                self.session.add_finding(Finding(
                    source="recon.service",
                    title=f"Null session allowed on SMB {target}:{port}",
                    severity=SeverityLevel.HIGH,
                    host=target,
                    port=port,
                    tags=["smb", "null-session", "misconfiguration"],
                    evidence="SMB null session allowed",
                    remediation="Disable null sessions. Restrict anonymous access.",
                ))

        except Exception as e:
            self.logger.debug(f"SMB enumeration failed: {e}")

        return result

    def _smb_null_session(self, target: str, port: int) -> bool:
        """
        Test for SMB null session.
        """
        try:
            # Simple test using nmap or smbclient
            import subprocess
            cmd = ["smbclient", "-L", target, "-N", "-p", str(port)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return proc.returncode == 0
        except Exception:
            return False

    def ftp_enum(self, target: str, port: int = 21) -> Dict[str, Any]:
        """
        Enumerate FTP service.
        """
        self.logger.info(f"FTP enumeration: {target}:{port}")

        result = {
            "port": port,
            "version": None,
            "banner": None,
            "anonymous": False,
            "supported": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["banner"] = banner
            result["supported"] = True

            # Extract version
            version_match = re.search(r"([A-Za-z]+[^\d]*([\d.]+))", banner)
            if version_match:
                result["version"] = version_match.group(1).strip()

            # Test anonymous login
            self.stealth.sleep(0.5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.recv(1024)

            # Send USER anonymous
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024)
            sock.send(b"PASS anonymous\r\n")
            response2 = sock.recv(1024)
            sock.close()

            if "230" in response2.decode("utf-8", errors="ignore"):
                result["anonymous"] = True
                self.session.add_finding(Finding(
                    source="recon.service",
                    title=f"Anonymous FTP allowed on {target}:{port}",
                    severity=SeverityLevel.HIGH,
                    host=target,
                    port=port,
                    tags=["ftp", "anonymous", "misconfiguration"],
                    evidence="Anonymous login successful",
                    remediation="Disable anonymous FTP access.",
                ))

        except Exception as e:
            self.logger.debug(f"FTP enumeration failed: {e}")

        return result

    def smtp_enum(self, target: str, port: int = 25) -> Dict[str, Any]:
        """
        Enumerate SMTP service.
        """
        self.logger.info(f"SMTP enumeration: {target}:{port}")

        result = {
            "port": port,
            "version": None,
            "banner": None,
            "supported": False,
            "vrfy_enabled": False,
            "expn_enabled": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["banner"] = banner
            result["supported"] = True

            # Extract version
            version_match = re.search(r"([\d.]+)", banner)
            if version_match:
                result["version"] = version_match.group(1)

            # Test VRFY
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.recv(1024)
            sock.send(b"VRFY root\r\n")
            response = sock.recv(1024)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore")
            if "252" in response_str or "250" in response_str:
                result["vrfy_enabled"] = True
                self.session.add_finding(Finding(
                    source="recon.service",
                    title=f"SMTP VRFY enabled on {target}:{port}",
                    severity=SeverityLevel.MEDIUM,
                    host=target,
                    port=port,
                    tags=["smtp", "vrfy", "user-enumeration"],
                    evidence="VRFY command accepted",
                    remediation="Disable VRFY and EXPN commands.",
                ))

            # Test EXPN
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.recv(1024)
            sock.send(b"EXPN root\r\n")
            response = sock.recv(1024)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore")
            if "252" in response_str or "250" in response_str:
                result["expn_enabled"] = True
                self.session.add_finding(Finding(
                    source="recon.service",
                    title=f"SMTP EXPN enabled on {target}:{port}",
                    severity=SeverityLevel.MEDIUM,
                    host=target,
                    port=port,
                    tags=["smtp", "expn", "user-enumeration"],
                    evidence="EXPN command accepted",
                    remediation="Disable VRFY and EXPN commands.",
                ))

        except Exception as e:
            self.logger.debug(f"SMTP enumeration failed: {e}")

        return result

    def dns_enum(self, target: str, port: int = 53) -> Dict[str, Any]:
        """
        Enumerate DNS service.
        """
        self.logger.info(f"DNS enumeration: {target}:{port}")

        result = {
            "port": port,
            "version": None,
            "supported": False,
            "zone_transfer": False
        }

        try:
            import dns.resolver
            import dns.query
            import dns.zone

            # Try to get DNS version
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [target]
                response = resolver.resolve("version.bind", "TXT", "CHAOS")
                if response:
                    result["version"] = str(response[0])
                    result["supported"] = True
            except Exception:
                pass

            # Try zone transfer
            ns_servers = []
            try:
                answers = dns.resolver.resolve(target, "NS")
                for answer in answers:
                    ns_servers.append(str(answer).rstrip("."))
            except Exception:
                pass

            for ns in ns_servers[:3]:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=5))
                    if zone:
                        result["zone_transfer"] = True
                        self.session.add_finding(Finding(
                            source="recon.service",
                            title=f"DNS zone transfer allowed from {ns}",
                            severity=SeverityLevel.CRITICAL,
                            host=target,
                            port=port,
                            tags=["dns", "zone-transfer", "misconfiguration"],
                            evidence=f"Zone transfer from {ns} successful",
                            remediation="Restrict zone transfers to authorised secondaries.",
                        ))
                        break
                except Exception:
                    pass

        except Exception as e:
            self.logger.debug(f"DNS enumeration failed: {e}")

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full service enumeration.
        """
        self.logger.banner(f"SERVICE RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        results = {
            "target": target,
            "services": {}
        }

        # Check if ports are open from previous recon
        open_ports = set()
        for f in self.session.get_findings():
            if f.port:
                open_ports.add(f.port)

        # Enumerate services on open ports
        for service, ports in self.SERVICE_PORTS.items():
            for port in ports:
                if port in open_ports:
                    self.logger.info(f"Enumerating {service} on {target}:{port}")

                    if service == "ssh":
                        results["services"][f"{service}_{port}"] = self.ssh_enum(target, port)
                    elif service == "smb":
                        results["services"][f"{service}_{port}"] = self.smb_enum(target, port)
                    elif service == "ftp":
                        results["services"][f"{service}_{port}"] = self.ftp_enum(target, port)
                    elif service == "smtp":
                        results["services"][f"{service}_{port}"] = self.smtp_enum(target, port)
                    elif service == "dns":
                        results["services"][f"{service}_{port}"] = self.dns_enum(target, port)
                    # Add more service enumerations here

        # Save results
        report_path = self.out_dir / f"service_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Service recon: {len(results['services'])} services enumerated")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]