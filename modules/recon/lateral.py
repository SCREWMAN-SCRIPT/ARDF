"""
modules/recon/lateral.py
────────────────────────
Lateral movement reconnaissance.

Provides:
  - Internal Network Mapping (private IP ranges, internal hostnames)
  - Network Topology Discovery (firewall rules, segmentation, DMZ)
  - Trust Relationships Detection (domain trusts, service accounts)
  - Lateral Movement Paths (Kerberos delegation, network shares)
"""

import re
import json
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class LateralRecon:
    """
    Lateral movement reconnaissance.
    """

    # Private IP ranges
    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
    ]

    # Common internal services
    INTERNAL_SERVICES = {
        "domain_controller": [88, 389, 445, 636, 3268, 3269],
        "dns_internal": [53],
        "dhcp": [67, 68],
        "ldap": [389, 636],
        "smb_internal": [139, 445],
        "rpc": [135],
        "netbios": [137, 138, 139],
        "wsus": [8530, 8531],
        "sccm": [80, 443, 2701, 2702],
        "vcenter": [443, 902, 903],
        "esxi": [443],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.lateral")
        self.out_dir = session.dir("recon") / "lateral"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def internal_network_mapping(self, target: str) -> Dict[str, Any]:
        """
        Map internal network structure.
        """
        self.logger.info(f"Internal network mapping: {target}")

        result = {
            "internal_ips": [],
            "internal_hostnames": [],
            "private_ranges_detected": [],
            "network_segments": []
        }

        # Check if target is in private range
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)

            for cidr in self.PRIVATE_RANGES:
                if ip in ipaddress.ip_network(cidr):
                    result["private_ranges_detected"].append(cidr)
                    self.logger.finding(f"Target {target} is in private range {cidr}", severity="info", host=target)
                    break
        except Exception:
            pass

        # Resolve hostname if IP
        try:
            if re.match(r"^[\d.]+$", target):
                hostname = socket.gethostbyaddr(target)[0]
                result["internal_hostnames"].append(hostname)
                self.logger.debug(f"Resolved {target} -> {hostname}")
        except Exception:
            pass

        # Resolve to IP if hostname
        try:
            if not re.match(r"^[\d.]+$", target):
                ip = socket.gethostbyname(target)
                result["internal_ips"].append(ip)
        except Exception:
            pass

        return result

    def trust_discovery(self, target: str) -> Dict[str, Any]:
        """
        Discover trust relationships.
        """
        self.logger.info(f"Trust discovery: {target}")

        result = {
            "domain": None,
            "trusts": [],
            "service_accounts": [],
            "detected": False
        }

        # Check for domain controller indicators
        # Look for Kerberos (port 88), LDAP (389), SMB (445)
        ports_to_check = [88, 389, 445, 636, 3268, 3269]

        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result_code = sock.connect_ex((target, port))
                sock.close()

                if result_code == 0:
                    if port == 88:
                        result["domain"] = "Kerberos detected"
                        result["detected"] = True
                        self.logger.finding(f"Kerberos on {target}:{port} -> potential domain controller", severity="info", host=target)
                    elif port in [389, 636, 3268, 3269]:
                        result["domain"] = "LDAP detected"
                        result["detected"] = True
                        self.logger.finding(f"LDAP on {target}:{port} -> potential domain controller", severity="info", host=target)

                self.stealth.sleep(0.3)

            except Exception:
                pass

        if result["detected"]:
            self.session.add_finding(Finding(
                source="recon.lateral",
                title=f"Domain controller indicators on {target}",
                severity=SeverityLevel.HIGH,
                host=target,
                tags=["lateral", "domain-controller", "active-directory"],
                evidence=json.dumps({"ports": [88, 389, 445], "detected": True}),
                remediation="Secure domain controllers with proper firewall and access controls.",
            ))

        return result

    def lateral_paths(self, target: str) -> List[Dict[str, Any]]:
        """
        Identify lateral movement paths.
        """
        self.logger.info(f"Lateral path identification: {target}")

        results = []

        # Check for common lateral movement services
        # SMB shares
        smb_ports = [139, 445]
        for port in smb_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result_code = sock.connect_ex((target, port))
                sock.close()

                if result_code == 0:
                    results.append({
                        "type": "smb_share",
                        "port": port,
                        "target": target,
                        "lateral_vector": "SMB lateral movement"
                    })
                    self.logger.finding(f"SMB on {target}:{port} -> potential lateral movement vector", severity="info", host=target)

                self.stealth.sleep(0.3)

            except Exception:
                pass

        # SSH (common for Linux lateral movement)
        ssh_ports = [22, 2222]
        for port in ssh_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result_code = sock.connect_ex((target, port))
                sock.close()

                if result_code == 0:
                    results.append({
                        "type": "ssh",
                        "port": port,
                        "target": target,
                        "lateral_vector": "SSH lateral movement"
                    })
                    self.logger.finding(f"SSH on {target}:{port} -> potential lateral movement vector", severity="info", host=target)

                self.stealth.sleep(0.3)

            except Exception:
                pass

        # RDP (Windows lateral movement)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result_code = sock.connect_ex((target, 3389))
            sock.close()

            if result_code == 0:
                results.append({
                    "type": "rdp",
                    "port": 3389,
                    "target": target,
                    "lateral_vector": "RDP lateral movement"
                })
                self.logger.finding(f"RDP on {target}:3389 -> potential lateral movement vector", severity="info", host=target)
        except Exception:
            pass

        return results

    def network_shares(self, target: str) -> List[Dict[str, str]]:
        """
        Discover network shares for lateral movement.
        """
        self.logger.info(f"Network share discovery: {target}")

        results = []

        # Try SMB share listing using smbclient if available
        smbclient_available = self._check_tool("smbclient")

        if smbclient_available:
            try:
                cmd = ["smbclient", "-L", target, "-N"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        if "\\" in line and "\\" not in line.strip()[0]:
                            share = line.strip().split()[0]
                            if share and share not in ["---", "-----"]:
                                results.append({
                                    "share": share,
                                    "target": target,
                                    "type": "smb_share"
                                })
                                self.logger.finding(f"Network share: {share} on {target}", severity="info", host=target)
                                self.session.add_finding(Finding(
                                    source="recon.lateral",
                                    title=f"SMB share: {share} on {target}",
                                    severity=SeverityLevel.MEDIUM,
                                    host=target,
                                    tags=["lateral", "smb", "share"],
                                    evidence=share,
                                    remediation="Restrict SMB share access to authorised users only.",
                                ))

            except Exception as e:
                self.logger.debug(f"smbclient failed: {e}")

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
        Run full lateral movement reconnaissance.
        """
        self.logger.banner(f"LATERAL RECON: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        results = {
            "target": target,
            "internal_network": {},
            "trusts": {},
            "lateral_paths": [],
            "network_shares": []
        }

        # Internal network mapping
        results["internal_network"] = self.internal_network_mapping(target)

        # Trust discovery
        results["trusts"] = self.trust_discovery(target)

        # Lateral paths
        results["lateral_paths"] = self.lateral_paths(target)

        # Network shares
        results["network_shares"] = self.network_shares(target)

        # Add summary findings
        if results["lateral_paths"]:
            self.session.add_finding(Finding(
                source="recon.lateral",
                title=f"Lateral movement vectors: {len(results['lateral_paths'])}",
                severity=SeverityLevel.HIGH,
                host=target,
                tags=["lateral", "movement", "paths"],
                evidence=json.dumps(results["lateral_paths"]),
                remediation="Restrict lateral movement paths. Use network segmentation.",
            ))

        # Save results
        report_path = self.out_dir / f"lateral_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Lateral recon: {len(results['lateral_paths'])} paths, {len(results['network_shares'])} shares")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]