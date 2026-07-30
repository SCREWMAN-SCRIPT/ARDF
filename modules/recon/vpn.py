"""
modules/recon/vpn.py
────────────────────
VPN service reconnaissance.

Provides:
  - VPN Service Detection (OpenVPN, WireGuard, IPSec, PPTP, L2TP)
  - SSL VPN Detection (port 443 custom)
  - Bastion/Jump Host Detection
  - VPN Gateway Identification
"""

import re
import json
import socket
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class VPNRecon:
    """
    VPN service detection and enumeration.
    """

    # VPN port mappings
    VPN_PORTS = {
        "openvpn": [1194],
        "wireguard": [51820, 51821],
        "ipsec": [500, 4500],
        "pptp": [1723],
        "l2tp": [1701],
        "ssl_vpn": [443],  # Custom SSL VPN
        "anyconnect": [443],
        "fortinet": [443],
        "pulse_secure": [443],
        "globalprotect": [443],
    }

    # VPN banner patterns
    VPN_BANNERS = {
        "openvpn": [r"OpenVPN", r"OpenVPN Server", r"OpenVPN v"],
        "wireguard": [r"WireGuard", r"wg-"],
        "ipsec": [r"IPSec", r"ISAKMP", r"IKEv[12]"],
        "pptp": [r"PPTP", r"Point-to-Point Tunneling"],
        "l2tp": [r"L2TP", r"Layer Two Tunneling"],
        "ssl_vpn": [r"SSL VPN", r"Secure Sockets Layer VPN"],
        "anyconnect": [r"Cisco AnyConnect", r"AnyConnect VPN"],
        "fortinet": [r"FortiGate", r"Fortinet VPN"],
        "pulse_secure": [r"Pulse Secure", r"Pulse VPN"],
        "globalprotect": [r"GlobalProtect", r"Palo Alto VPN"],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.vpn")
        self.out_dir = session.dir("recon") / "vpn"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def port_scan_vpn(self, target: str) -> Dict[str, List[int]]:
        """
        Scan for VPN ports.
        """
        self.logger.info(f"VPN port scan: {target}")

        all_ports = []
        for ports in self.VPN_PORTS.values():
            all_ports.extend(ports)
        all_ports = list(set(all_ports))

        results = {vpn: [] for vpn in self.VPN_PORTS.keys()}

        for port in all_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    for vpn, ports in self.VPN_PORTS.items():
                        if port in ports:
                            results[vpn].append(port)
                            self.logger.finding(f"VPN port {port} open -> {vpn}", severity="info", host=target)
                            break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Port {port} scan failed: {e}")

        return results

    def service_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detect VPN service via banner grabbing.
        """
        self.logger.info(f"VPN service detection: {target}:{port}")

        result = {
            "port": port,
            "service": None,
            "banner": None,
            "supported": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.send(b"\n")
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["banner"] = banner

            for vpn, patterns in self.VPN_BANNERS.items():
                for pattern in patterns:
                    if re.search(pattern, banner, re.I):
                        result["service"] = vpn
                        result["supported"] = True
                        break
                if result["service"]:
                    break

            # SSL VPN detection on port 443
            if port == 443 and not result["service"]:
                # Check for VPN-specific paths
                vpn_paths = ["/vpn", "/vpn/index", "/sslvpn", "/ssl-vpn", "/webvpn"]
                for path in vpn_paths:
                    try:
                        test_url = f"https://{target}{path}"
                        status, headers, content = self.stealth.get(test_url, timeout=5)
                        if status == 200:
                            if any(p in content.lower() for p in ["vpn", "ssl vpn", "secure access"]):
                                result["service"] = "ssl_vpn"
                                result["supported"] = True
                                break
                    except Exception:
                        pass

        except Exception as e:
            self.logger.debug(f"VPN service detection failed: {e}")

        return result

    def bastion_detection(self, target: str) -> Dict[str, Any]:
        """
        Detect bastion/jump hosts.
        """
        self.logger.info(f"Bastion detection: {target}")

        result = {
            "detected": False,
            "ports": [],
            "evidence": []
        }

        # Check for SSH on non-standard ports
        ssh_ports = [22, 2222, 22222, 20022, 10022, 2000, 8022, 2022]

        for port in ssh_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result_code = sock.connect_ex((target, port))
                sock.close()

                if result_code == 0:
                    result["ports"].append(port)
                    result["evidence"].append(f"SSH on port {port}")

                    # Try to get SSH banner
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        sock.connect((target, port))
                        data = sock.recv(1024)
                        sock.close()
                        banner = data.decode("utf-8", errors="ignore")
                        if "SSH" in banner:
                            result["detected"] = True
                    except Exception:
                        pass

                self.stealth.sleep(0.3)

            except Exception:
                pass

        if result["detected"]:
            self.logger.finding(f"Potential bastion host: SSH on {', '.join(str(p) for p in result['ports'])}", severity="info", host=target)
            self.session.add_finding(Finding(
                source="recon.vpn",
                title=f"Bastion host detected on {target}",
                description=f"SSH on ports: {', '.join(str(p) for p in result['ports'])}",
                severity=SeverityLevel.MEDIUM,
                host=target,
                tags=["bastion", "jump-host", "ssh"],
                evidence=json.dumps(result["evidence"]),
                remediation="Secure bastion hosts with strong authentication and IP restrictions.",
            ))

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full VPN reconnaissance.
        """
        self.logger.banner(f"VPN RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        results = {
            "target": target,
            "vpn_ports": {},
            "vpn_services": {},
            "bastion": {}
        }

        # Scan VPN ports
        vpn_ports = self.port_scan_vpn(target)
        results["vpn_ports"] = vpn_ports

        # Detect services on open ports
        for vpn, ports in vpn_ports.items():
            for port in ports:
                details = self.service_detection(target, port)
                if details["service"]:
                    results["vpn_services"][f"{vpn}:{port}"] = details

                    self.session.add_finding(Finding(
                        source="recon.vpn",
                        title=f"VPN service: {details['service']} on {target}:{port}",
                        severity=SeverityLevel.INFO,
                        host=target,
                        port=port,
                        tags=["vpn", details["service"]],
                        evidence=details["banner"][:200] if details["banner"] else "Banner not captured",
                    ))

        # Bastion detection
        results["bastion"] = self.bastion_detection(target)

        # Save results
        report_path = self.out_dir / f"vpn_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"VPN recon: {len(results['vpn_services'])} VPN services detected")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]