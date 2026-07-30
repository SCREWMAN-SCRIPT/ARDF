"""
modules/recon/network.py
────────────────────────
Network reconnaissance.

Provides:
  - Host Discovery (ICMP, TCP SYN, ARP)
  - Port Scanning (TCP SYN, FIN/ACK/NULL, UDP)
  - Service Version Detection (banner grabbing, nmap -sV)
  - OS Fingerprinting (nmap -O)
  - Firewall & IDS/IPS Detection
"""

import re
import json
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class NetworkRecon:
    """
    Network reconnaissance with stealth-aware scanning.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.network")
        self.out_dir = session.dir("recon") / "network"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def host_discovery(self, target: str) -> List[str]:
        """
        Discover live hosts using ICMP and TCP SYN.
        """
        self.logger.info(f"Host discovery: {target}")

        hosts = set()

        # Check if target is a single IP or CIDR
        import ipaddress
        try:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(network.network_address), str(network.broadcast_address)]
            is_network = True
        except ValueError:
            targets = [target]
            is_network = False

        # ICMP ping
        if self._check_tool("ping"):
            for t in targets[:2]:
                try:
                    cmd = ["ping", "-c", "1", "-W", "1", t]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if proc.returncode == 0:
                        hosts.add(t)
                        self.logger.debug(f"Host {t} responds to ICMP")
                except Exception:
                    pass
                self.stealth.sleep(0.5)

        # TCP SYN ping using nmap if available
        if self._check_tool("nmap"):
            nmap_out = self.out_dir / f"nmap_host_discovery_{_safe(target)}.xml"
            try:
                cmd = ["nmap", "-sn", "-oX", str(nmap_out), target]
                subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if nmap_out.exists():
                    import xml.etree.ElementTree as ET
                    for host in ET.parse(nmap_out).getroot().findall("host"):
                        addr = host.find("address")
                        if addr is not None:
                            ip = addr.get("addr")
                            if ip:
                                hosts.add(ip)
            except Exception as e:
                self.logger.warning(f"Nmap host discovery failed: {e}")

        self.logger.success(f"Host discovery: {len(hosts)} hosts found")
        return list(hosts)

    def port_scan(self, target: str, ports: str = "top1000") -> List[Dict]:
        """
        Perform port scan using nmap with stealth options.
        """
        self.logger.info(f"Port scan: {target} ({ports})")

        results = []

        if not self._check_tool("nmap"):
            self.logger.warning("nmap not available for port scanning")
            return results

        nmap_xml = self.out_dir / f"nmap_scan_{_safe(target)}.xml"

        # Build nmap command with stealth
        cmd = ["nmap", "-sV", "-sC", "-T2"]

        if ports == "top1000":
            cmd.append("--top-ports")
            cmd.append("1000")
        elif ports == "top100":
            cmd.append("--top-ports")
            cmd.append("100")
        elif ports != "all":
            cmd.append("-p")
            cmd.append(ports)

        cmd.extend(["-oX", str(nmap_xml), target])

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            if nmap_xml.exists():
                import xml.etree.ElementTree as ET
                for host in ET.parse(nmap_xml).getroot().findall("host"):
                    ip = host.find("address").get("addr") if host.find("address") is not None else target

                    for port in host.findall(".//port"):
                        port_id = int(port.get("portid", 0))
                        protocol = port.get("protocol", "tcp")
                        state = port.find("state")
                        service = port.find("service")

                        if state is None or state.get("state") != "open":
                            continue

                        service_name = service.get("name", "") if service is not None else ""
                        product = service.get("product", "") if service is not None else ""
                        version = service.get("version", "") if service is not None else ""

                        results.append({
                            "ip": ip,
                            "port": port_id,
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version
                        })

        except subprocess.TimeoutExpired:
            self.logger.warning("Port scan timeout")
        except Exception as e:
            self.logger.warning(f"Port scan failed: {e}")

        # Add findings
        for r in results:
            severity = SeverityLevel.INFO
            if r["port"] in [22, 23, 21, 445, 3389, 3306, 5432, 1433, 27017]:
                severity = SeverityLevel.MEDIUM

            self.session.add_finding(Finding(
                source="recon.network",
                title=f"Port {r['port']}/{r['protocol']} open ({r['service']})",
                description=f"product={r['product']} version={r['version']}" if r['product'] else "",
                severity=severity,
                host=r["ip"],
                port=r["port"],
                tags=["port", "network", r["service"] if r["service"] else "unknown"],
                evidence=f"Service: {r['service']}" if r['service'] else "",
            ))

        self.logger.success(f"Port scan: {len(results)} open ports found")
        return results

    def service_version_detection(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """
        Detailed service version detection for specific ports.
        """
        self.logger.info(f"Service version detection: {target} on {len(ports)} ports")

        results = {}

        if not ports or not self._check_tool("nmap"):
            return results

        port_str = ",".join(str(p) for p in ports[:20])
        nmap_xml = self.out_dir / f"nmap_versions_{_safe(target)}.xml"

        try:
            cmd = ["nmap", "-sV", "--version-intensity", "7", "-p", port_str, "-oX", str(nmap_xml), target]
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if nmap_xml.exists():
                import xml.etree.ElementTree as ET
                for host in ET.parse(nmap_xml).getroot().findall("host"):
                    ip = host.find("address").get("addr") if host.find("address") is not None else target

                    for port in host.findall(".//port"):
                        port_id = int(port.get("portid", 0))
                        service = port.find("service")

                        if service is not None:
                            results[port_id] = {
                                "service": service.get("name", ""),
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                                "extra": service.get("extrainfo", "")
                            }

        except Exception as e:
            self.logger.warning(f"Service version detection failed: {e}")

        return results

    def os_fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Detect operating system using nmap -O.
        """
        self.logger.info(f"OS fingerprint: {target}")

        result = {"guesses": [], "detected": False}

        if not self._check_tool("nmap"):
            return result

        nmap_xml = self.out_dir / f"nmap_os_{_safe(target)}.xml"

        try:
            cmd = ["nmap", "-O", "-oX", str(nmap_xml), target]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if nmap_xml.exists():
                import xml.etree.ElementTree as ET
                for os in ET.parse(nmap_xml).getroot().findall(".//osclass"):
                    os_name = os.get("osfamily", "")
                    os_gen = os.get("osgen", "")
                    vendor = os.get("vendor", "")

                    if os_name:
                        result["guesses"].append({
                            "family": os_name,
                            "generation": os_gen,
                            "vendor": vendor,
                            "accuracy": os.get("accuracy", "0")
                        })
                        result["detected"] = True

        except Exception as e:
            self.logger.warning(f"OS fingerprint failed: {e}")

        if result["detected"]:
            self.session.add_finding(Finding(
                source="recon.network",
                title=f"OS detected: {result['guesses'][0]['family']} {result['guesses'][0]['generation']}",
                severity=SeverityLevel.INFO,
                host=target,
                tags=["os", "fingerprint", "nmap"],
                evidence=json.dumps(result["guesses"][:3]),
            ))

        return result

    def firewall_detection(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """
        Detect firewall/IDS/IPS presence.
        """
        self.logger.info(f"Firewall detection: {target}")

        result = {
            "firewall_detected": False,
            "filtered_ports": [],
            "open_ports": [],
            "closed_ports": []
        }

        if not self._check_tool("nmap"):
            return result

        # Use nmap to detect filtered ports
        port_str = ",".join(str(p) for p in ports[:20])
        nmap_xml = self.out_dir / f"nmap_firewall_{_safe(target)}.xml"

        try:
            cmd = ["nmap", "-sS", "-p", port_str, "-oX", str(nmap_xml), target]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if nmap_xml.exists():
                import xml.etree.ElementTree as ET
                for host in ET.parse(nmap_xml).getroot().findall("host"):
                    for port in host.findall(".//port"):
                        port_id = int(port.get("portid", 0))
                        state = port.find("state")

                        if state is not None:
                            state_val = state.get("state", "")
                            if state_val == "filtered":
                                result["filtered_ports"].append(port_id)
                            elif state_val == "open":
                                result["open_ports"].append(port_id)
                            elif state_val == "closed":
                                result["closed_ports"].append(port_id)

            result["firewall_detected"] = len(result["filtered_ports"]) > 5

            if result["firewall_detected"]:
                self.session.add_finding(Finding(
                    source="recon.network",
                    title=f"Firewall/IDS detected on {target}",
                    description=f"{len(result['filtered_ports'])} filtered ports detected",
                    severity=SeverityLevel.LOW,
                    host=target,
                    tags=["firewall", "ids", "filtered"],
                    evidence=json.dumps(result["filtered_ports"][:20]),
                ))

        except Exception as e:
            self.logger.warning(f"Firewall detection failed: {e}")

        return result

    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            proc = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full network reconnaissance.
        """
        self.logger.banner(f"NETWORK RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        results = {
            "target": target,
            "hosts": [],
            "ports": [],
            "os": {},
            "firewall": {}
        }

        # Host discovery
        hosts = self.host_discovery(target)
        results["hosts"] = hosts

        # Port scan
        ports = self.port_scan(target)
        results["ports"] = ports

        # Service version detection on open ports
        if ports:
            open_ports = [p["port"] for p in ports if p["service"]]
            if open_ports:
                results["service_versions"] = self.service_version_detection(target, open_ports)

        # OS fingerprint
        results["os"] = self.os_fingerprint(target)

        # Firewall detection
        if ports:
            all_ports = [p["port"] for p in ports[:20]]
            results["firewall"] = self.firewall_detection(target, all_ports)

        # Save results
        report_path = self.out_dir / f"network_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Network recon: {len(results['hosts'])} hosts, {len(results['ports'])} open ports")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]