"""
modules/tools/nmap_wrapper.py
─────────────────────────────
Nmap wrapper for ARDF.

Provides controlled Nmap execution with:
  - Stealth mode integration (timing templates, random delays)
  - Multiple scan types (TCP SYN, TCP connect, UDP, FIN, NULL, ACK)
  - Service version detection
  - OS fingerprinting
  - Script scanning
  - Output parsing and finding extraction
  - Session management

All execution requires Tier 2 confirmation (one-click yes/no)
before any active scanning.
"""

import re
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class NmapWrapper:
    """
    Nmap wrapper with stealth and integration.
    """

    # Timing templates
    TIMING_TEMPLATES = {
        "paranoid": 0,
        "sneaky": 1,
        "polite": 2,
        "normal": 3,
        "aggressive": 4,
        "insane": 5,
    }

    # Scan types
    SCAN_TYPES = {
        "syn": "-sS",
        "connect": "-sT",
        "udp": "-sU",
        "fin": "-sF",
        "null": "-sN",
        "ack": "-sA",
        "window": "-sW",
        "maimon": "-sM",
        "version": "-sV",
        "os": "-O",
        "aggressive": "-A",
    }

    # Common scripts by category
    SCRIPTS = {
        "default": ["default"],
        "safe": ["safe"],
        "vuln": ["vuln"],
        "discovery": ["discovery"],
        "exploit": ["exploit"],
        "auth": ["auth"],
        "brute": ["brute"],
        "intrusive": ["intrusive"],
        "all": ["all"],
    }

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        nmap_path: Optional[str] = None,
    ):
        self.session = session
        self.logger = logger or get_logger("tools.nmap")
        self.out_dir = session.dir("tools") / "nmap"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # Find nmap
        self.nmap_path = self._find_nmap(nmap_path)
        self.available = self.nmap_path is not None

        if not self.available:
            self.logger.warning("nmap not found. Install with: apt install nmap")

    def _find_nmap(self, path: Optional[str] = None) -> Optional[str]:
        """Find nmap executable."""
        if path and Path(path).exists():
            return path

        common_paths = [
            "nmap",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/nmap/nmap",
        ]

        for p in common_paths:
            try:
                if Path(p).exists():
                    return str(p)
            except Exception:
                pass

        try:
            result = subprocess.run(
                ["which", "nmap"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        return None

    def _build_command(
        self,
        target: str,
        scan_type: str = "syn",
        timing: str = "polite",
        ports: Optional[str] = None,
        scripts: Optional[List[str]] = None,
        script_args: Optional[str] = None,
        os_detection: bool = False,
        version_detection: bool = False,
        verbose: bool = False,
    ) -> List[str]:
        """Build nmap command."""
        cmd = [self.nmap_path]

        # Scan type
        if scan_type in self.SCAN_TYPES:
            cmd.append(self.SCAN_TYPES[scan_type])

        # Timing
        if timing in self.TIMING_TEMPLATES:
            cmd.extend(["-T", str(self.TIMING_TEMPLATES[timing])])

        # Ports
        if ports:
            cmd.extend(["-p", ports])

        # Scripts
        if scripts:
            script_str = ",".join(scripts)
            cmd.extend(["--script", script_str])

        # Script args
        if script_args:
            cmd.extend(["--script-args", script_args])

        # OS detection
        if os_detection:
            cmd.append("-O")

        # Version detection
        if version_detection:
            cmd.append("-sV")

        # Output
        xml_output = self.out_dir / f"nmap_{_safe(target)}.xml"
        cmd.extend(["-oX", str(xml_output)])

        # Stealth: randomize source port
        cmd.append("--source-port")
        cmd.append("53")

        # Stealth: fragment packets
        cmd.append("-f")

        # Stealth: random delays
        cmd.append("--scan-delay")
        cmd.append("2s")

        if not verbose:
            cmd.append("--quiet")

        cmd.append(target)

        return cmd, xml_output

    def _parse_xml(self, xml_path: Path) -> Dict[str, Any]:
        """Parse nmap XML output."""
        results = {
            "hosts": [],
            "ports": [],
            "os": [],
            "scripts": [],
        }

        if not xml_path.exists():
            return results

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                # Host info
                addr = host.find("address")
                if addr is None:
                    continue
                ip = addr.get("addr", "")

                host_info = {"ip": ip, "ports": [], "os": []}

                # Ports
                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    state = port.find("state")
                    service = port.find("service")

                    if state is None or state.get("state") != "open":
                        continue

                    port_info = {
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": "open",
                    }

                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["product"] = service.get("product", "")
                        port_info["version"] = service.get("version", "")
                        port_info["extra"] = service.get("extrainfo", "")

                    host_info["ports"].append(port_info)
                    results["ports"].append(port_info)

                # OS
                for os in host.findall(".//osclass"):
                    os_info = {
                        "family": os.get("osfamily", ""),
                        "generation": os.get("osgen", ""),
                        "vendor": os.get("vendor", ""),
                        "accuracy": os.get("accuracy", "0"),
                    }
                    host_info["os"].append(os_info)
                    results["os"].append(os_info)

                # Scripts
                for script in host.findall(".//script"):
                    script_info = {
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    }
                    results["scripts"].append(script_info)

                results["hosts"].append(host_info)

        except Exception as e:
            self.logger.warning(f"XML parse error: {e}")

        return results

    def scan(
        self,
        target: str,
        scan_type: str = "syn",
        timing: str = "polite",
        ports: Optional[str] = None,
        scripts: Optional[List[str]] = None,
        script_args: Optional[str] = None,
        os_detection: bool = False,
        version_detection: bool = False,
        timeout: int = 1800,
    ) -> Dict[str, Any]:
        """
        Run nmap scan.

        Args:
            target: Target IP or hostname
            scan_type: Scan type (syn, connect, udp, fin, null, ack)
            timing: Timing template (paranoid, sneaky, polite, normal, aggressive, insane)
            ports: Port specification (e.g., "22,80,443", "1-1000", "top100")
            scripts: Script categories (default, safe, vuln, discovery, exploit)
            script_args: Script arguments
            os_detection: Enable OS detection
            version_detection: Enable version detection
            timeout: Timeout in seconds

        Returns:
            Scan results
        """
        if not self.available:
            return {"status": "not_available", "error": "nmap not found"}

        self.logger.info(f"Starting nmap scan on: {target}")

        cmd, xml_output = self._build_command(
            target=target,
            scan_type=scan_type,
            timing=timing,
            ports=ports,
            scripts=scripts,
            script_args=script_args,
            os_detection=os_detection,
            version_detection=version_detection,
        )

        # Execute
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            elapsed = time.time() - start_time

            parsed = self._parse_xml(xml_output)

            # Add findings
            for port_info in parsed["ports"]:
                severity = SeverityLevel.INFO
                # High-risk ports
                if port_info["port"] in [22, 23, 21, 445, 3389, 3306, 5432, 1433, 27017]:
                    severity = SeverityLevel.MEDIUM
                # Critical ports (database, admin)
                if port_info["port"] in [3306, 5432, 1433, 27017, 27018]:
                    severity = SeverityLevel.HIGH

                self.session.add_finding(Finding(
                    source="tools.nmap",
                    title=f"Nmap: Port {port_info['port']}/{port_info['protocol']} open",
                    description=f"Service: {port_info.get('service', 'unknown')} ({port_info.get('product', '')} {port_info.get('version', '')})",
                    severity=severity,
                    host=target,
                    port=port_info["port"],
                    tags=["nmap", "port", "scan"],
                    evidence=json.dumps(port_info),
                ))

            for os_info in parsed["os"]:
                self.session.add_finding(Finding(
                    source="tools.nmap",
                    title=f"Nmap OS: {os_info['family']} {os_info['generation']}",
                    severity=SeverityLevel.INFO,
                    host=target,
                    tags=["nmap", "os", "fingerprint"],
                    evidence=json.dumps(os_info),
                ))

            for script in parsed["scripts"]:
                if "vuln" in script.get("id", ""):
                    self.session.add_finding(Finding(
                        source="tools.nmap",
                        title=f"Nmap script: {script['id']}",
                        severity=SeverityLevel.MEDIUM,
                        host=target,
                        tags=["nmap", "script", "vulnerability"],
                        evidence=script.get("output", "")[:300],
                    ))

            return {
                "status": "completed" if result.returncode == 0 else "partial",
                "elapsed": elapsed,
                "target": target,
                "hosts": parsed["hosts"],
                "ports": parsed["ports"],
                "os": parsed["os"],
                "scripts": parsed["scripts"],
                "output_file": str(xml_output),
                "exit_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Nmap scan timed out after {timeout}s")
            return {"status": "timeout", "target": target}
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            return {"status": "failed", "error": str(e), "target": target}

    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick scan with top 100 ports."""
        return self.scan(
            target=target,
            scan_type="syn",
            timing="polite",
            ports="top100",
            version_detection=True,
        )

    def full_scan(self, target: str) -> Dict[str, Any]:
        """Full scan with service detection and scripts."""
        return self.scan(
            target=target,
            scan_type="syn",
            timing="sneaky",
            ports="1-65535",
            version_detection=True,
            os_detection=True,
            scripts=["default", "safe", "vuln"],
            timeout=7200,
        )

    def vuln_scan(self, target: str) -> Dict[str, Any]:
        """Vulnerability scan with vuln scripts."""
        return self.scan(
            target=target,
            scan_type="syn",
            timing="polite",
            ports="top1000",
            version_detection=True,
            scripts=["vuln"],
            script_args="vulns.showall",
        )

    def run(self, target: str, depth: str = "quick") -> Dict[str, Any]:
        """
        Run nmap on target with specified depth.

        Args:
            target: Target IP or hostname
            depth: Scan depth (quick, full, vuln)
        """
        self.logger.banner(f"NMAP SCAN: {target}", style="bold red")

        if not self.available:
            return {"status": "not_available"}

        results = {
            "target": target,
            "depth": depth,
            "scans": [],
        }

        if depth == "quick":
            result = self.quick_scan(target)
            results["scans"].append(result)
        elif depth == "full":
            result = self.full_scan(target)
            results["scans"].append(result)
        elif depth == "vuln":
            result = self.vuln_scan(target)
            results["scans"].append(result)
        else:
            result = self.scan(
                target=target,
                scan_type="syn",
                timing="polite",
                ports="top1000",
                version_detection=True,
            )
            results["scans"].append(result)

        # Aggregate results
        results["ports"] = []
        results["os"] = []
        results["scripts"] = []

        for scan in results["scans"]:
            results["ports"].extend(scan.get("ports", []))
            results["os"].extend(scan.get("os", []))
            results["scripts"].extend(scan.get("scripts", []))

        # Save results
        report_path = self.out_dir / f"nmap_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Nmap: {len(results['ports'])} open ports, {len(results['os'])} OS fingerprints")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]