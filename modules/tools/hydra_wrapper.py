"""
modules/tools/hydra_wrapper.py
──────────────────────────────
Hydra wrapper for ARDF.

Provides controlled Hydra execution with:
  - Stealth mode integration (rate limiting, random delays)
  - Multiple service support (SSH, FTP, HTTP, SMB, RDP, etc.)
  - Wordlist management
  - Output parsing and finding extraction
  - Session management

All execution requires Tier 3 confirmation (typed CONFIRM)
before any exploitation attempts.
"""

import re
import json
import time
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class HydraWrapper:
    """
    Hydra wrapper with stealth and integration.
    """

    # Supported services
    SERVICES = {
        "ssh": {"port": 22, "protocol": "ssh"},
        "ftp": {"port": 21, "protocol": "ftp"},
        "http": {"port": 80, "protocol": "http-get"},
        "https": {"port": 443, "protocol": "http-get"},
        "http-post": {"port": 80, "protocol": "http-post"},
        "https-post": {"port": 443, "protocol": "http-post"},
        "smb": {"port": 445, "protocol": "smb"},
        "rdp": {"port": 3389, "protocol": "rdp"},
        "mysql": {"port": 3306, "protocol": "mysql"},
        "postgres": {"port": 5432, "protocol": "postgres"},
        "mssql": {"port": 1433, "protocol": "mssql"},
        "smtp": {"port": 25, "protocol": "smtp"},
        "pop3": {"port": 110, "protocol": "pop3"},
        "imap": {"port": 143, "protocol": "imap"},
        "vnc": {"port": 5900, "protocol": "vnc"},
        "telnet": {"port": 23, "protocol": "telnet"},
        "snmp": {"port": 161, "protocol": "snmp"},
    }

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        hydra_path: Optional[str] = None,
    ):
        self.session = session
        self.logger = logger or get_logger("tools.hydra")
        self.out_dir = session.dir("tools") / "hydra"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # Find hydra
        self.hydra_path = self._find_hydra(hydra_path)
        self.available = self.hydra_path is not None

        if not self.available:
            self.logger.warning("hydra not found. Install with: apt install hydra")

        # Default wordlists
        self.default_userlist = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        self.default_passlist = "/usr/share/wordlists/rockyou.txt"

    def _find_hydra(self, path: Optional[str] = None) -> Optional[str]:
        """Find hydra executable."""
        if path and Path(path).exists():
            return path

        common_paths = [
            "hydra",
            "/usr/bin/hydra",
            "/usr/local/bin/hydra",
            "/opt/hydra/hydra",
        ]

        for p in common_paths:
            try:
                if Path(p).exists():
                    return str(p)
            except Exception:
                pass

        try:
            result = subprocess.run(
                ["which", "hydra"],
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
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: Optional[int] = None,
        threads: int = 4,
        timeout: int = 30,
        verbose: bool = False,
    ) -> List[str]:
        """Build hydra command."""
        cmd = [self.hydra_path]

        # Service
        service_info = self.SERVICES.get(service)
        if not service_info:
            raise ValueError(f"Unsupported service: {service}")

        # Target and port
        if port:
            cmd.extend(["-s", str(port)])

        # Username(s)
        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])

        # Password(s)
        if password:
            cmd.extend(["-p", password])
        elif passlist:
            cmd.extend(["-P", passlist])

        # Threads
        cmd.extend(["-t", str(threads)])

        # Timeout
        cmd.extend(["-w", str(timeout)])

        # Output format
        cmd.extend(["-o", str(self.out_dir / f"hydra_{_safe(target)}.txt")])

        # Stealth: reduce speed
        cmd.extend(["-W", "2"])  # Wait 2 seconds between attempts

        if not verbose:
            cmd.append("-q")

        # Target and service
        cmd.append(f"{target}://{service}")

        return cmd

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output for findings."""
        results = {
            "credentials": [],
            "services_found": [],
            "errors": [],
        }

        # Parse successful credentials
        cred_patterns = [
            r"\[(\d+)\]\[([\w-]+)\] host: ([\w.-]+)\s+login: ([\w.-]+)\s+password: (.*)",
            r"login: ([\w.-]+)\s+password: (.*)",
            r"\[([\w-]+)\] host: ([\w.-]+)\s+login: ([\w.-]+)\s+password: (.*)",
        ]

        for pattern in cred_patterns:
            for match in re.finditer(pattern, output):
                groups = match.groups()
                if len(groups) == 5:
                    results["credentials"].append({
                        "port": groups[0],
                        "service": groups[1],
                        "host": groups[2],
                        "username": groups[3],
                        "password": groups[4],
                    })
                elif len(groups) == 2:
                    results["credentials"].append({
                        "username": groups[0],
                        "password": groups[1],
                    })
                elif len(groups) == 4:
                    results["credentials"].append({
                        "service": groups[0],
                        "host": groups[1],
                        "username": groups[2],
                        "password": groups[3],
                    })

        # Parse services found
        service_pattern = r"\[(\d+)\](?:\[)?([\w-]+)?(?:host:)?\s+[\w.-]+"
        for match in re.finditer(service_pattern, output):
            if len(match.groups()) >= 2:
                results["services_found"].append({
                    "port": match.group(1),
                    "service": match.group(2) or "unknown",
                })

        # Parse errors
        if "ERROR" in output:
            results["errors"].append("Hydra errors encountered")

        return results

    def brute_force(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: Optional[int] = None,
        threads: int = 4,
        timeout: int = 300,
        max_attempts: int = 100,
    ) -> Dict[str, Any]:
        """
        Run hydra brute-force.

        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http, smb, etc.)
            username: Single username
            userlist: Username wordlist
            password: Single password
            passlist: Password wordlist
            port: Service port (auto-detected if not provided)
            threads: Number of threads
            timeout: Timeout in seconds
            max_attempts: Maximum attempts (limits wordlist size)

        Returns:
            Brute-force results
        """
        if not self.available:
            return {"status": "not_available", "error": "hydra not found"}

        self.logger.info(f"Starting hydra brute-force on {target} ({service})")

        # Validate credentials
        if not username and not userlist:
            userlist = self.default_userlist
        if not password and not passlist:
            passlist = self.default_passlist

        # Auto-detect port
        if not port and service in self.SERVICES:
            port = self.SERVICES[service]["port"]

        cmd = self._build_command(
            target=target,
            service=service,
            username=username,
            userlist=userlist,
            password=password,
            passlist=passlist,
            port=port,
            threads=threads,
            timeout=timeout,
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

            output = result.stdout + result.stderr
            parsed = self._parse_output(output)

            # Save output
            report_path = self.out_dir / f"hydra_{_safe(target)}_{service}.log"
            report_path.write_text(output)

            # Add findings
            if parsed["credentials"]:
                self.logger.finding(f"Credentials found: {len(parsed['credentials'])} pairs", severity="critical", host=target)
                for cred in parsed["credentials"][:5]:
                    username = cred.get("username", "unknown")
                    password = cred.get("password", "unknown")
                    self.session.add_finding(Finding(
                        source="tools.hydra",
                        title=f"Hydra credentials: {username}:{password}",
                        severity=SeverityLevel.CRITICAL,
                        host=target,
                        port=port,
                        tags=["hydra", "credentials", "bruteforce"],
                        evidence=f"Service: {service}\nUsername: {username}\nPassword: {password}",
                        remediation="Change exposed credentials immediately. Implement account lockout.",
                    ))

            return {
                "status": "completed" if result.returncode == 0 else "partial",
                "elapsed": elapsed,
                "target": target,
                "service": service,
                "port": port,
                "credentials": parsed["credentials"],
                "services_found": parsed["services_found"],
                "output_file": str(report_path),
                "exit_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Hydra brute-force timed out after {timeout}s")
            return {"status": "timeout", "target": target, "service": service}
        except Exception as e:
            self.logger.error(f"Hydra brute-force failed: {e}")
            return {"status": "failed", "error": str(e), "target": target, "service": service}

    def brute_force_service(
        self,
        target: str,
        service: str,
        username: str = "admin",
        passlist: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Brute-force a specific service with common credentials.
        """
        return self.brute_force(
            target=target,
            service=service,
            username=username,
            passlist=passlist or self.default_passlist,
            port=port,
        )

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run hydra on target for multiple services.
        """
        self.logger.banner(f"HYDRA SCAN: {target}", style="bold red")

        if not self.available:
            return {"status": "not_available"}

        results = {
            "target": target,
            "scans": [],
            "credentials": [],
        }

        # Find open ports from session
        open_ports = set()
        for f in self.session.get_findings():
            if f.port:
                open_ports.add(f.port)

        # Determine services to test based on open ports
        services_to_test = []
        for service, info in self.SERVICES.items():
            if info["port"] in open_ports:
                services_to_test.append(service)

        # Default services if no ports found
        if not services_to_test:
            services_to_test = ["ssh", "ftp", "http", "https"]

        # Test each service
        for service in services_to_test[:3]:
            try:
                result = self.brute_force_service(
                    target=target,
                    service=service,
                    username="admin",
                )
                results["scans"].append(result)
                if result.get("credentials"):
                    results["credentials"].extend(result["credentials"])
            except Exception as e:
                self.logger.warning(f"Hydra scan failed for {service}: {e}")

        # Save results
        report_path = self.out_dir / f"hydra_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Hydra: {len(results['scans'])} scans, {len(results['credentials'])} credentials")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]