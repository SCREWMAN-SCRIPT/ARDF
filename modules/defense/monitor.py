"""
modules/defense/monitor.py
───────────────────────────
SecurityMonitor — passive blue team monitoring.

Monitors system and network activity during assessments,
logs defensive observations, and feeds findings back into
the session for purple team correlation.

All monitoring is READ-ONLY — no system changes are made.
"""

import os
import re
import json
import time
import subprocess
from datetime import datetime
from pathlib  import Path
from typing   import Any, Dict, List, Optional

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Monitor result schema
# ─────────────────────────────────────────────────────────────

class MonitorResult:
    def __init__(
        self,
        monitor_name: str,
        observations: List[Dict],
        anomalies:    List[Dict],
        raw_data:     Dict,
    ):
        self.monitor_name = monitor_name
        self.observations = observations
        self.anomalies    = anomalies
        self.raw_data     = raw_data
        self.timestamp    = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "monitor":      self.monitor_name,
            "timestamp":    self.timestamp,
            "observations": self.observations,
            "anomalies":    self.anomalies,
            "raw_data":     self.raw_data,
        }


# ─────────────────────────────────────────────────────────────
# SecurityMonitor
# ─────────────────────────────────────────────────────────────

class SecurityMonitor:
    """
    Passive blue team monitoring module.

    Reads system state, network connections, logs, and
    processes to identify anomalies during assessments.
    All operations are read-only.
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session  = session
        self.logger   = logger or get_logger("defense.monitor")
        self.out_dir  = session.dir("defense") / "monitor"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._baselines: Dict[str, Any] = {}

    # ── Public API ────────────────────────────────────────────

    def run_all(self) -> Dict[str, MonitorResult]:
        """Run all available monitors and return results."""
        self.logger.banner("SECURITY MONITORING", style="bold green")

        monitors = {
            "open_ports":       self.monitor_open_ports,
            "active_connections":self.monitor_connections,
            "listening_services":self.monitor_services,
            "failed_logins":    self.monitor_failed_logins,
            "process_list":     self.monitor_processes,
            "file_permissions": self.monitor_suid_files,
            "network_interfaces":self.monitor_interfaces,
            "firewall_rules":   self.monitor_firewall,
            "os_patch_level":   self.monitor_patch_level,
            "log_anomalies":    self.monitor_logs,
        }

        results = {}
        for name, fn in monitors.items():
            try:
                self.logger.info(f"Running monitor: {name}")
                result = fn()
                results[name] = result
                self._save_result(name, result)
                if result.anomalies:
                    self.logger.warning(
                        f"Monitor {name}: {len(result.anomalies)} anomalies detected"
                    )
                    self._create_findings(result)
            except Exception as e:
                self.logger.error(f"Monitor {name} failed: {e}")

        self.logger.success(f"Monitoring complete | {len(results)} monitors run")
        return results

    def set_baseline(self):
        """Capture current system state as a baseline for delta detection."""
        self.logger.info("Capturing system baseline...")
        self._baselines["ports"]     = self._get_open_ports()
        self._baselines["processes"] = self._get_processes()
        self._baselines["conns"]     = self._get_connections()
        self._baselines["timestamp"] = datetime.utcnow().isoformat()
        self.logger.success("Baseline captured")

    def get_delta(self) -> Dict[str, List]:
        """Compare current state against baseline and return deltas."""
        if not self._baselines:
            return {"error": "No baseline captured — call set_baseline() first"}

        current_ports = set(self._get_open_ports())
        base_ports    = set(self._baselines.get("ports", []))

        current_procs = {p["pid"]: p for p in self._get_processes()}
        base_procs    = {p["pid"]: p for p in self._baselines.get("processes", [])}

        return {
            "new_ports":    list(current_ports - base_ports),
            "closed_ports": list(base_ports - current_ports),
            "new_processes":[
                p for pid, p in current_procs.items()
                if pid not in base_procs
            ],
            "ended_processes":[
                p for pid, p in base_procs.items()
                if pid not in current_procs
            ],
            "since": self._baselines.get("timestamp", "unknown"),
        }

    # ── Individual monitors ───────────────────────────────────

    def monitor_open_ports(self) -> MonitorResult:
        """Check currently open ports on the local system."""
        ports    = self._get_open_ports()
        anomalies = []

        # Flag unexpected high-risk ports
        risk_ports = {
            21:   "FTP — plaintext credential transfer",
            23:   "Telnet — unencrypted remote access",
            512:  "rexec — legacy remote execution",
            513:  "rlogin — legacy remote login",
            514:  "rsh — legacy remote shell",
            1433: "MSSQL — database exposed",
            3306: "MySQL — database exposed",
            5432: "PostgreSQL — database exposed",
            6379: "Redis — often unauthenticated",
            27017:"MongoDB — often unauthenticated",
            9200: "Elasticsearch — often unauthenticated",
            2375: "Docker daemon — unauthenticated API",
            4243: "Docker daemon — unauthenticated API",
        }

        observations = [{"port": p, "status": "open"} for p in ports]
        for port in ports:
            if port in risk_ports:
                anomalies.append({
                    "type":    "risky_port",
                    "port":    port,
                    "reason":  risk_ports[port],
                    "severity":"high",
                })

        return MonitorResult(
            monitor_name="open_ports",
            observations=observations,
            anomalies=anomalies,
            raw_data={"ports": ports},
        )

    def monitor_connections(self) -> MonitorResult:
        """Monitor active network connections."""
        conns      = self._get_connections()
        anomalies  = []
        observations = []

        # Look for suspicious connection patterns
        external_conns = [
            c for c in conns
            if c.get("remote_ip") and not self._is_private(c["remote_ip"])
        ]

        for conn in conns:
            observations.append(conn)

        if len(external_conns) > 50:
            anomalies.append({
                "type":     "high_external_connections",
                "count":    len(external_conns),
                "severity": "medium",
                "reason":   f"Unusually high number of external connections: {len(external_conns)}",
            })

        return MonitorResult(
            monitor_name="active_connections",
            observations=observations,
            anomalies=anomalies,
            raw_data={"connections": conns, "external_count": len(external_conns)},
        )

    def monitor_services(self) -> MonitorResult:
        """Monitor listening services and their bindings."""
        stdout, _   = self._run(["ss", "-tlnp"])
        lines       = stdout.splitlines()[1:]
        observations = []
        anomalies    = []

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr = parts[3] if len(parts) > 3 else ""
            # Flag services bound to all interfaces
            if local_addr.startswith("0.0.0.0") or local_addr.startswith("*:"):
                observations.append({
                    "binding":  local_addr,
                    "line":     line.strip(),
                    "warning":  "bound to all interfaces",
                })
                port_match = re.search(r":(\d+)$", local_addr)
                if port_match:
                    port = int(port_match.group(1))
                    if port not in (80, 443, 22):
                        anomalies.append({
                            "type":    "service_bound_all_interfaces",
                            "port":    port,
                            "binding": local_addr,
                            "severity":"medium",
                            "reason":  f"Service on port {port} is accessible from all network interfaces",
                        })

        return MonitorResult(
            monitor_name="listening_services",
            observations=observations,
            anomalies=anomalies,
            raw_data={"raw_ss": stdout},
        )

    def monitor_failed_logins(self) -> MonitorResult:
        """Check auth logs for failed login attempts."""
        observations = []
        anomalies    = []
        fail_count   = 0

        # Try multiple log sources
        log_sources = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/messages",
        ]

        for log_path in log_sources:
            if not Path(log_path).exists():
                continue
            try:
                stdout, _ = self._run(["tail", "-n", "500", log_path])
                failures  = [
                    l for l in stdout.splitlines()
                    if any(k in l.lower() for k in [
                        "failed password", "invalid user",
                        "authentication failure", "failed login",
                        "too many authentication",
                    ])
                ]
                fail_count += len(failures)
                for line in failures[:20]:
                    observations.append({"source": log_path, "line": line.strip()})

                # Extract IPs from failures
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(failures))
                ip_counts: Dict[str, int] = {}
                for ip in ips:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

                for ip, count in ip_counts.items():
                    if count >= 5:
                        anomalies.append({
                            "type":     "repeated_auth_failure",
                            "ip":       ip,
                            "count":    count,
                            "severity": "high" if count >= 20 else "medium",
                            "reason":   f"IP {ip} has {count} failed login attempts",
                        })
            except Exception as e:
                self.logger.debug(f"Could not read {log_path}: {e}")

        return MonitorResult(
            monitor_name="failed_logins",
            observations=observations,
            anomalies=anomalies,
            raw_data={"total_failures": fail_count},
        )

    def monitor_processes(self) -> MonitorResult:
        """Monitor running processes for suspicious activity."""
        processes    = self._get_processes()
        observations = []
        anomalies    = []

        # Known suspicious process names
        suspicious = [
            "nc", "ncat", "netcat", "socat", "msfconsole",
            "meterpreter", "empire", "cobalt", "beacon",
            "mimikatz", "bloodhound", "sharphound",
        ]

        for proc in processes:
            cmd_lower = proc.get("cmd", "").lower()
            observations.append(proc)
            for susp in suspicious:
                if susp in cmd_lower:
                    anomalies.append({
                        "type":    "suspicious_process",
                        "pid":     proc.get("pid"),
                        "cmd":     proc.get("cmd", ""),
                        "severity":"high",
                        "reason":  f"Potentially suspicious process: {susp}",
                    })
                    break

        return MonitorResult(
            monitor_name="process_list",
            observations=observations[:50],
            anomalies=anomalies,
            raw_data={"process_count": len(processes)},
        )

    def monitor_suid_files(self) -> MonitorResult:
        """Find SUID/SGID files that could be used for privilege escalation."""
        observations = []
        anomalies    = []

        stdout, _ = self._run([
            "find", "/usr", "/bin", "/sbin", "/tmp", "/opt",
            "-type", "f",
            "-perm", "/6000",
            "-ls",
        ], timeout=30)

        # Known legitimate SUID binaries
        legitimate_suid = {
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
            "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
            "/usr/bin/gpasswd", "/usr/sbin/pppd",
            "/bin/mount", "/bin/umount", "/bin/ping",
            "/usr/lib/openssh/ssh-keysign",
        }

        for line in stdout.splitlines():
            if not line.strip():
                continue
            observations.append({"line": line.strip()})
            # Extract path
            parts = line.split()
            if len(parts) >= 11:
                path = parts[-1]
                if path not in legitimate_suid:
                    anomalies.append({
                        "type":    "unexpected_suid",
                        "path":    path,
                        "line":    line.strip(),
                        "severity":"medium",
                        "reason":  f"Non-standard SUID binary: {path}",
                    })

        return MonitorResult(
            monitor_name="file_permissions",
            observations=observations,
            anomalies=anomalies,
            raw_data={"suid_count": len(observations)},
        )

    def monitor_interfaces(self) -> MonitorResult:
        """Monitor network interfaces and their configuration."""
        stdout, _    = self._run(["ip", "addr", "show"])
        observations = []
        anomalies    = []

        # Check for promiscuous mode (packet sniffing indicator)
        promisc_check, _ = self._run(["ip", "link", "show"])
        for line in promisc_check.splitlines():
            if "PROMISC" in line:
                iface = re.search(r"^\d+: (\S+):", line)
                if iface:
                    anomalies.append({
                        "type":     "promiscuous_mode",
                        "interface":iface.group(1),
                        "severity": "high",
                        "reason":   f"Interface {iface.group(1)} in promiscuous mode — possible packet capture",
                    })

        observations.append({"interfaces": stdout})
        return MonitorResult(
            monitor_name="network_interfaces",
            observations=observations,
            anomalies=anomalies,
            raw_data={"ip_addr": stdout, "ip_link": promisc_check},
        )

    def monitor_firewall(self) -> MonitorResult:
        """Check firewall rule status."""
        observations = []
        anomalies    = []

        # Check UFW
        ufw_out, _ = self._run(["ufw", "status"])
        if "inactive" in ufw_out.lower():
            anomalies.append({
                "type":    "firewall_disabled",
                "tool":    "ufw",
                "severity":"high",
                "reason":  "UFW firewall is inactive — no host-based packet filtering",
            })
        observations.append({"ufw_status": ufw_out})

        # Check iptables
        ipt_out, _ = self._run(["iptables", "-L", "-n", "--line-numbers"])
        if "Chain INPUT (policy ACCEPT)" in ipt_out:
            anomalies.append({
                "type":    "permissive_iptables",
                "severity":"medium",
                "reason":  "iptables INPUT chain has ACCEPT default policy — consider DROP",
            })
        observations.append({"iptables": ipt_out[:2000]})

        return MonitorResult(
            monitor_name="firewall_rules",
            observations=observations,
            anomalies=anomalies,
            raw_data={"ufw": ufw_out, "iptables": ipt_out[:2000]},
        )

    def monitor_patch_level(self) -> MonitorResult:
        """Check for available security updates."""
        observations = []
        anomalies    = []

        # Check for pending updates
        if self._cmd_exists("apt-get"):
            stdout, _ = self._run(
                ["apt-get", "--simulate", "--just-print", "upgrade"],
                timeout=30,
            )
            upgrade_lines = [l for l in stdout.splitlines() if "Inst" in l]
            security_updates = [l for l in upgrade_lines if "security" in l.lower()]

            observations.append({
                "pending_updates":  len(upgrade_lines),
                "security_updates": len(security_updates),
            })

            if security_updates:
                anomalies.append({
                    "type":    "pending_security_updates",
                    "count":   len(security_updates),
                    "severity":"high",
                    "reason":  f"{len(security_updates)} pending security updates found",
                    "updates": security_updates[:10],
                })

        # OS version
        os_info, _ = self._run(["cat", "/etc/os-release"])
        observations.append({"os_info": os_info})

        # Kernel version
        kernel, _ = self._run(["uname", "-r"])
        observations.append({"kernel": kernel.strip()})

        return MonitorResult(
            monitor_name="os_patch_level",
            observations=observations,
            anomalies=anomalies,
            raw_data={"kernel": kernel.strip(), "os_release": os_info},
        )

    def monitor_logs(self) -> MonitorResult:
        """Scan system logs for security-relevant anomalies."""
        observations = []
        anomalies    = []

        patterns = {
            "root_login":       r"session opened for user root",
            "sudo_abuse":       r"sudo:.*COMMAND=/bin/bash|sudo:.*COMMAND=/bin/sh",
            "cron_modification":r"CRON.*changed|crontab.*modified",
            "pkg_install":      r"installed|dpkg.*upgrade",
            "ssh_key_added":    r"authorized_keys",
        }

        log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"]
        for log_path in log_files:
            if not Path(log_path).exists():
                continue
            try:
                stdout, _ = self._run(["tail", "-n", "200", log_path])
                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, stdout, re.IGNORECASE)
                    if matches:
                        observations.append({
                            "log":     log_path,
                            "pattern": pattern_name,
                            "matches": len(matches),
                        })
                        if pattern_name in ("root_login", "sudo_abuse", "ssh_key_added"):
                            anomalies.append({
                                "type":    f"log_{pattern_name}",
                                "source":  log_path,
                                "count":   len(matches),
                                "severity":"medium",
                                "reason":  f"Pattern '{pattern_name}' detected in {log_path}",
                            })
            except Exception as e:
                self.logger.debug(f"Could not read {log_path}: {e}")

        return MonitorResult(
            monitor_name="log_anomalies",
            observations=observations,
            anomalies=anomalies,
            raw_data={},
        )

    # ── Purple team monitors ──────────────────────────────────

    def monitor_recon_activity(self) -> MonitorResult:
        """Detect recon activity against this host (purple mode)."""
        return self.monitor_connections()

    def monitor_web_attacks(self) -> MonitorResult:
        """Monitor web server logs for attack patterns (purple mode)."""
        observations = []
        anomalies    = []

        web_logs = [
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
        ]

        attack_patterns = {
            "sqli":    r"union.*select|sleep\(|benchmark\(|'.*or.*'.*=.*'",
            "xss":     r"<script|javascript:|onerror=|onload=",
            "lfi":     r"\.\./\.\./|/etc/passwd|/proc/self",
            "scanner": r"nikto|sqlmap|nmap|nuclei|masscan|zap|burpsuite",
        }

        for log_path in web_logs:
            if not Path(log_path).exists():
                continue
            try:
                stdout, _ = self._run(["tail", "-n", "1000", log_path])
                for name, pattern in attack_patterns.items():
                    matches = re.findall(pattern, stdout, re.IGNORECASE)
                    if matches:
                        anomalies.append({
                            "type":    f"web_{name}",
                            "source":  log_path,
                            "count":   len(matches),
                            "severity":"high",
                            "reason":  f"Web attack pattern '{name}' detected in logs",
                        })
                        observations.append({
                            "log": log_path, "pattern": name, "hits": len(matches)
                        })
            except Exception as e:
                self.logger.debug(f"Could not read {log_path}: {e}")

        return MonitorResult(
            monitor_name="web_attack_monitor",
            observations=observations,
            anomalies=anomalies,
            raw_data={},
        )

    def monitor_network_attacks(self) -> MonitorResult:
        """Detect network-level attack patterns (purple mode)."""
        return self.monitor_open_ports()

    def monitor_credential_attacks(self) -> MonitorResult:
        """Monitor for credential attack activity (purple mode)."""
        return self.monitor_failed_logins()

    def monitor_post_exploitation(self) -> MonitorResult:
        """Monitor for post-exploitation indicators (purple mode)."""
        results   = []
        anomalies = []

        # Check for new SUID files recently created
        stdout, _ = self._run([
            "find", "/tmp", "/var/tmp", "/dev/shm",
            "-type", "f", "-newer", "/etc/passwd",
            "-ls",
        ], timeout=15)
        if stdout.strip():
            for line in stdout.splitlines():
                anomalies.append({
                    "type":    "new_file_in_temp",
                    "line":    line.strip(),
                    "severity":"high",
                    "reason":  "New file detected in temp directory",
                })
                results.append({"location": "temp", "line": line.strip()})

        return MonitorResult(
            monitor_name="post_exploitation_monitor",
            observations=results,
            anomalies=anomalies,
            raw_data={"temp_files": stdout},
        )

    # ── Utilities ─────────────────────────────────────────────

    def _get_open_ports(self) -> List[int]:
        stdout, _ = self._run(["ss", "-tlnp"])
        ports = []
        for line in stdout.splitlines()[1:]:
            match = re.search(r":(\d+)\s", line)
            if match:
                ports.append(int(match.group(1)))
        return sorted(set(ports))

    def _get_processes(self) -> List[Dict]:
        stdout, _ = self._run(["ps", "aux", "--no-headers"])
        procs = []
        for line in stdout.splitlines():
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0],
                    "pid":  parts[1],
                    "cpu":  parts[2],
                    "mem":  parts[3],
                    "cmd":  parts[10][:200],
                })
        return procs

    def _get_connections(self) -> List[Dict]:
        stdout, _ = self._run(["ss", "-tnp"])
        conns = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                remote = parts[4] if len(parts) > 4 else ""
                ip_match = re.match(r"^([\d.]+):\d+$", remote)
                conns.append({
                    "state":     parts[1] if len(parts) > 1 else "",
                    "local":     parts[3] if len(parts) > 3 else "",
                    "remote":    remote,
                    "remote_ip": ip_match.group(1) if ip_match else "",
                })
        return conns

    def _is_private(self, ip: str) -> bool:
        private_re = re.compile(
            r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)"
        )
        return bool(private_re.match(ip))

    def _cmd_exists(self, cmd: str) -> bool:
        try:
            subprocess.run(
                ["which", cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _run(
        self,
        cmd:     List[str],
        timeout: int = 15,
    ) -> tuple:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except FileNotFoundError:
            return "", f"not_found: {cmd[0]}"
        except Exception as e:
            return "", str(e)

    def _save_result(self, name: str, result: MonitorResult):
        path = self.out_dir / f"{name}.json"
        path.write_text(
            json.dumps(result.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

    def _create_findings(self, result: MonitorResult):
        """Convert monitor anomalies into session findings."""
        sev_map = {
            "critical": SeverityLevel.CRITICAL,
            "high":     SeverityLevel.HIGH,
            "medium":   SeverityLevel.MEDIUM,
            "low":      SeverityLevel.LOW,
        }
        for anomaly in result.anomalies:
            sev = sev_map.get(anomaly.get("severity", "low"), SeverityLevel.LOW)
            self.session.add_finding(Finding(
                source      = f"defense.monitor.{result.monitor_name}",
                title       = f"[Monitor] {anomaly.get('reason', anomaly.get('type', 'Anomaly'))}",
                description = json.dumps(anomaly, default=str)[:300],
                severity    = sev,
                host        = self.session.meta.target,
                tags        = ["monitor", "blue", result.monitor_name,
                               anomaly.get("type", "")],
                evidence    = json.dumps(anomaly, default=str),
            ))
