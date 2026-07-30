"""
modules/recon/database.py
─────────────────────────
Database reconnaissance.

Provides:
  - Port Scanning for Databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch)
  - Database Service Detection (version, banner)
  - Database Accessibility Testing
  - NoSQL Database Enumeration
"""

import re
import json
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class DatabaseRecon:
    """
    Database reconnaissance.
    """

    # Database port mappings
    DB_PORTS = {
        "mysql": [3306],
        "postgresql": [5432],
        "mssql": [1433, 1434],
        "mongodb": [27017, 27018, 27019],
        "redis": [6379],
        "elasticsearch": [9200, 9300],
        "cassandra": [9042],
        "couchdb": [5984, 5985],
        "neo4j": [7474, 7687],
        "oracle": [1521],
        "ibm_db2": [50000],
        "sqlite": [None],  # File-based
        "dynamodb": [None],  # Cloud-based
        "influxdb": [8086],
        "memcached": [11211],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.database")
        self.out_dir = session.dir("recon") / "database"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def port_scan_databases(self, target: str) -> Dict[str, List[int]]:
        """
        Scan for database ports.
        """
        self.logger.info(f"Database port scan: {target}")

        all_ports = []
        for ports in self.DB_PORTS.values():
            all_ports.extend(ports)

        all_ports = [p for p in all_ports if p is not None]
        all_ports = list(set(all_ports))

        results = {db: [] for db in self.DB_PORTS.keys()}

        for port in all_ports[:30]:  # Limit ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    for db, ports in self.DB_PORTS.items():
                        if port in ports:
                            results[db].append(port)
                            self.logger.finding(f"Database port {port} open -> {db}", severity="info", host=target)
                            break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Port {port} scan failed: {e}")

        return results

    def service_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detect database service and version via banner grabbing.
        """
        self.logger.info(f"Database service detection: {target}:{port}")

        result = {
            "port": port,
            "service": None,
            "version": None,
            "banner": None,
            "ssl": False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Send probe
            sock.send(b"\n")
            data = sock.recv(1024)
            sock.close()

            banner = data.decode("utf-8", errors="ignore")
            result["banner"] = banner

            # Detect service from banner
            if "MySQL" in banner or "mysql" in banner:
                result["service"] = "MySQL"
                version_match = re.search(r"MySQL[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "PostgreSQL" in banner or "postgres" in banner:
                result["service"] = "PostgreSQL"
                version_match = re.search(r"PostgreSQL[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "MongoDB" in banner or "mongo" in banner:
                result["service"] = "MongoDB"
                version_match = re.search(r"MongoDB[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "Redis" in banner or "redis" in banner:
                result["service"] = "Redis"
                version_match = re.search(r"Redis[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "Elasticsearch" in banner or "elastic" in banner:
                result["service"] = "Elasticsearch"
                version_match = re.search(r"Elasticsearch[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "Cassandra" in banner or "cassandra" in banner:
                result["service"] = "Cassandra"
                version_match = re.search(r"Cassandra[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "CouchDB" in banner or "couchdb" in banner:
                result["service"] = "CouchDB"
                version_match = re.search(r"CouchDB[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "Neo4j" in banner or "neo4j" in banner:
                result["service"] = "Neo4j"
                version_match = re.search(r"Neo4j[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "SQL Server" in banner or "mssql" in banner:
                result["service"] = "MSSQL"
                version_match = re.search(r"SQL Server[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            elif "Oracle" in banner or "oracle" in banner:
                result["service"] = "Oracle"
                version_match = re.search(r"Oracle[^\d]*([\d.]+)", banner, re.I)
                if version_match:
                    result["version"] = version_match.group(1)

            # Check for SSL/TLS
            if "SSL" in banner or "TLS" in banner:
                result["ssl"] = True

        except Exception as e:
            self.logger.debug(f"Service detection on {port} failed: {e}")

        return result

    def accessibility_test(self, target: str, port: int, service: str) -> Dict[str, Any]:
        """
        Test database accessibility and authentication.
        """
        self.logger.info(f"Database accessibility test: {target}:{port} ({service})")

        result = {
            "port": port,
            "service": service,
            "accessible": False,
            "auth_required": True,
            "auth_bypass": False,
            "version": None
        }

        # Try unauthenticated connection
        try:
            if service in ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]:
                # Try simple connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                sock.send(b"\n")
                data = sock.recv(1024)
                sock.close()

                banner = data.decode("utf-8", errors="ignore")

                # Check if auth is required
                if "denied" in banner.lower() or "access" in banner.lower():
                    result["auth_required"] = True
                else:
                    result["auth_required"] = False
                    result["accessible"] = True

            elif service in ["MongoDB", "Redis", "Elasticsearch"]:
                # Try HTTP/REST interface
                if port == 9200:  # Elasticsearch
                    try:
                        status, headers, content = self.stealth.get(f"http://{target}:{port}", timeout=5)
                        if status == 200:
                            result["accessible"] = True
                            result["auth_required"] = False
                    except Exception:
                        pass
                else:
                    # Try socket connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    sock.send(b"\n")
                    data = sock.recv(1024)
                    sock.close()

                    if data:
                        result["accessible"] = True
                        result["auth_required"] = False

        except Exception as e:
            self.logger.debug(f"Accessibility test failed: {e}")

        if result["accessible"] and not result["auth_required"]:
            self.logger.finding(f"Database {service} accessible without auth: {target}:{port}", severity="critical", host=target)
            self.session.add_finding(Finding(
                source="recon.database",
                title=f"{service} accessible without authentication on {target}:{port}",
                severity=SeverityLevel.CRITICAL,
                host=target,
                port=port,
                tags=["database", "misconfiguration", "unauthorized"],
                evidence=f"{service} at {target}:{port} is accessible without credentials.",
                remediation=f"Enable authentication for {service}. Restrict access to trusted networks.",
            ))

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full database reconnaissance.
        """
        self.logger.banner(f"DATABASE RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.MEDIUM

        results = {
            "target": target,
            "databases": {},
            "accessible": [],
            "details": {}
        }

        # Scan database ports
        db_ports = self.port_scan_databases(target)
        results["databases"] = db_ports

        # Detect services on open ports
        for db, ports in db_ports.items():
            for port in ports:
                details = self.service_detection(target, port)
                if details["service"]:
                    results["details"][f"{db}:{port}"] = details

                    # Accessibility test
                    if details["service"]:
                        acc = self.accessibility_test(target, port, details["service"])
                        if acc["accessible"]:
                            results["accessible"].append({**acc, "details": details})

                    self.session.add_finding(Finding(
                        source="recon.database",
                        title=f"Database found: {details['service']} on {target}:{port}",
                        description=f"Version: {details['version'] or 'unknown'}",
                        severity=SeverityLevel.MEDIUM,
                        host=target,
                        port=port,
                        tags=["database", details.get("service", "").lower()],
                        evidence=f"Banner: {details['banner'][:200] if details['banner'] else 'unknown'}",
                        remediation="Ensure database is secured with strong authentication and network restrictions.",
                    ))

        # Save results
        report_path = self.out_dir / f"database_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Database recon: {len(results['databases'])} databases detected, {len(results['accessible'])} accessible without auth")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]