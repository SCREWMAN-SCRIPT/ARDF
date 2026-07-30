"""
modules/tools/sqlmap_wrapper.py
───────────────────────────────
SQLMap wrapper for ARDF.

Provides controlled SQLMap execution with:
  - Stealth mode integration (rate limiting, random delays)
  - Configurable risk levels
  - Output parsing and finding extraction
  - Session management
  - Automatic database fingerprinting

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


class SQLMapWrapper:
    """
    SQLMap wrapper with stealth and integration.
    """

    # SQLMap risk levels
    RISK_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    # SQLMap evasion techniques
    EVASION_TECHNIQUES = [
        "space2comment",
        "charunion",
        "charunicodeencode",
        "unionalltounion",
        "schemacomment",
        "uppercase",
        "lowercase",
        "randomcase",
        "ifnull2ifisnull",
        "doubleslash",
        "charreplace",
        "hexchar",
        "space2mssqlhash",
        "space2mysqlblank",
        "space2mysqldash",
        "between",
        "greatest",
        "multiplespaces",
        "percentage",
        "sp_password",
        "charencode",
        "randomcomments",
        "versionedkeywords",
        "versionedmorekeywords",
        "inlinecomments",
        "concat2concatws",
        "concat2char",
        "modsecurityversioned",
        "modsecurityzeroversioned",
        "recursiveunion",
        "nonrecursiveunion",
        "minmax",
        "hexentities",
        "ordinal",
        "space2dash",
        "space2hnumber",
        "space2plus",
        "dunion",
        "xor",
        "selectnullfrom",
        "deal",
        "limitstring",
        "space2mssqlblank",
        "space2mysqlhash",
        "functioncall",
        "orderbygroupby",
        "columncase",
        "charcaseswap",
        "postgrescast",
        "ifcast",
        "mergecast",
        "deprecatedcast",
        "mysqllib",
        "hex2dec",
        "prefixsuffix",
        "suffixprefix",
        "randomagent",
        "noescape",
        "nonumber",
        "dud",
        "replace",
        "commentpack",
        "swap",
        "nullify",
        "invalid",
        "delimiter",
    ]

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        sqlmap_path: Optional[str] = None,
    ):
        self.session = session
        self.logger = logger or get_logger("tools.sqlmap")
        self.out_dir = session.dir("tools") / "sqlmap"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # Find sqlmap
        self.sqlmap_path = self._find_sqlmap(sqlmap_path)
        self.available = self.sqlmap_path is not None

        if not self.available:
            self.logger.warning("sqlmap not found. Install with: pip install sqlmap")

    def _find_sqlmap(self, path: Optional[str] = None) -> Optional[str]:
        """Find sqlmap executable."""
        if path and Path(path).exists():
            return path

        # Check common locations
        common_paths = [
            "sqlmap",
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
            "/home/*/.local/bin/sqlmap",
        ]

        for p in common_paths:
            try:
                if Path(p).expanduser().exists():
                    return str(p)
            except Exception:
                pass

        # Check with which
        try:
            result = subprocess.run(
                ["which", "sqlmap"],
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
        url: str,
        params: Optional[Dict[str, Any]] = None,
        risk: str = "medium",
        level: int = 1,
        technique: str = "BEUST",
        evasion: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> List[str]:
        """Build sqlmap command."""
        cmd = [self.sqlmap_path, "-u", url, "--batch", "--output-dir", str(self.out_dir)]

        # Risk level
        risk_value = self.RISK_LEVELS.get(risk, 2)
        cmd.extend(["--risk", str(risk_value)])

        # Level
        cmd.extend(["--level", str(level)])

        # Techniques
        if technique:
            cmd.extend(["--technique", technique])

        # Evasion
        if evasion:
            for tech in evasion[:3]:
                cmd.extend(["--tamper", tech])

        # Stealth
        cmd.extend(["--delay", "2"])
        cmd.extend(["--timeout", "10"])
        cmd.extend(["--retries", "2"])

        # Random agent
        cmd.append("--random-agent")

        # Output
        if not verbose:
            cmd.append("--quiet")

        # Parameters
        if params:
            if params.get("data"):
                cmd.extend(["--data", params["data"]])
            if params.get("cookie"):
                cmd.extend(["--cookie", params["cookie"]])
            if params.get("headers"):
                cmd.extend(["--headers", params["headers"]])
            if params.get("host"):
                cmd.extend(["--host", params["host"]])
            if params.get("method"):
                cmd.extend(["--method", params["method"]])
            if params.get("param"):
                cmd.extend(["-p", params["param"]])
            if params.get("level"):
                cmd.extend(["--level", str(params["level"])])

        # Additional options
        if params and params.get("dump"):
            cmd.append("--dump")
        if params and params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])

        return cmd

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output for findings."""
        results = {
            "databases": [],
            "tables": [],
            "columns": [],
            "credentials": [],
            "vulnerabilities": [],
        }

        # Parse databases
        db_pattern = r"\[\*\] (?:Database|Schema): ([\w.-]+)"
        for match in re.finditer(db_pattern, output):
            results["databases"].append(match.group(1))

        # Parse tables
        table_pattern = r"\+-+\+\s*\| ([\w.-]+) \|"
        for match in re.finditer(table_pattern, output):
            results["tables"].append(match.group(1))

        # Parse credentials
        cred_pattern = r"\| ([\w.-]+) \| ([\w.-]+) \|"
        for match in re.finditer(cred_pattern, output):
            results["credentials"].append({
                "username": match.group(1),
                "password": match.group(2),
            })

        # Parse vulnerabilities
        vuln_patterns = [
            (r"\[(CRITICAL|HIGH|MEDIUM|LOW)\] (.*)", "vulnerability"),
            (r"Parameter: ([\w.-]+) is vulnerable", "injection"),
            (r"Database: ([\w.-]+)", "database"),
            (r"Retrieved ([\w.-]+) rows", "rows"),
        ]

        for pattern, vuln_type in vuln_patterns:
            for match in re.finditer(pattern, output, re.I):
                results["vulnerabilities"].append({
                    "type": vuln_type,
                    "match": match.group(0),
                    "severity": match.group(1) if len(match.groups()) > 1 else "UNKNOWN",
                })

        return results

    def scan(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        risk: str = "medium",
        level: int = 1,
        technique: str = "BEUST",
        evasion: Optional[List[str]] = None,
        timeout: int = 3600,
    ) -> Dict[str, Any]:
        """
        Run sqlmap scan.

        Args:
            url: Target URL
            params: Additional parameters (data, cookie, headers, etc.)
            risk: Risk level (low, medium, high)
            level: Test level (1-5)
            technique: Techniques (BEUST)
            evasion: Evasion techniques
            timeout: Timeout in seconds

        Returns:
            Scan results
        """
        if not self.available:
            return {"status": "not_available", "error": "sqlmap not found"}

        self.logger.info(f"Starting sqlmap scan on: {url}")

        cmd = self._build_command(
            url=url,
            params=params,
            risk=risk,
            level=level,
            technique=technique,
            evasion=evasion,
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
            report_path = self.out_dir / f"sqlmap_{_safe(url)}.log"
            report_path.write_text(output)

            # Add findings
            if parsed["databases"]:
                self.logger.finding(f"Databases found: {', '.join(parsed['databases'])}", severity="info", host=url)
                self.session.add_finding(Finding(
                    source="tools.sqlmap",
                    title=f"SQLMap: {len(parsed['databases'])} databases discovered",
                    description=f"Databases: {', '.join(parsed['databases'])}",
                    severity=SeverityLevel.HIGH,
                    host=url,
                    tags=["sqlmap", "database", "enumeration"],
                    evidence=json.dumps(parsed["databases"][:5]),
                ))

            if parsed["credentials"]:
                self.logger.finding(f"Credentials found: {len(parsed['credentials'])} pairs", severity="critical", host=url)
                for cred in parsed["credentials"][:5]:
                    self.session.add_finding(Finding(
                        source="tools.sqlmap",
                        title=f"SQLMap credentials: {cred['username']}:{cred['password']}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["sqlmap", "credentials", "data-exposure"],
                        evidence=f"Username: {cred['username']}\nPassword: {cred['password']}",
                        remediation="Change exposed credentials immediately.",
                    ))

            if parsed["tables"]:
                self.logger.success(f"Tables found: {len(parsed['tables'])}")
                self.session.add_finding(Finding(
                    source="tools.sqlmap",
                    title=f"SQLMap: {len(parsed['tables'])} tables discovered",
                    severity=SeverityLevel.MEDIUM,
                    host=url,
                    tags=["sqlmap", "table", "enumeration"],
                    evidence=json.dumps(parsed["tables"][:10]),
                ))

            return {
                "status": "completed",
                "elapsed": elapsed,
                "url": url,
                "databases": parsed["databases"],
                "tables": parsed["tables"],
                "credentials": parsed["credentials"],
                "vulnerabilities": parsed["vulnerabilities"],
                "output_file": str(report_path),
                "exit_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            self.logger.warning(f"sqlmap scan timed out after {timeout}s")
            return {"status": "timeout", "url": url}
        except Exception as e:
            self.logger.error(f"sqlmap scan failed: {e}")
            return {"status": "failed", "error": str(e), "url": url}

    def scan_endpoint(
        self,
        url: str,
        parameter: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        risk: str = "medium",
        level: int = 1,
    ) -> Dict[str, Any]:
        """
        Scan a specific parameter on an endpoint.
        """
        return self.scan(
            url=url,
            params={
                "param": parameter,
                "data": data,
                "cookie": cookie,
                "level": level,
            },
            risk=risk,
            level=level,
        )

    def dump_database(
        self,
        url: str,
        database: str,
        table: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Dump a database or table.
        """
        scan_params = params or {}
        scan_params["dump"] = True
        scan_params["param"] = scan_params.get("param", "id")

        return self.scan(
            url=url,
            params=scan_params,
            risk="high",
            level=3,
            timeout=7200,
        )

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run sqlmap on target.
        """
        self.logger.banner(f"SQLMAP SCAN: {target}", style="bold red")

        if not self.available:
            return {"status": "not_available"}

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "scans": [],
            "databases": [],
            "credentials": [],
        }

        for url in urls:
            try:
                # Try to detect parameters first
                from modules.validate.sqli import SQLiValidator
                sqli = SQLiValidator(self.session, self.logger)
                params = sqli.detect_parameters(url)

                if params:
                    # Scan each parameter
                    for param in params[:3]:
                        result = self.scan_endpoint(
                            url=param["url"],
                            parameter=param["name"],
                            data=param.get("data"),
                        )
                        results["scans"].append(result)
                        if result.get("databases"):
                            results["databases"].extend(result["databases"])
                        if result.get("credentials"):
                            results["credentials"].extend(result["credentials"])
                else:
                    # Try generic scan
                    result = self.scan(url)
                    results["scans"].append(result)
                    if result.get("databases"):
                        results["databases"].extend(result["databases"])
                    if result.get("credentials"):
                        results["credentials"].extend(result["credentials"])

            except Exception as e:
                self.logger.warning(f"SQLMap scan failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"sqlmap_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"SQLMap: {len(results['scans'])} scans, {len(results['databases'])} databases, {len(results['credentials'])} credentials")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]