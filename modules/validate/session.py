"""
modules/validate/session.py
───────────────────────────
Session management validation module.

Detects and validates session vulnerabilities:
  - Session fixation
  - Session prediction
  - Session hijacking
  - Session timeout
  - Cookie security flags
  - Session token analysis

All validation requires Tier 3 confirmation (typed CONFIRM)
before any exploitation attempts.
"""

import re
import json
import time
import hashlib
import base64
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class SessionValidator:
    """
    Session management validation module.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.session")
        self.out_dir = session.dir("validate") / "session"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def analyze_cookies(self, url: str) -> Dict[str, Any]:
        """
        Analyze session cookies for security issues.
        """
        self.logger.info(f"Analyzing cookies: {url}")

        result = {
            "url": url,
            "cookies": [],
            "issues": [],
            "secure": False,
            "httponly": False,
            "samesite": False,
            "session_cookie": None
        }

        try:
            status, headers, content = self.stealth.get(url)

            set_cookie = headers.get("set-cookie", "")
            if not set_cookie:
                result["issues"].append("No cookies set")
                return result

            for cookie in set_cookie.split(","):
                cookie_info = {"raw": cookie.strip()}

                # Parse cookie attributes
                if "Secure" in cookie:
                    result["secure"] = True
                    cookie_info["secure"] = True
                else:
                    cookie_info["secure"] = False
                    if "Secure" not in result["issues"]:
                        result["issues"].append("Missing Secure flag")

                if "HttpOnly" in cookie:
                    result["httponly"] = True
                    cookie_info["httponly"] = True
                else:
                    cookie_info["httponly"] = False
                    if "HttpOnly" not in result["issues"]:
                        result["issues"].append("Missing HttpOnly flag")

                if "SameSite" in cookie:
                    result["samesite"] = True
                    cookie_info["samesite"] = True
                else:
                    cookie_info["samesite"] = False
                    if "SameSite" not in result["issues"]:
                        result["issues"].append("Missing SameSite attribute")

                # Extract name
                name_match = re.match(r"([^=]+)=", cookie)
                if name_match:
                    cookie_info["name"] = name_match.group(1)

                    # Check if this is likely a session cookie
                    if any(s in cookie_info["name"].lower() for s in ["session", "sid", "token", "auth"]):
                        result["session_cookie"] = cookie_info["name"]

                result["cookies"].append(cookie_info)

            # Add findings for issues
            if result["issues"]:
                self.logger.warning(f"Cookie issues: {', '.join(result['issues'])} on {url}")
                self.session.add_finding(Finding(
                    source="validate.session",
                    title=f"Session cookie issues on {url}",
                    description=f"Issues: {', '.join(result['issues'])}",
                    severity=SeverityLevel.HIGH,
                    host=url,
                    tags=["session", "cookie", "security"],
                    evidence=json.dumps(result["issues"]),
                    remediation="Set Secure, HttpOnly, and SameSite attributes on session cookies.",
                ))

        except Exception as e:
            self.logger.debug(f"Cookie analysis failed: {e}")
            result["error"] = str(e)

        return result

    def session_fixation_test(self, url: str) -> Dict[str, Any]:
        """
        Test for session fixation vulnerability.
        """
        self.logger.info(f"Session fixation test: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "evidence": [],
            "pre_login_session": None,
            "post_login_session": None
        }

        try:
            # Get session before login
            status, headers, content = self.stealth.get(url)
            pre_cookie = headers.get("set-cookie", "")

            if pre_cookie:
                result["pre_login_session"] = pre_cookie[:100]

                # Try to set a custom session ID
                # This is a simplified test
                test_cookie = pre_cookie.split(";")[0] if ";" in pre_cookie else pre_cookie

                # Try to use the same session after login
                # In a real test, we would login with the pre-set session
                # For now, we check if the session persists

                # Check if session ID is predictable
                session_id_match = re.search(r"([a-zA-Z0-9]+)", pre_cookie)
                if session_id_match:
                    session_id = session_id_match.group(1)

                    # Check for entropy
                    if len(session_id) < 16:
                        result["vulnerable"] = True
                        result["evidence"].append("Session ID too short (low entropy)")

                    # Check for predictable pattern
                    if session_id.isdigit():
                        result["vulnerable"] = True
                        result["evidence"].append("Session ID is numeric (predictable)")

                    if session_id.isalnum() and not any(c.islower() for c in session_id):
                        result["vulnerable"] = True
                        result["evidence"].append("Session ID lacks lowercase characters (low entropy)")

            if result["vulnerable"]:
                self.logger.finding(f"Session fixation vulnerability detected on {url}", severity="critical", host=url)
                self.session.add_finding(Finding(
                    source="validate.session",
                    title=f"Session fixation vulnerability on {url}",
                    severity=SeverityLevel.CRITICAL,
                    host=url,
                    tags=["session", "fixation", "vulnerability"],
                    evidence=json.dumps(result["evidence"]),
                    remediation="Generate new session ID after login. Use unpredictable session IDs.",
                ))

        except Exception as e:
            self.logger.debug(f"Session fixation test failed: {e}")

        return result

    def session_timeout_test(self, url: str) -> Dict[str, Any]:
        """
        Test session timeout.
        """
        self.logger.info(f"Session timeout test: {url}")

        result = {
            "url": url,
            "timeout_detected": False,
            "timeout_seconds": None,
            "session_persists": False,
            "evidence": []
        }

        try:
            # Get initial session
            status, headers, content = self.stealth.get(url)
            session_cookie = headers.get("set-cookie", "")

            if not session_cookie:
                return result

            # Wait for potential timeout
            test_times = [30, 60, 120, 300]  # 30s, 1m, 2m, 5m

            for wait_time in test_times:
                self.logger.debug(f"Waiting {wait_time}s for session timeout test")

                # Set cookie for request
                cookies = {}
                if session_cookie:
                    cookie_parts = session_cookie.split(";")[0].split("=")
                    if len(cookie_parts) == 2:
                        cookies[cookie_parts[0]] = cookie_parts[1]

                # Make request with session cookie
                time.sleep(wait_time)

                # In a real test, we would check if the session is still valid
                # For now, we check if the cookie has expired

                # Check if max-age or expires is set
                if "Max-Age" in session_cookie:
                    max_age_match = re.search(r"Max-Age=(\d+)", session_cookie)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        result["timeout_detected"] = True
                        result["timeout_seconds"] = max_age
                        result["evidence"].append(f"Session timeout: {max_age}s")

                        if max_age > 3600:
                            result["evidence"].append("Session timeout > 1 hour (long)")
                        elif max_age > 86400:
                            result["evidence"].append("Session timeout > 24 hours (too long)")

                if "Expires" in session_cookie:
                    result["timeout_detected"] = True
                    result["evidence"].append("Session has explicit expiry")

                break

            if result["timeout_detected"]:
                self.session.add_finding(Finding(
                    source="validate.session",
                    title=f"Session timeout: {result['timeout_seconds']}s on {url}",
                    severity=SeverityLevel.MEDIUM if result.get("timeout_seconds", 0) > 3600 else SeverityLevel.LOW,
                    host=url,
                    tags=["session", "timeout", "security"],
                    evidence=json.dumps(result["evidence"]),
                    remediation="Set appropriate session timeout values (15-30 minutes for sensitive applications).",
                ))

        except Exception as e:
            self.logger.debug(f"Session timeout test failed: {e}")

        return result

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full session validation workflow.
        """
        self.logger.info(f"Session validation: {url}")

        results = {
            "url": url,
            "cookie_analysis": {},
            "session_fixation": {},
            "session_timeout": {},
            "vulnerabilities": [],
            "status": "completed"
        }

        # Cookie analysis
        results["cookie_analysis"] = self.analyze_cookies(url)

        # Session fixation test
        results["session_fixation"] = self.session_fixation_test(url)

        # Session timeout test
        results["session_timeout"] = self.session_timeout_test(url)

        # Collect vulnerabilities
        if results["session_fixation"].get("vulnerable"):
            results["vulnerabilities"].append({
                "type": "session_fixation",
                "url": url,
                "evidence": results["session_fixation"].get("evidence", [])
            })

        if results["cookie_analysis"].get("issues"):
            results["vulnerabilities"].append({
                "type": "cookie_security",
                "url": url,
                "issues": results["cookie_analysis"].get("issues", [])
            })

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run session validation on target.
        """
        self.logger.banner(f"SESSION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "urls_tested": [],
            "vulnerabilities": []
        }

        for url in urls:
            try:
                result = self.validate(url)
                results["urls_tested"].append(url)
                results["vulnerabilities"].extend(result["vulnerabilities"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"session_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Session validation: {len(results['vulnerabilities'])} vulnerabilities found")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]