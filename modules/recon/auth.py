"""
modules/recon/auth.py
─────────────────────
Authentication system reconnaissance.

Provides:
  - Identity Providers (Okta, Azure AD, Auth0, Keycloak, Ping, OneLogin)
  - Login Portal Discovery (admin panels, login pages)
  - MFA Detection (TOTP, SMS, Email, Hardware tokens)
  - SSO Integration Detection
  - API Authentication Detection (OAuth, JWT, API keys)
  - Session Cookie Analysis
"""

import re
import json
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse, urljoin

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class AuthRecon:
    """
    Authentication system reconnaissance.
    """

    # Identity provider patterns
    IDP_PATTERNS = {
        "okta": [r"okta\.com", r"okta-", r"okta"],
        "azure_ad": [r"login\.microsoftonline\.com", r"azure\.com", r"azure-ad"],
        "auth0": [r"auth0\.com", r"auth0-", r"\.auth0\.com"],
        "keycloak": [r"keycloak", r"auth/keycloak", r"/auth/"],
        "ping_identity": [r"pingidentity", r"ping-", r"pingid"],
        "onelogin": [r"onelogin\.com", r"onelogin-"],
        "google": [r"accounts\.google\.com", r"googleapis\.com/auth"],
        "facebook": [r"facebook\.com/login", r"fb\.com/login"],
        "github": [r"github\.com/login", r"github\.com/auth"],
        "saml": [r"saml", r"SAML", r"/saml/", r"auth/saml"],
        "oauth": [r"oauth", r"/oauth/", r"oauth2", r"/oauth2/"],
        "openid": [r"openid", r"/openid/", r"openid-connect"],
    }

    # Login portal paths
    LOGIN_PATHS = [
        "/login", "/signin", "/auth", "/admin", "/administrator",
        "/Account/Login", "/user/login", "/api/login",
        "/login.php", "/login.asp", "/login.jsp",
        "/wp-login.php", "/admin/login", "/cpanel",
        "/webmail", "/mail/login", "/auth/login",
        "/sign-in", "/log-in", "/member/login",
        "/staff/login", "/employee/login", "/manager/login",
        "/portal/login", "/dashboard/login", "/console/login",
        "/oauth/login", "/saml/login", "/sso/login",
        "/idp/login", "/auth0/login", "/okta/login",
    ]

    # Admin panel paths
    ADMIN_PATHS = [
        "/admin", "/administrator", "/adm", "/admin.php",
        "/admin.asp", "/admin.jsp", "/admin/index",
        "/dashboard", "/panel", "/control", "/manage",
        "/wp-admin", "/cpanel", "/plesk", "/webadmin",
        "/system-admin", "/super-admin", "/root-admin",
        "/admin-console", "/management", "/backend",
        "/admin-dashboard", "/staff-admin", "/user-admin",
    ]

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.auth")
        self.out_dir = session.dir("recon") / "auth"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def discover_login_endpoints(self, target: str) -> List[Dict[str, str]]:
        """
        Discover login portals.
        """
        self.logger.info(f"Login endpoint discovery: {target}")

        results = []
        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        for base_url in urls:
            for path in self.LOGIN_PATHS:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 302, 401, 403]:
                        # Check if it's actually a login page
                        content_lower = content.lower()
                        indicators = ["login", "signin", "password", "username", "email", "auth", "log in", "sign in"]

                        if any(ind in content_lower for ind in indicators) or status in [302, 401]:
                            results.append({
                                "url": test_url,
                                "status": status,
                                "type": "login"
                            })
                            self.logger.finding(f"Login endpoint: {test_url}", severity="info", host=target)
                            self.session.add_finding(Finding(
                                source="recon.auth",
                                title=f"Login portal: {path}",
                                severity=SeverityLevel.LOW,
                                host=target,
                                tags=["auth", "login", "portal"],
                                evidence=test_url,
                            ))

                    self.stealth.sleep(0.5)

                except Exception:
                    pass

        return results

    def discover_admin_panels(self, target: str) -> List[Dict[str, str]]:
        """
        Discover admin panels.
        """
        self.logger.info(f"Admin panel discovery: {target}")

        results = []
        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        for base_url in urls:
            for path in self.ADMIN_PATHS:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 302, 401, 403]:
                        # Check for admin indicators
                        content_lower = content.lower()
                        indicators = ["admin", "dashboard", "manage", "control", "system", "configuration"]

                        if any(ind in content_lower for ind in indicators) or status == 401:
                            results.append({
                                "url": test_url,
                                "status": status,
                                "type": "admin"
                            })
                            self.logger.finding(f"Admin panel: {test_url}", severity="critical", host=target)
                            self.session.add_finding(Finding(
                                source="recon.auth",
                                title=f"Admin panel: {path}",
                                severity=SeverityLevel.HIGH,
                                host=target,
                                tags=["auth", "admin", "panel"],
                                evidence=test_url,
                                remediation="Restrict admin panel access. Use strong authentication.",
                            ))

                    self.stealth.sleep(0.5)

                except Exception:
                    pass

        return results

    def detect_identity_providers(self, target: str) -> List[Dict[str, str]]:
        """
        Detect identity providers.
        """
        self.logger.info(f"Identity provider detection: {target}")

        results = []

        # Collect URLs from findings
        urls = []
        for f in self.session.get_findings():
            if f.evidence and "http" in f.evidence:
                urls.append(f.evidence)

        for url in urls:
            for idp, patterns in self.IDP_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url, re.I):
                        results.append({
                            "provider": idp,
                            "url": url,
                            "type": "identity_provider"
                        })
                        self.logger.finding(f"Identity provider: {idp} -> {url}", severity="info", host=target)
                        self.session.add_finding(Finding(
                            source="recon.auth",
                            title=f"Identity provider: {idp}",
                            severity=SeverityLevel.INFO,
                            host=target,
                            tags=["auth", "idp", idp],
                            evidence=url,
                        ))
                        break

        return results

    def mfa_detection(self, url: str) -> Dict[str, Any]:
        """
        Detect MFA mechanisms.
        """
        self.logger.info(f"MFA detection: {url}")

        result = {
            "url": url,
            "mfa_detected": False,
            "mfa_types": [],
            "evidence": []
        }

        try:
            status, headers, content = self.stealth.get(url, timeout=5)

            content_lower = content.lower()

            # Check for MFA indicators
            mfa_indicators = {
                "totp": ["authenticator", "totp", "google authenticator", "microsoft authenticator", "6-digit code", "6 digit code"],
                "sms": ["sms", "text message", "phone verification", "mobile number", "phone number"],
                "email": ["email verification", "email code", "sent to your email", "verify email"],
                "security_questions": ["security question", "security answer", "mother maiden"],
                "hardware_token": ["yubikey", "security key", "physical token", "fido", "webauthn"],
                "push": ["push notification", "approve", "deny", "push request"],
                "backup_codes": ["backup code", "recovery code", "recovery backup"],
            }

            for mfa_type, indicators in mfa_indicators.items():
                for indicator in indicators:
                    if indicator in content_lower:
                        result["mfa_detected"] = True
                        if mfa_type not in result["mfa_types"]:
                            result["mfa_types"].append(mfa_type)
                        result["evidence"].append(f"Found '{indicator}' in page")

            if result["mfa_detected"]:
                self.logger.finding(f"MFA detected: {', '.join(result['mfa_types'])} on {url}", severity="info", host=url)
                self.session.add_finding(Finding(
                    source="recon.auth",
                    title=f"MFA types: {', '.join(result['mfa_types'])}",
                    severity=SeverityLevel.INFO,
                    host=url,
                    tags=["auth", "mfa", "security"],
                    evidence=json.dumps(result["evidence"]),
                ))

        except Exception as e:
            self.logger.debug(f"MFA detection failed: {e}")

        return result

    def api_auth_detection(self, target: str) -> Dict[str, Any]:
        """
        Detect API authentication methods.
        """
        self.logger.info(f"API auth detection: {target}")

        result = {
            "target": target,
            "auth_methods": [],
            "endpoints": [],
            "detected": False
        }

        # Check common API paths
        api_paths = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql", "/swagger"]

        for path in api_paths:
            try:
                test_url = f"https://{target}{path}"
                status, headers, content = self.stealth.get(test_url, timeout=5)

                if status in [200, 401, 403]:
                    result["endpoints"].append(test_url)

                    # Check auth headers
                    if "authorization" in headers:
                        result["auth_methods"].append("bearer_token")
                        result["detected"] = True

                    if "x-api-key" in headers:
                        result["auth_methods"].append("api_key")
                        result["detected"] = True

                    if "basic" in headers.get("www-authenticate", "").lower():
                        result["auth_methods"].append("basic_auth")
                        result["detected"] = True

                    # Check for OAuth patterns
                    if "oauth" in content.lower() or "bearer" in content.lower():
                        result["auth_methods"].append("oauth")
                        result["detected"] = True

                    # Check for JWT patterns
                    if "jwt" in content.lower() or "json web token" in content.lower():
                        result["auth_methods"].append("jwt")
                        result["detected"] = True

                    if result["detected"]:
                        self.logger.finding(f"API auth: {', '.join(result['auth_methods'])} on {test_url}", severity="info", host=target)
                        self.session.add_finding(Finding(
                            source="recon.auth",
                            title=f"API authentication: {', '.join(result['auth_methods'])}",
                            severity=SeverityLevel.LOW,
                            host=target,
                            tags=["api", "auth", "authentication"],
                            evidence=f"{test_url} -> {', '.join(result['auth_methods'])}",
                        ))

                self.stealth.sleep(0.5)

            except Exception:
                pass

        return result

    def session_cookie_analysis(self, url: str) -> Dict[str, Any]:
        """
        Analyze session cookies.
        """
        self.logger.info(f"Session cookie analysis: {url}")

        result = {
            "url": url,
            "cookies": [],
            "issues": [],
            "secure": False,
            "httponly": False,
            "samesite": False
        }

        try:
            status, headers, content = self.stealth.get(url, timeout=5)

            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                for cookie in set_cookie.split(","):
                    cookie_info = {"raw": cookie}
                    cookie = cookie.strip()

                    # Parse cookie attributes
                    if "Secure" in cookie:
                        result["secure"] = True
                        cookie_info["secure"] = True
                    else:
                        cookie_info["secure"] = False
                        result["issues"].append("Missing Secure flag")

                    if "HttpOnly" in cookie:
                        result["httponly"] = True
                        cookie_info["httponly"] = True
                    else:
                        cookie_info["httponly"] = False
                        result["issues"].append("Missing HttpOnly flag")

                    if "SameSite" in cookie:
                        result["samesite"] = True
                        cookie_info["samesite"] = True
                    else:
                        cookie_info["samesite"] = False
                        result["issues"].append("Missing SameSite attribute")

                    # Extract name
                    name_match = re.match(r"([^=]+)=", cookie)
                    if name_match:
                        cookie_info["name"] = name_match.group(1)

                    result["cookies"].append(cookie_info)

            if result["issues"]:
                self.logger.warning(f"Cookie issues: {', '.join(result['issues'])} on {url}")
                self.session.add_finding(Finding(
                    source="recon.auth",
                    title=f"Session cookie issues on {url}",
                    description=f"Issues: {', '.join(result['issues'])}",
                    severity=SeverityLevel.MEDIUM,
                    host=url,
                    tags=["auth", "session", "cookie", "security"],
                    evidence=json.dumps(result["issues"]),
                    remediation="Set Secure, HttpOnly, and SameSite attributes on session cookies.",
                ))

        except Exception as e:
            self.logger.debug(f"Cookie analysis failed: {e}")

        return result

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full authentication reconnaissance.
        """
        self.logger.banner(f"AUTH RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "login_endpoints": [],
            "admin_panels": [],
            "identity_providers": [],
            "mfa": [],
            "api_auth": {},
            "session_analysis": {}
        }

        # Discover login endpoints
        results["login_endpoints"] = self.discover_login_endpoints(target)

        # Discover admin panels
        results["admin_panels"] = self.discover_admin_panels(target)

        # Detect identity providers
        results["identity_providers"] = self.detect_identity_providers(target)

        # MFA detection on found login endpoints
        for endpoint in results["login_endpoints"][:5]:
            mfa_result = self.mfa_detection(endpoint["url"])
            if mfa_result["mfa_detected"]:
                results["mfa"].append(mfa_result)

        # API auth detection
        results["api_auth"] = self.api_auth_detection(target)

        # Session cookie analysis on base URL
        urls = [f"https://{target}", f"http://{target}"]
        for url in urls[:1]:
            results["session_analysis"][url] = self.session_cookie_analysis(url)

        # Save results
        report_path = self.out_dir / f"auth_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Auth recon: {len(results['login_endpoints'])} login endpoints, {len(results['admin_panels'])} admin panels")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]