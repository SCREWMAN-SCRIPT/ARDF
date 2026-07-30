"""
modules/recon/social.py
───────────────────────
Social intelligence reconnaissance.

Provides:
  - Employee enumeration (LinkedIn, GitHub)
  - Email harvesting
  - Social media profiling
  - Breach database lookups
  - Leaked credential detection
"""

import re
import json
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class SocialRecon:
    """
    Social intelligence and OSINT reconnaissance.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.social")
        self.out_dir = session.dir("recon") / "social"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        pattern = r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(pattern, text)))

    def extract_usernames(self, text: str) -> List[str]:
        """Extract potential usernames from text."""
        patterns = [
            r'@([a-zA-Z0-9_]+)',  # Twitter style
            r'username["\']?\s*[:=]\s*["\']([^"\']+)["\']',  # JSON style
            r'user["\']?\s*[:=]\s*["\']([^"\']+)["\']',  # JSON style
        ]
        usernames = []
        for pattern in patterns:
            usernames.extend(re.findall(pattern, text, re.I))
        return list(set(usernames))

    def linkedin_profiles(self, target: str) -> List[Dict[str, str]]:
        """
        Discover LinkedIn profiles related to target.
        """
        self.logger.info(f"LinkedIn profile search: {target}")
        profiles = []

        # Extract domain for searching
        domain = target.replace("www.", "").split(".")[0] if "." in target else target

        try:
            # Search Google for LinkedIn profiles
            query = f"site:linkedin.com {domain} company"
            url = f"https://www.google.com/search?q={query.replace(' ', '+')}"

            status, headers, content = self.stealth.get(url)

            # Parse results (simplified)
            link_pattern = r'<a[^>]*href=["\'](https://[^"\']+linkedin\.com[^"\']+)["\'][^>]*>'
            for match in re.finditer(link_pattern, content):
                profile_url = match.group(1)
                # Extract name from URL
                name_match = re.search(r'/in/([^/]+)', profile_url)
                if name_match:
                    profiles.append({
                        "url": profile_url,
                        "username": name_match.group(1),
                        "type": "employee"
                    })

                if len(profiles) > 50:
                    break

        except Exception as e:
            self.logger.warning(f"LinkedIn search failed: {e}")

        return profiles

    def github_profiles(self, target: str) -> List[Dict[str, str]]:
        """
        Discover GitHub profiles related to target.
        """
        self.logger.info(f"GitHub profile search: {target}")
        profiles = []

        domain = target.replace("www.", "").split(".")[0] if "." in target else target

        try:
            # Search GitHub for organization
            url = f"https://api.github.com/search/users?q={domain}+type:org"

            status, headers, content = self.stealth.get(url)
            if status == 200:
                data = json.loads(content)
                for user in data.get("items", [])[:20]:
                    profiles.append({
                        "username": user.get("login"),
                        "url": user.get("html_url"),
                        "type": "organization"
                    })

            # Search for users with email domain
            url = f"https://api.github.com/search/users?q=@%40{domain}"
            status, headers, content = self.stealth.get(url)
            if status == 200:
                data = json.loads(content)
                for user in data.get("items", [])[:20]:
                    profiles.append({
                        "username": user.get("login"),
                        "url": user.get("html_url"),
                        "type": "employee"
                    })

        except Exception as e:
            self.logger.warning(f"GitHub search failed: {e}")

        return profiles

    def breach_lookup(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in known breaches.
        """
        self.logger.info(f"Breach lookup: {email}")

        result = {
            "email": email,
            "breaches": [],
            "found": False,
            "source": None
        }

        try:
            # HaveIBeenPwned API (v3)
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"hibp-api-key": ""}  # Optional for v3

            status, headers, content = self.stealth.get(url)

            if status == 200:
                data = json.loads(content)
                for breach in data:
                    result["breaches"].append({
                        "name": breach.get("Name"),
                        "title": breach.get("Title"),
                        "breach_date": breach.get("BreachDate"),
                        "data_classes": breach.get("DataClasses", [])
                    })
                result["found"] = True
                result["source"] = "hibp"

                self.logger.finding(f"Email {email} found in {len(result['breaches'])} breaches", severity="critical")
                self.session.add_finding(Finding(
                    source="recon.social",
                    title=f"Email {email} in breach: {', '.join([b['name'] for b in result['breaches'][:3]])}",
                    severity=SeverityLevel.CRITICAL,
                    host=email,
                    tags=["osint", "breach", "leak", "hibp"],
                    evidence=json.dumps(result["breaches"][:3]),
                    remediation="Change password for all accounts using this email. Enable MFA.",
                ))

        except Exception as e:
            self.logger.debug(f"Breach lookup failed: {e}")

        return result

    def company_employees(self, target: str) -> List[Dict[str, str]]:
        """
        Enumerate company employees via LinkedIn and other sources.
        """
        self.logger.info(f"Employee enumeration: {target}")
        employees = []

        # Use LinkedIn
        linkedin_employees = self.linkedin_profiles(target)
        for emp in linkedin_employees:
            employees.append(emp)

        # Use GitHub
        github_employees = self.github_profiles(target)
        for emp in github_employees:
            employees.append(emp)

        return employees

    def social_media_profiles(self, username: str) -> Dict[str, str]:
        """
        Check social media presence for a username.
        """
        self.logger.info(f"Social media check: {username}")

        platforms = {
            "twitter": f"https://twitter.com/{username}",
            "instagram": f"https://instagram.com/{username}",
            "facebook": f"https://facebook.com/{username}",
            "linkedin": f"https://linkedin.com/in/{username}",
            "github": f"https://github.com/{username}",
            "reddit": f"https://reddit.com/user/{username}",
            "youtube": f"https://youtube.com/@{username}",
            "tiktok": f"https://tiktok.com/@{username}",
        }

        results = {}
        for platform, url in platforms.items():
            try:
                status, headers, content = self.stealth.get(url, timeout=5)
                if status == 200:
                    results[platform] = url
                    self.logger.debug(f"Found {platform} profile: {url}")
            except Exception:
                pass
            self.stealth.sleep(0.5)

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full social intelligence reconnaissance.
        """
        self.logger.banner(f"SOCIAL RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "employees": [],
            "emails": [],
            "breaches": [],
            "social_profiles": {}
        }

        # Extract emails from existing findings
        findings = self.session.get_findings()
        all_text = ""
        for f in findings:
            all_text += f"{f.title} {f.description} {f.evidence}"

        extracted_emails = self.extract_emails(all_text)
        results["emails"] = extracted_emails

        # Also check recon summary
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            try:
                data = json.loads(recon_path.read_text())
                for email in data.get("emails", []):
                    if email not in results["emails"]:
                        results["emails"].append(email)
            except Exception:
                pass

        # Check breaches for each email
        for email in results["emails"][:5]:
            breach_result = self.breach_lookup(email)
            if breach_result["found"]:
                results["breaches"].append(breach_result)

        # Employee enumeration
        results["employees"] = self.company_employees(target)

        # Social profiles from extracted usernames
        usernames = self.extract_usernames(all_text)
        for username in usernames[:10]:
            if username and len(username) > 2:
                results["social_profiles"][username] = self.social_media_profiles(username)

        # Add findings
        if results["employees"]:
            emp_summary = []
            for emp in results["employees"][:10]:
                emp_summary.append(f"{emp.get('username', 'unknown')} ({emp.get('type', 'unknown')})")

            self.session.add_finding(Finding(
                source="recon.social",
                title=f"Employees found: {len(results['employees'])}",
                severity=SeverityLevel.LOW,
                host=target,
                tags=["osint", "employees", "linkedin", "github"],
                evidence=json.dumps(emp_summary),
            ))

        if results["breaches"]:
            self.session.add_finding(Finding(
                source="recon.social",
                title=f"Emails in breaches: {len(results['breaches'])}",
                severity=SeverityLevel.HIGH,
                host=target,
                tags=["osint", "breach", "leak"],
                evidence=json.dumps([b["email"] for b in results["breaches"]]),
                remediation="Rotate credentials immediately. Enable MFA.",
            ))

        # Save results
        report_path = self.out_dir / f"social_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Social recon: emails={len(results['emails'])}, breaches={len(results['breaches'])}, employees={len(results['employees'])}")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]