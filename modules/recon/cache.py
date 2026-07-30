"""
modules/recon/cache.py
──────────────────────
Cache and historical intelligence reconnaissance.

Provides:
  - Wayback Machine snapshots (archive.org)
  - Cached page analysis (Google Cache)
  - Git history extraction
  - Backup file discovery (.bak, .old, .sql, .zip)
  - Misconfigured robots.txt analysis
"""

import re
import json
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class CacheRecon:
    """
    Historical and cached data reconnaissance.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.cache")
        self.out_dir = session.dir("recon") / "cache"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def wayback_machine(self, target: str) -> Dict[str, Any]:
        """
        Query Wayback Machine for historical snapshots.
        """
        self.logger.info(f"Wayback Machine: {target}")

        result = {
            "target": target,
            "snapshots": [],
            "first_seen": None,
            "last_seen": None,
            "total": 0
        }

        try:
            # Get snapshot count
            url = f"https://archive.org/wayback/available?url={target}"

            status, headers, content = self.stealth.get(url)
            if status == 200:
                data = json.loads(content)
                snap = data.get("archived_snapshots", {})
                closest = snap.get("closest", {})
                if closest:
                    result["snapshots"].append({
                        "timestamp": closest.get("timestamp"),
                        "url": closest.get("url"),
                        "status": closest.get("status")
                    })
                    result["first_seen"] = closest.get("timestamp")

            # Get full timeline (CDX API)
            url = f"https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=100"

            status, headers, content = self.stealth.get(url)
            if status == 200:
                data = json.loads(content)
                if len(data) > 1:
                    for entry in data[1:]:  # Skip header
                        timestamp = entry[1] if len(entry) > 1 else None
                        url = entry[2] if len(entry) > 2 else None
                        if timestamp:
                            result["snapshots"].append({
                                "timestamp": timestamp,
                                "url": url
                            })

            result["total"] = len(result["snapshots"])
            if result["snapshots"]:
                result["first_seen"] = result["snapshots"][0]["timestamp"]
                result["last_seen"] = result["snapshots"][-1]["timestamp"]

                self.logger.finding(f"Wayback Machine: {result['total']} snapshots found", severity="info", host=target)
                self.session.add_finding(Finding(
                    source="recon.cache",
                    title=f"Wayback Machine snapshots: {result['total']}",
                    severity=SeverityLevel.INFO,
                    host=target,
                    tags=["wayback", "archive", "historical"],
                    evidence=f"First: {result['first_seen']} | Last: {result['last_seen']}",
                ))

        except Exception as e:
            self.logger.warning(f"Wayback Machine failed: {e}")

        return result

    def robots_txt_analysis(self, url: str) -> Dict[str, Any]:
        """
        Analyze robots.txt for hidden paths and directories.
        """
        self.logger.info(f"robots.txt analysis: {url}")

        result = {
            "url": url,
            "disallowed": [],
            "allowed": [],
            "sitemaps": [],
            "found": False
        }

        try:
            robots_url = url.rstrip("/") + "/robots.txt"
            status, headers, content = self.stealth.get(robots_url)

            if status == 200:
                result["found"] = True
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.lower().startswith("disallow"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            result["disallowed"].append(path)
                    elif line.lower().startswith("allow"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["allowed"].append(path)
                    elif "sitemap" in line.lower():
                        result["sitemaps"].append(line)

                if result["disallowed"]:
                    self.logger.finding(f"robots.txt: {len(result['disallowed'])} disallowed paths", severity="info", host=url)
                    self.session.add_finding(Finding(
                        source="recon.cache",
                        title=f"robots.txt disallowed paths: {len(result['disallowed'])}",
                        severity=SeverityLevel.LOW,
                        host=url,
                        tags=["robots", "disallowed", "directory"],
                        evidence=json.dumps(result["disallowed"][:20]),
                        remediation="Review robots.txt to ensure sensitive paths are not exposed.",
                    ))

        except Exception as e:
            self.logger.warning(f"robots.txt analysis failed: {e}")

        return result

    def sitemap_analysis(self, url: str) -> List[str]:
        """
        Parse sitemap.xml for URLs.
        """
        self.logger.info(f"sitemap.xml analysis: {url}")

        urls = []

        try:
            sitemap_url = url.rstrip("/") + "/sitemap.xml"
            status, headers, content = self.stealth.get(sitemap_url)

            if status == 200:
                # Look for <loc> tags
                loc_pattern = r'<loc>(.*?)</loc>'
                for match in re.finditer(loc_pattern, content, re.I):
                    urls.append(match.group(1))

                # Also check for sitemap index
                sitemap_index_pattern = r'<sitemap>\s*<loc>(.*?)</loc>'
                for match in re.finditer(sitemap_index_pattern, content, re.I):
                    sub_sitemap = match.group(1)
                    try:
                        s_status, s_headers, s_content = self.stealth.get(sub_sitemap)
                        if s_status == 200:
                            for m in re.finditer(loc_pattern, s_content, re.I):
                                urls.append(m.group(1))
                    except Exception:
                        pass

        except Exception as e:
            self.logger.warning(f"sitemap.xml analysis failed: {e}")

        return urls

    def git_discovery(self, url: str) -> Dict[str, Any]:
        """
        Check for exposed .git directory.
        """
        self.logger.info(f"Git discovery: {url}")

        result = {"exposed": False, "files": [], "url": url}

        git_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.git/refs/heads/master",
            "/.git/logs/HEAD",
        ]

        for path in git_paths:
            try:
                test_url = url.rstrip("/") + path
                status, headers, content = self.stealth.get(test_url)

                if status == 200 and content and len(content) > 10:
                    result["exposed"] = True
                    result["files"].append(path)
                    self.logger.finding(f"Exposed .git: {path}", severity="critical", host=url)
                    self.session.add_finding(Finding(
                        source="recon.cache",
                        title=f"Exposed .git directory: {path}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["git", "source-code", "exposure"],
                        evidence=f"Found at {test_url[:100]}",
                        remediation="Remove .git directory from production. Restrict access.",
                    ))
                self.stealth.sleep(0.5)

            except Exception:
                pass

        return result

    def backup_file_discovery(self, url: str) -> List[Dict[str, str]]:
        """
        Discover backup files.
        """
        self.logger.info(f"Backup file discovery: {url}")

        results = []

        backup_patterns = [
            ".bak", ".old", ".backup", ".copy", ".tmp",
            ".swp", ".save", ".orig", ".sql", ".dump",
            ".zip", ".tar.gz", ".tgz", ".rar", ".7z",
            "~", "#", "._", ".log", ".cache"
        ]

        # Common filenames
        common_files = [
            "config", "settings", "credentials", "passwords",
            "database", "backup", "dump", "data", "user",
            "admin", "root", "web.config", ".env", ".env.local"
        ]

        for base in common_files:
            for pattern in backup_patterns:
                filename = f"{base}{pattern}"
                try:
                    test_url = url.rstrip("/") + "/" + filename
                    status, headers, content = self.stealth.get(test_url, timeout=3)

                    if status == 200 and content:
                        results.append({
                            "url": test_url,
                            "filename": filename,
                            "size": len(content),
                            "status": "found"
                        })
                        self.logger.finding(f"Backup file: {filename}", severity="info", host=url)

                except Exception:
                    pass
                self.stealth.sleep(0.2)

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full cache and historical reconnaissance.
        """
        self.logger.banner(f"CACHE RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "wayback": {},
            "robots": {},
            "sitemaps": [],
            "git": {},
            "backup_files": []
        }

        for url in urls[:2]:
            # Wayback Machine
            if not results["wayback"]:
                results["wayback"] = self.wayback_machine(target)

            # robots.txt
            results["robots"] = self.robots_txt_analysis(url)

            # sitemap.xml
            if not results["sitemaps"]:
                results["sitemaps"] = self.sitemap_analysis(url)

            # .git discovery
            if not results["git"]:
                results["git"] = self.git_discovery(url)

            # Backup files (limited)
            if not results["backup_files"]:
                results["backup_files"] = self.backup_file_discovery(url)

        # Save results
        report_path = self.out_dir / f"cache_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Cache recon: snapshots={results['wayback'].get('total', 0)}, backup_files={len(results['backup_files'])}")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]