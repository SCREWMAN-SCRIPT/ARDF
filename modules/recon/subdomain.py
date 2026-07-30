"""
modules/recon/subdomain.py
──────────────────────────
Subdomain enumeration reconnaissance.

Provides:
  - Passive subdomain enumeration (SecurityTrails, crt.sh, C99)
  - Active subdomain bruteforce (massdns, puredns)
  - Permutation-based subdomain discovery
  - Subdomain takeover detection (subjack)
"""

import re
import json
import time
import subprocess
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class SubdomainRecon:
    """
    Subdomain enumeration reconnaissance.
    Passive and active discovery methods.
    """

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.subdomain")
        self.out_dir = session.dir("recon") / "subdomain"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

        # API keys
        self.securitytrails_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.c99_key = os.environ.get("C99_API_KEY", "")

        # Wordlist paths
        self.wordlist_paths = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/wordlists/dnsmap.txt",
        ]

    def passive_enumeration(self, target: str) -> Set[str]:
        """
        Passive subdomain enumeration from public sources.
        """
        self.logger.info(f"Passive subdomain enumeration: {target}")
        subdomains = set()

        # crt.sh
        crtsh_subs = self._crt_sh(target)
        subdomains.update(crtsh_subs)

        # SecurityTrails
        if self.securitytrails_key:
            st_subs = self._securitytrails(target)
            subdomains.update(st_subs)

        # C99 API
        if self.c99_key:
            c99_subs = self._c99(target)
            subdomains.update(c99_subs)

        # Shodan
        if self.shodan_key:
            shodan_subs = self._shodan(target)
            subdomains.update(shodan_subs)

        # CertSpotter (via crt.sh alternative)
        cert_subs = self._certspotter(target)
        subdomains.update(cert_subs)

        self.logger.success(f"Passive enumeration: {len(subdomains)} subdomains")
        return subdomains

    def _crt_sh(self, target: str) -> Set[str]:
        """Fetch subdomains from crt.sh certificate transparency logs."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{target}&output=json"

        try:
            status, headers, content = self.stealth.get(url)
            if status != 200:
                self.logger.warning(f"crt.sh returned {status}")
                return subdomains

            data = json.loads(content)
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(target) and name != target:
                        subdomains.add(name)

            self.logger.debug(f"crt.sh: {len(subdomains)} subdomains")

        except json.JSONDecodeError:
            # crt.sh sometimes returns malformed JSON
            # Try parsing as text
            try:
                status, headers, content = self.stealth.get(url.replace("&output=json", "&output=text"))
                for line in content.splitlines():
                    line = line.strip().lstrip("*.")
                    if line.endswith(target) and line != target:
                        subdomains.add(line)
            except Exception:
                pass
        except Exception as e:
            self.logger.warning(f"crt.sh failed: {e}")

        return subdomains

    def _securitytrails(self, target: str) -> Set[str]:
        """Fetch subdomains from SecurityTrails API."""
        subdomains = set()
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"

        try:
            headers = {"APIKEY": self.securitytrails_key, "Accept": "application/json"}
            status, headers, content = self.stealth.get(url, headers=headers)

            if status != 200:
                self.logger.warning(f"SecurityTrails returned {status}")
                return subdomains

            data = json.loads(content)
            for sub in data.get("subdomains", []):
                fqdn = f"{sub}.{target}"
                subdomains.add(fqdn)

            self.logger.debug(f"SecurityTrails: {len(subdomains)} subdomains")

        except Exception as e:
            self.logger.warning(f"SecurityTrails failed: {e}")

        return subdomains

    def _c99(self, target: str) -> Set[str]:
        """Fetch subdomains from C99 API."""
        subdomains = set()
        url = f"https://api.c99.nl/subdomainfinder?key={self.c99_key}&domain={target}&json"

        try:
            status, headers, content = self.stealth.get(url)
            if status != 200:
                return subdomains

            data = json.loads(content)
            for entry in data.get("subdomains", []):
                sub = entry.get("subdomain", "")
                if sub:
                    fqdn = f"{sub}.{target}"
                    subdomains.add(fqdn)

            self.logger.debug(f"c99: {len(subdomains)} subdomains")

        except Exception as e:
            self.logger.warning(f"c99 failed: {e}")

        return subdomains

    def _shodan(self, target: str) -> Set[str]:
        """Fetch subdomains from Shodan."""
        subdomains = set()
        url = f"https://api.shodan.io/dns/domain/{target}?key={self.shodan_key}"

        try:
            status, headers, content = self.stealth.get(url)
            if status != 200:
                return subdomains

            data = json.loads(content)
            for sub in data.get("subdomains", []):
                fqdn = f"{sub}.{target}"
                subdomains.add(fqdn)

            self.logger.debug(f"Shodan: {len(subdomains)} subdomains")

        except Exception as e:
            self.logger.warning(f"Shodan failed: {e}")

        return subdomains

    def _certspotter(self, target: str) -> Set[str]:
        """Fetch subdomains from CertSpotter."""
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"

        try:
            status, headers, content = self.stealth.get(url)
            if status != 200:
                return subdomains

            data = json.loads(content)
            for entry in data:
                for name in entry.get("dns_names", []):
                    name = name.strip().lstrip("*.")
                    if name.endswith(target) and name != target:
                        subdomains.add(name)

            self.logger.debug(f"CertSpotter: {len(subdomains)} subdomains")

        except Exception as e:
            self.logger.warning(f"CertSpotter failed: {e}")

        return subdomains

    def active_bruteforce(self, target: str, wordlist_path: Optional[str] = None) -> Set[str]:
        """
        Active subdomain bruteforce using wordlist.
        """
        self.logger.info(f"Active subdomain bruteforce: {target}")

        subdomains = set()

        if not wordlist_path:
            for path in self.wordlist_paths:
                if Path(path).exists():
                    wordlist_path = path
                    break

        if not wordlist_path or not Path(wordlist_path).exists():
            self.logger.warning("No wordlist found for subdomain bruteforce")
            return subdomains

        # Use massdns if available
        massdns_available = self._check_tool("massdns")
        puredns_available = self._check_tool("puredns")

        if massdns_available:
            subdomains.update(self._massdns_bruteforce(target, wordlist_path))
        elif puredns_available:
            subdomains.update(self._puredns_bruteforce(target, wordlist_path))
        else:
            # Fallback to simple DNS resolution
            subdomains.update(self._simple_bruteforce(target, wordlist_path))

        self.logger.success(f"Active bruteforce: {len(subdomains)} subdomains")
        return subdomains

    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _massdns_bruteforce(self, target: str, wordlist_path: str) -> Set[str]:
        """Use massdns for subdomain bruteforce."""
        subdomains = set()
        massdns_out = self.out_dir / f"massdns_{_safe(target)}.txt"

        try:
            # Create subdomain list
            subdomains_file = self.out_dir / f"subdomains_{_safe(target)}.txt"
            with open(wordlist_path, "r") as f:
                subs = [f"{line.strip()}.{target}" for line in f if line.strip()][:10000]
            subdomains_file.write_text("\n".join(subs))

            # Run massdns
            cmd = ["massdns", "-r", "/etc/resolv.conf", "-t", "A", "-o", "S", "-w", str(massdns_out), str(subdomains_file)]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if massdns_out.exists():
                for line in massdns_out.read_text().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 1 and parts[0].endswith(target):
                        subdomains.add(parts[0])

        except Exception as e:
            self.logger.warning(f"massdns failed: {e}")

        return subdomains

    def _puredns_bruteforce(self, target: str, wordlist_path: str) -> Set[str]:
        """Use puredns for subdomain bruteforce."""
        subdomains = set()
        puredns_out = self.out_dir / f"puredns_{_safe(target)}.txt"

        try:
            cmd = ["puredns", "bruteforce", wordlist_path, target, "-w", str(puredns_out)]
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if puredns_out.exists():
                for line in puredns_out.read_text().splitlines():
                    if line.strip().endswith(target):
                        subdomains.add(line.strip())

        except Exception as e:
            self.logger.warning(f"puredns failed: {e}")

        return subdomains

    def _simple_bruteforce(self, target: str, wordlist_path: str) -> Set[str]:
        """Simple DNS resolution for subdomain bruteforce."""
        import dns.resolver
        subdomains = set()
        count = 0

        try:
            with open(wordlist_path, "r") as f:
                for line in f:
                    if count > 5000:  # Limit for simple mode
                        break
                    sub = line.strip()
                    if not sub:
                        continue
                    fqdn = f"{sub}.{target}"
                    try:
                        dns.resolver.resolve(fqdn, "A", timeout=2)
                        subdomains.add(fqdn)
                        self.stealth.sleep(0.1)
                        count += 1
                    except Exception:
                        pass

        except Exception as e:
            self.logger.warning(f"Simple bruteforce failed: {e}")

        return subdomains

    def subdomain_takeover(self, subdomains: List[str]) -> List[Dict[str, str]]:
        """
        Check for subdomain takeover vulnerabilities.
        Uses subjack if available.
        """
        self.logger.info(f"Subdomain takeover check: {len(subdomains)} subdomains")

        results = []
        subjack_available = self._check_tool("subjack")

        if subjack_available and subdomains:
            subjack_out = self.out_dir / f"subjack_{_safe(self.session.meta.target)}.txt"
            subs_file = self.out_dir / "subdomains_for_takeover.txt"
            subs_file.write_text("\n".join(subdomains))

            try:
                cmd = ["subjack", "-w", str(subs_file), "-t", "50", "-timeout", "30", "-o", str(subjack_out), "-ssl"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if subjack_out.exists():
                    for line in subjack_out.read_text().splitlines():
                        if "is vulnerable" in line.lower():
                            parts = line.strip().split()
                            results.append({
                                "subdomain": parts[0] if parts else "unknown",
                                "status": "vulnerable",
                                "evidence": line
                            })
                            self.logger.finding(f"Subdomain takeover: {parts[0] if parts else 'unknown'}", severity="high")

            except Exception as e:
                self.logger.warning(f"subjack failed: {e}")

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full subdomain reconnaissance.
        """
        self.logger.banner(f"SUBDOMAIN RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "passive": [],
            "active": [],
            "takeover": [],
            "total": 0
        }

        # Passive enumeration
        passive_subs = self.passive_enumeration(target)
        results["passive"] = list(passive_subs)

        # Active bruteforce
        active_subs = self.active_bruteforce(target)
        results["active"] = list(active_subs)

        # Combine unique subdomains
        all_subs = list(passive_subs | active_subs)
        results["total"] = len(all_subs)

        # Subdomain takeover
        if all_subs:
            results["takeover"] = self.subdomain_takeover(all_subs)

        # Add findings
        for sub in all_subs[:50]:
            self.session.add_finding(Finding(
                source="recon.subdomain",
                title=f"Subdomain discovered: {sub}",
                severity=SeverityLevel.INFO,
                host=sub,
                tags=["subdomain", "enumeration"],
            ))

        if results["takeover"]:
            for t in results["takeover"]:
                self.session.add_finding(Finding(
                    source="recon.subdomain",
                    title=f"Subdomain takeover: {t.get('subdomain', 'unknown')}",
                    severity=SeverityLevel.HIGH,
                    host=t.get("subdomain", target),
                    tags=["takeover", "subjack"],
                    evidence=t.get("evidence", ""),
                    remediation="Remove dangling DNS records or claim the service.",
                ))

        # Save results
        report_path = self.out_dir / f"subdomain_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Subdomain recon: {results['total']} subdomains, {len(results['takeover'])} takeover risks")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]