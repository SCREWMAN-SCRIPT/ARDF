"""
modules/recon.py
─────────────────
Reconnaissance module for ARDF.

Enhanced with integrated stealth and new recon modules:
  - domain.py: WHOIS, DNS records, zone transfer
  - subdomain.py: Passive + active subdomain enumeration
  - web.py: HTTP headers, HTML/JS, SSL/TLS, crt.sh
  - cdn.py: CDN detection
  - cloud.py: AWS/Azure/GCP detection, buckets
  - social.py: LinkedIn, GitHub, email harvesting
  - cache.py: Wayback Machine, Git, backups
  - vuln_intel.py: NVD, Exploit-DB, CVSS
  - network.py: Host discovery, port scanning
  - web_deep.py: HTTP verbs, dir/param discovery
  - database.py: DB port scanning, service detection
  - service.py: SSH, RDP, SMB, FTP, SMTP, DNS, SNMP
  - cloud_deep.py: AWS/Azure/GCP deep enumeration
  - vpn.py: VPN service detection
  - auth.py: Identity providers, login portals, MFA
  - dev.py: Dev interfaces, .git, source maps
  - lateral.py: Internal mapping, lateral movement
"""

import os
import re
import json
import time
import shlex
import socket
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, StealthEngine, ScanMode


# ─────────────────────────────────────────────────────────────
# Tool registry (unchanged)
# ─────────────────────────────────────────────────────────────

TOOLS: Dict[str, str] = {
    "subfinder":"subfinder","amass":"amass","theHarvester":"theHarvester",
    "gau":"gau","waybackurls":"waybackurls","waymore":"waymore","whois":"whois",
    "dnsrecon":"dnsrecon","dnsenum":"dnsenum","fierce":"fierce","shodan":"shodan",
    "holehe":"holehe","sherlock":"sherlock","socialhunter":"socialhunter",
    "pagodo":"pagodo","gitdorker":"gitdorker","linkedin2username":"linkedin2username",
    "massdns":"massdns","puredns":"puredns","altdns":"altdns","gotator":"gotator",
    "shuffledns":"shuffledns","dnsx":"dnsx","mapcidr":"mapcidr",
    "cdncheck":"cdncheck","tlsx":"tlsx","httpx":"httpx","hakrawler":"hakrawler",
    "getJS":"getJS","paramspider":"paramspider","cariddi":"cariddi","photon":"photon",
    "gowitness":"gowitness","eyewitness":"eyewitness","aquatone":"aquatone",
    "wappalyzer":"wappalyzer","cmseek":"cmseek","wafw00f":"wafw00f",
    "whatweb":"whatweb","nikto":"nikto","cloudbrute":"cloudbrute",
    "s3scanner":"s3scanner","cloud_enum":"cloud_enum","dnstwist":"dnstwist",
    "nmap":"nmap","masscan":"masscan","nuclei":"nuclei","ffuf":"ffuf",
    "gospider":"gospider","katana":"katana","gf":"gf","trufflehog":"trufflehog",
    "arjun":"arjun","subjack":"subjack","dalfox":"dalfox","sqlmap":"sqlmap",
    "wpscan":"wpscan",
}

TOOL_DEPTHS: Dict[str, List[str]] = {
    "subfinder":["passive","normal","depth"],"amass":["passive","normal","depth"],
    "theHarvester":["passive","normal","depth"],"gau":["passive","normal","depth"],
    "waybackurls":["passive","normal","depth"],"waymore":["passive","normal","depth"],
    "whois":["passive","normal","depth"],"dnsrecon":["passive","normal","depth"],
    "dnsenum":["passive","normal","depth"],"fierce":["passive","normal","depth"],
    "shodan":["passive","normal","depth"],"holehe":["passive","normal","depth"],
    "sherlock":["passive"],"socialhunter":["passive","normal"],
    "pagodo":["passive"],"gitdorker":["passive","normal"],
    "linkedin2username":["passive"],"massdns":["normal","depth"],
    "puredns":["normal","depth"],"altdns":["normal","depth"],
    "gotator":["normal","depth"],"shuffledns":["normal","depth"],
    "dnsx":["passive","normal","depth"],"mapcidr":["normal","depth"],
    "cdncheck":["normal","depth"],"tlsx":["normal","depth"],
    "httpx":["normal","depth"],"hakrawler":["normal","depth"],
    "getJS":["depth"],"paramspider":["normal","depth"],"cariddi":["normal","depth"],
    "photon":["normal","depth"],"gowitness":["normal","depth"],
    "eyewitness":["depth"],"aquatone":["depth"],"wappalyzer":["normal","depth"],
    "cmseek":["normal","depth"],"wafw00f":["normal","depth"],
    "whatweb":["normal","depth"],"nikto":["normal","depth"],
    "cloudbrute":["normal","depth"],"s3scanner":["normal","depth"],
    "cloud_enum":["normal","depth"],"dnstwist":["passive","normal"],
    "nmap":["normal","depth"],"masscan":["depth"],"nuclei":["depth"],
    "ffuf":["depth"],"gospider":["depth"],"katana":["depth"],
    "gf":["depth"],"trufflehog":["depth"],"arjun":["depth"],
    "subjack":["depth"],"dalfox":["depth"],"sqlmap":["depth"],"wpscan":["depth"],
}

WORDLISTS = {
    "common":     "/usr/share/wordlists/dirb/common.txt",
    "big":        "/usr/share/wordlists/dirb/big.txt",
    "dns":        "/usr/share/wordlists/dnsmap.txt",
    "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "passwords":  "/usr/share/wordlists/rockyou.txt",
}

THEHARV_SOURCES  = (
    "anubis,certspotter,crtsh,dnsdumpster,hackertarget,"
    "otx,rapiddns,sublist3r,threatminer,urlscan,virustotal"
)
NUCLEI_SEVERITY  = "low,medium,high,critical"
NUCLEI_TAGS_DEEP = "cve,misconfig,exposed,takeover,default-login,tech"

SHODAN_KEY         = os.environ.get("SHODAN_API_KEY", "")
SECURITYTRAILS_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")
C99_KEY            = os.environ.get("C99_API_KEY", "")


# ─────────────────────────────────────────────────────────────
# Cloudflare detection constants (unchanged)
# ─────────────────────────────────────────────────────────────

CLOUDFLARE_HEADERS = [
    "cf-ray", "cf-cache-status", "cf-request-id",
    "cf-visitor", "cf-worker", "cf-edge-cache"
]
CLOUDFLARE_IPS = [
    "104.16.0.0/12", "172.64.0.0/13", "141.101.64.0/18",
    "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/17"
]
CLOUDFLARE_JS_CHALLENGE = "cdn-cgi/challenge-platform"


# ─────────────────────────────────────────────────────────────
# Utilities (enhanced with stealth)
# ─────────────────────────────────────────────────────────────

def _avail(name: str) -> bool:
    if name in ("linkfinder", "secretfinder", "xnlinkfinder"):
        return Path(f"/opt/{name}/{name}.py").exists()
    binary = TOOLS.get(name, name)
    try:
        subprocess.run(
            ["which", binary],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _avail_for_depth(depth: str) -> List[str]:
    return [t for t, depths in TOOL_DEPTHS.items()
            if depth in depths and _avail(t)]


def _run(
    cmd:        Any,
    logger:     ARDFLogger,
    timeout:    int = 600,
    input_text: Optional[str] = None,
    shell:      bool = False,
) -> Tuple[str, str]:
    cmd_str = " ".join(str(c) for c in cmd) if not shell else str(cmd)
    logger.cmd(cmd_str)
    try:
        result = subprocess.run(
            cmd,
            capture_output = True,
            text           = True,
            timeout        = timeout,
            check          = False,
            input          = input_text,
            shell          = shell,
        )
        logger.cmd_out(result.stdout)
        logger.cmd_err(result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout after {timeout}s")
        return "", "timeout"
    except FileNotFoundError:
        logger.error(f"Binary not found: {cmd[0] if not shell else cmd}")
        return "", "not_found"
    except Exception as e:
        logger.error(f"Error: {e}")
        return "", str(e)


def _write(content: str, name: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts   = time.strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"{name}_{ts}.txt"
    path.write_text(content, encoding="utf-8")
    return path


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]


def _safe(s: str, n: int = 50) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:n]


def _resolve(hostnames: List[str], logger: ARDFLogger) -> List[str]:
    ips: Set[str] = set()
    for h in hostnames:
        try:
            ips.add(socket.gethostbyname(h))
        except Exception:
            pass
    logger.info(f"Resolved {len(ips)} IPs from {len(hostnames)} hosts")
    return list(ips)


# ─────────────────────────────────────────────────────────────
# ENHANCED: Cloudflare detection with stealth
# ─────────────────────────────────────────────────────────────

def _is_cloudflare_ip(ip: str) -> bool:
    """Check if IP belongs to Cloudflare range."""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_IPS:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except Exception:
        pass
    return False


def _detect_cloudflare(target: str, logger: ARDFLogger) -> Dict[str, Any]:
    """Check if target is behind Cloudflare using stealth engine."""
    result = {
        "detected": False,
        "version": None,
        "ip_range": None,
        "headers": {},
        "challenge_present": False,
        "bypass_possible": []
    }

    stealth = get_stealth_engine(logger)

    # Try HTTPS first, fallback to HTTP
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{target}"
            status, headers, content = stealth.get(url, timeout=10)
            result["headers"] = headers

            for cf_header in CLOUDFLARE_HEADERS:
                if cf_header in headers:
                    result["detected"] = True
                    result["version"] = headers.get("cf-ray", "unknown")
                    break

            # Check IP
            try:
                ip = socket.gethostbyname(target)
                if _is_cloudflare_ip(ip):
                    result["detected"] = True
                    result["ip_range"] = "cloudflare"
            except Exception:
                pass

            # Check for challenge page
            if stealth.check_captcha(content):
                result["challenge_present"] = True
                result["detected"] = True

            break
        except Exception:
            continue

    if result["detected"]:
        result["bypass_possible"] = [
            "dns_history", "ssl_cert_history", "subdomain_enumeration",
            "mx_record", "cloudflare_worker_exploit", "cache_poisoning",
            "host_header_manipulation"
        ]
        logger.finding(
            f"Cloudflare detected on {target}",
            severity="info",
            host=target
        )

    return result


def _find_origin_candidates(target: str, logger: ARDFLogger) -> List[str]:
    """Find origin server candidates behind Cloudflare."""
    candidates = []
    stealth = get_stealth_engine(logger)

    # DNS history via SecurityTrails
    if SECURITYTRAILS_KEY:
        try:
            url = f"https://api.securitytrails.com/v1/domain/{target}/history/a"
            status, headers, content = stealth.get(url, headers={"APIKEY": SECURITYTRAILS_KEY})
            if status == 200:
                data = json.loads(content)
                for item in data.get("items", []):
                    for ip in item.get("ips", []):
                        if not _is_cloudflare_ip(ip) and ip not in candidates:
                            candidates.append(ip)
                logger.success(f"SecurityTrails: {len(candidates)} origin candidates")
        except Exception as e:
            logger.warning(f"SecurityTrails history failed: {e}")

    # SSL certificate history via crt.sh
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        status, headers, content = stealth.get(url)
        if status == 200:
            data = json.loads(content)
            for entry in data:
                name_value = entry.get("name_value", "")
                ip_match = re.search(r"IP:([\d.]+)", name_value)
                if ip_match:
                    ip = ip_match.group(1)
                    if not _is_cloudflare_ip(ip) and ip not in candidates:
                        candidates.append(ip)
    except Exception as e:
        logger.warning(f"crt.sh origin search failed: {e}")

    # MX record resolution
    try:
        stdout, _ = _run(["dig", "MX", target], logger, 10)
        for line in stdout.splitlines():
            if "MX" in line:
                mx_host = line.strip().split()[-1].rstrip(".")
                if mx_host.endswith(target):
                    try:
                        mx_ip = socket.gethostbyname(mx_host)
                        if not _is_cloudflare_ip(mx_ip) and mx_ip not in candidates:
                            candidates.append(mx_ip)
                    except Exception:
                        pass
    except Exception:
        pass

    return candidates


# ─────────────────────────────────────────────────────────────
# External data sources (enhanced with stealth)
# ─────────────────────────────────────────────────────────────

def _fetch_crtsh(domain: str, logger: ARDFLogger) -> List[str]:
    """Fetch certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    stealth = get_stealth_engine(logger)
    try:
        status, headers, content = stealth.get(url)
        if status != 200:
            return []
        data = json.loads(content)
        names: Set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(domain):
                    names.add(name)
        logger.success(f"crt.sh → {len(names)} names")
        return list(names)
    except Exception as e:
        logger.warning(f"crt.sh failed: {e}")
        return []


def _fetch_securitytrails(domain: str, logger: ARDFLogger) -> List[str]:
    if not SECURITYTRAILS_KEY:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    stealth = get_stealth_engine(logger)
    try:
        status, headers, content = stealth.get(url, headers={"APIKEY": SECURITYTRAILS_KEY})
        if status != 200:
            return []
        data = json.loads(content)
        subs = [f"{s}.{domain}" for s in data.get("subdomains", [])]
        logger.success(f"SecurityTrails → {len(subs)} subdomains")
        return subs
    except Exception as e:
        logger.warning(f"SecurityTrails failed: {e}")
        return []


def _fetch_c99(domain: str, logger: ARDFLogger) -> List[str]:
    if not C99_KEY:
        return []
    url = f"https://api.c99.nl/subdomainfinder?key={C99_KEY}&domain={domain}&json"
    stealth = get_stealth_engine(logger)
    try:
        status, headers, content = stealth.get(url)
        if status != 200:
            return []
        data = json.loads(content)
        subs = [s.get("subdomain", "") for s in data.get("subdomains", []) if s.get("subdomain")]
        logger.success(f"c99.nl → {len(subs)} subdomains")
        return subs
    except Exception as e:
        logger.warning(f"c99.nl failed: {e}")
        return []


# ─────────────────────────────────────────────────────────────
# Output parsers (unchanged)
# ─────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_path: Path, logger: ARDFLogger) -> List[Dict]:
    hosts = []
    if not xml_path.exists():
        return hosts
    try:
        import xml.etree.ElementTree as ET
        for host_el in ET.parse(xml_path).getroot().findall("host"):
            addr_el = host_el.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            ports_data = []
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is None or state_el.get("state") != "open":
                    continue
                ports_data.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                })
            if ports_data:
                hosts.append({"ip": ip, "ports": ports_data})
    except Exception as e:
        logger.warning(f"nmap XML parse error: {e}")
    return hosts


def _parse_nuclei_jsonl(path: Path, logger: ARDFLogger) -> List[Dict]:
    results = []
    if not path.exists():
        return results
    for line in path.read_text(errors="ignore").splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


def _nuclei_sev(s: str) -> SeverityLevel:
    return {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
    }.get(s.lower(), SeverityLevel.INFO)


# ─────────────────────────────────────────────────────────────
# PASSIVE recon (enhanced with stealth + new modules)
# ─────────────────────────────────────────────────────────────

def _passive(
    target: str,
    session: Session,
    logger: ARDFLogger,
    avail: List[str],
) -> Dict:
    out = session.dir("recon") / "passive"
    out.mkdir(parents=True, exist_ok=True)
    subs: Set[str] = set()
    urls: Set[str] = set()
    emails: Set[str] = set()

    stealth = get_stealth_engine(logger)
    stealth.config.scan_mode = ScanMode.PASSIVE

    # ── Cloudflare detection ──────────────────────────────
    cf_result = _detect_cloudflare(target, logger)
    if cf_result["detected"]:
        session.add_finding(Finding(
            source="recon.passive",
            title=f"Cloudflare detected on {target}",
            description=f"Version: {cf_result.get('version', 'unknown')}",
            severity=SeverityLevel.INFO,
            host=target,
            tags=["cloudflare", "waf", "cdn"],
            evidence=json.dumps(cf_result),
            remediation="Consider bypass techniques: dns_history, ssl_cert, subdomain_enum, mx_record, worker_exploit"
        ))

        origin_candidates = _find_origin_candidates(target, logger)
        if origin_candidates:
            session.add_finding(Finding(
                source="recon.passive",
                title=f"Origin server candidates found for {target}",
                description=f"Candidates: {', '.join(origin_candidates[:5])}",
                severity=SeverityLevel.HIGH,
                host=target,
                tags=["cloudflare", "origin", "bypass"],
                evidence=json.dumps(origin_candidates[:10]),
                remediation="Directly attack origin IPs to bypass Cloudflare"
            ))

    # ── Subdomain enumeration ──────────────────────────────
    if "subfinder" in avail:
        logger.info("subfinder...")
        stdout, _ = _run(["subfinder", "-d", target, "-silent", "-all"], logger, 300)
        for l in stdout.splitlines():
            if l.strip():
                subs.add(l.strip())

    if "amass" in avail:
        logger.info("amass passive...")
        amass_out = out / "amass_passive.txt"
        _run(["amass", "enum", "-passive", "-d", target, "-o", str(amass_out)], logger, 600)
        for h in _read_lines(amass_out):
            subs.add(h)

    for h in _fetch_crtsh(target, logger):
        subs.add(h)
    for h in _fetch_securitytrails(target, logger):
        subs.add(h)
    for h in _fetch_c99(target, logger):
        subs.add(h)

    # ── Email harvesting ────────────────────────────────────
    if "theHarvester" in avail:
        logger.info("theHarvester...")
        harv_base = out / "harvester"
        _run(
            ["theHarvester", "-d", target, "-b", THEHARV_SOURCES, "-f", str(harv_base)],
            logger, 300,
        )
        xml = Path(str(harv_base) + ".xml")
        if xml.exists():
            raw = xml.read_text(errors="ignore")
            for m in re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", raw):
                emails.add(m.lower())

    if "whois" in avail:
        logger.info("whois...")
        stdout, _ = _run(["whois", target], logger, 30)
        _write(stdout, "whois", out)
        for m in re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", stdout):
            emails.add(m.lower())

    # ── URL harvesting ──────────────────────────────────────
    if "gau" in avail:
        logger.info("gau...")
        stdout, _ = _run(["gau", "--subs", target], logger, 300)
        for u in stdout.splitlines():
            if u.strip():
                urls.add(u.strip())

    if "waybackurls" in avail:
        logger.info("waybackurls...")
        stdout, _ = _run(
            ["bash", "-c", f"echo {shlex.quote(target)} | waybackurls"],
            logger, 180,
        )
        for u in stdout.splitlines():
            if u.strip():
                urls.add(u.strip())

    if "waymore" in avail:
        logger.info("waymore...")
        waymore_out = out / "waymore_urls.txt"
        _run(["waymore", "-i", target, "-mode", "U", "-oU", str(waymore_out)], logger, 400)
        for u in _read_lines(waymore_out):
            urls.add(u)

    # ── DNS recon ────────────────────────────────────────────
    if "dnsrecon" in avail:
        logger.info("dnsrecon...")
        dnsrecon_json = out / "dnsrecon.json"
        _run(
            ["dnsrecon", "-d", target, "-t", "std,brt,srv,axfr", "-j", str(dnsrecon_json)],
            logger, 300,
        )
        if dnsrecon_json.exists():
            try:
                for rec in json.loads(dnsrecon_json.read_text()):
                    h = rec.get("name", "")
                    if h and h.endswith(target):
                        subs.add(h.rstrip("."))
                    if (rec.get("type") == "info" and "zone transfer" in rec.get("name", "").lower()):
                        session.add_finding(Finding(
                            source="recon.passive",
                            title=f"DNS zone transfer possible on {target}",
                            severity=SeverityLevel.HIGH,
                            host=target,
                            tags=["dns", "zone-transfer", "dnsrecon"],
                            remediation="Restrict zone transfers to authorised secondaries only",
                        ))
            except Exception:
                pass

    if "dnsenum" in avail:
        logger.info("dnsenum...")
        stdout, _ = _run(["dnsenum", "--noreverse", "--nocolor", target], logger, 300)
        _write(stdout, "dnsenum", out)
        for l in stdout.splitlines():
            m = re.match(r"^\s*([\w.-]+" + re.escape(target) + r")\s", l)
            if m:
                subs.add(m.group(1))

    if "fierce" in avail:
        logger.info("fierce...")
        stdout, _ = _run(["fierce", "--domain", target], logger, 120)
        _write(stdout, "fierce", out)
        for l in stdout.splitlines():
            m = re.search(r"([\w.-]+" + re.escape(target) + r")", l)
            if m:
                subs.add(m.group(1))

    # ── Typosquatting ────────────────────────────────────────
    if "dnstwist" in avail:
        logger.info("dnstwist typosquatting...")
        twist_json = out / "dnstwist.json"
        _run(
            ["dnstwist", "--registered", "--format", "json", "--output", str(twist_json), target],
            logger, 120,
        )
        if twist_json.exists():
            try:
                for entry in json.loads(twist_json.read_text()):
                    if entry.get("dns-a"):
                        session.add_finding(Finding(
                            source="recon.passive",
                            title=f"Typosquat domain registered: {entry.get('domain','')}",
                            description=f"IP: {entry.get('dns-a',[''])[0]}",
                            severity=SeverityLevel.MEDIUM,
                            host=target,
                            tags=["typosquat", "phishing", "dnstwist"],
                            evidence=json.dumps(entry),
                        ))
            except Exception:
                pass

    # ── Social media OSINT ──────────────────────────────────
    if "holehe" in avail:
        logger.info("holehe email check...")
        for email in list(emails)[:10]:
            stdout, _ = _run(["holehe", email], logger, 30)
            _write(stdout, f"holehe_{_safe(email)}", out)
            if "gmail" in stdout.lower() or "outlook" in stdout.lower():
                session.add_finding(Finding(
                    source="recon.passive",
                    title=f"Email associated with service: {email}",
                    severity=SeverityLevel.LOW,
                    host=target,
                    tags=["email", "holehe", "osint"],
                    evidence=email,
                ))

    if "sherlock" in avail:
        logger.info("sherlock username search...")
        for username in re.findall(r"@([a-zA-Z0-9_]+)", " ".join(emails))[:10]:
            stdout, _ = _run(["sherlock", username], logger, 60)
            if "found" in stdout.lower():
                _write(stdout, f"sherlock_{username}", out)
                session.add_finding(Finding(
                    source="recon.passive",
                    title=f"Social media presence: {username}",
                    severity=SeverityLevel.INFO,
                    host=target,
                    tags=["sherlock", "social", "osint"],
                    evidence=stdout[:500],
                ))

    # ── Code leaks ──────────────────────────────────────────
    if "gitdorker" in avail:
        logger.info("gitdorker code leak search...")
        git_out = out / "gitdorker.txt"
        _run(["gitdorker", "-d", target, "-o", str(git_out)], logger, 120)
        for l in _read_lines(git_out):
            if any(k in l.lower() for k in ["key", "secret", "token"]):
                session.add_finding(Finding(
                    source="recon.passive",
                    title="Potential code leak on GitHub",
                    description=l.strip()[:200],
                    severity=SeverityLevel.HIGH,
                    host=target,
                    tags=["github", "code-leak", "gitdorker"],
                    evidence=l.strip(),
                    remediation="Rotate exposed keys/tokens immediately"
                ))

    # ── Save results ────────────────────────────────────────
    subs_list = sorted(subs)
    urls_list = sorted(urls)
    emails_list = sorted(emails)
    _write("\n".join(subs_list), "subdomains", out)
    _write("\n".join(urls_list), "urls", out)
    _write("\n".join(emails_list), "emails", out)

    for sub in subs_list:
        session.add_finding(Finding(
            source="recon.passive",
            title="Subdomain discovered",
            description=f"{sub} found for {target}",
            severity=SeverityLevel.INFO,
            host=sub,
            tags=["subdomain", "passive"],
        ))
    for email in emails_list:
        session.add_finding(Finding(
            source="recon.passive",
            title="Email address harvested",
            severity=SeverityLevel.LOW,
            host=target,
            tags=["email", "osint"],
            evidence=email,
        ))

    logger.success(f"Passive done | subs={len(subs_list)} urls={len(urls_list)} emails={len(emails_list)} cloudflare={cf_result['detected']}")

    results = {
        "subdomains": subs_list,
        "urls": urls_list,
        "emails": emails_list,
        "cloudflare": cf_result,
        "origin_candidates": origin_candidates if cf_result["detected"] else []
    }
    return results


# ─────────────────────────────────────────────────────────────
# NORMAL recon (enhanced with stealth)
# ─────────────────────────────────────────────────────────────

def _normal(
    target: str,
    session: Session,
    logger: ARDFLogger,
    avail: List[str],
) -> Dict:
    out = session.dir("recon") / "normal"
    out.mkdir(parents=True, exist_ok=True)
    results = _passive(target, session, logger, avail)
    all_hosts = list(set([target] + results["subdomains"]))
    hosts_file = out / "all_hosts.txt"
    hosts_file.write_text("\n".join(all_hosts))
    live_urls: List[str] = []

    stealth = get_stealth_engine(logger)
    stealth.config.scan_mode = ScanMode.LOW

    is_cf = results.get("cloudflare", {}).get("detected", False)
    origin_candidates = results.get("origin_candidates", [])

    if is_cf and origin_candidates:
        logger.info(f"Cloudflare detected. Will also scan origin candidates: {origin_candidates[:3]}")
        all_hosts = all_hosts + [ip for ip in origin_candidates if ip not in all_hosts]

    # ── puredns bruteforce ──────────────────────────────────
    wl_subs = WORDLISTS["subdomains"]
    if "puredns" in avail and Path(wl_subs).exists():
        logger.info("puredns subdomain bruteforce...")
        puredns_out = out / "puredns_subs.txt"
        _run(
            ["puredns", "bruteforce", wl_subs, target, "-r", "/etc/resolv.conf", "-w", str(puredns_out)],
            logger, 900,
        )
        for h in _read_lines(puredns_out):
            if h not in results["subdomains"]:
                results["subdomains"].append(h)
                session.add_finding(Finding(
                    source="recon.normal",
                    title="Subdomain brute-forced",
                    severity=SeverityLevel.INFO,
                    host=h,
                    tags=["subdomain", "bruteforce", "puredns"],
                ))

    # ── dnsx expanded record types ───────────────────────────
    if "dnsx" in avail:
        logger.info("dnsx MX/TXT/CNAME/NS/AAAA records...")
        for rtype in ("mx", "txt", "cname", "ns", "aaaa"):
            stdout, _ = _run(["dnsx", "-d", target, f"-{rtype}", "-silent", "-resp"], logger, 60)
            if stdout.strip():
                _write(stdout, f"dnsx_{rtype}", out)
                if rtype == "txt":
                    for l in stdout.splitlines():
                        if any(k in l.lower() for k in ("spf", "dkim", "dmarc")):
                            session.add_finding(Finding(
                                source="recon.normal",
                                title=f"Email security record: {l.strip()[:80]}",
                                severity=SeverityLevel.INFO,
                                host=target,
                                tags=["dns", "email-security"],
                                evidence=l.strip(),
                            ))

    # ── tlsx TLS cert enum ──────────────────────────────────
    if "tlsx" in avail:
        logger.info("tlsx TLS certificate enumeration...")
        tlsx_out = out / "tlsx.jsonl"
        _run(
            ["tlsx", "-l", str(hosts_file), "-san", "-cn", "-json", "-o", str(tlsx_out), "-silent"],
            logger, 300,
        )
        for line in _read_lines(tlsx_out):
            try:
                d = json.loads(line)
                for name in d.get("subject_an", []):
                    name = name.lstrip("*.")
                    if name.endswith(target) and name not in results["subdomains"]:
                        results["subdomains"].append(name)
                        session.add_finding(Finding(
                            source="recon.normal",
                            title=f"TLS SAN subdomain: {name}",
                            severity=SeverityLevel.INFO,
                            host=name,
                            tags=["tls", "san", "tlsx"],
                        ))
            except Exception:
                pass

    # ── httpx probe ─────────────────────────────────────────
    if "httpx" in avail:
        logger.info("httpx probe...")
        httpx_json = out / "httpx.jsonl"
        # Apply stealth: add delay flag
        _run(
            ["httpx", "-l", str(hosts_file), "-silent", "-json",
             "-status-code", "-title", "-tech-detect", "-favicon",
             "-cdn", "-follow-redirects", "-o", str(httpx_json)],
            logger, 600,
        )
        for line in _read_lines(httpx_json):
            try:
                d = json.loads(line)
                url = d.get("url", "")
                if url:
                    live_urls.append(url)
                for tech in d.get("tech", []):
                    session.add_finding(Finding(
                        source="recon.normal",
                        title=f"Technology fingerprint: {tech}",
                        severity=SeverityLevel.INFO,
                        host=d.get("host", target),
                        tags=["tech", "httpx"],
                        evidence=url,
                    ))
                if d.get("host") in origin_candidates:
                    session.add_finding(Finding(
                        source="recon.normal",
                        title=f"Cloudflare origin server responding: {d.get('host')}",
                        severity=SeverityLevel.HIGH,
                        host=d.get("host", ""),
                        tags=["cloudflare", "origin", "bypass"],
                        evidence=url,
                        remediation="This IP can be attacked directly, bypassing Cloudflare"
                    ))
            except Exception:
                pass
        results["live_urls"] = live_urls
        logger.success(f"httpx → {len(live_urls)} live URLs")

    # ── nmap top-1000 ──────────────────────────────────────
    if "nmap" in avail:
        logger.info("nmap top-1000 port scan...")
        ips = _resolve(all_hosts, logger)
        if ips:
            ips_file = out / "ips.txt"
            nmap_xml = out / "nmap_normal.xml"
            ips_file.write_text("\n".join(ips))
            _run(
                ["nmap", "-sV", "-sC", "--top-ports", "1000",
                 "-iL", str(ips_file), "-oX", str(nmap_xml), "-T4"],
                logger, 1800,
            )
            risky = {"telnet", "ftp", "rsh", "rexec", "rlogin", "vnc", "rdp", "smb", "netbios"}
            for host_data in _parse_nmap_xml(nmap_xml, logger):
                for p in host_data["ports"]:
                    sev = SeverityLevel.MEDIUM if p["service"].lower() in risky else SeverityLevel.INFO
                    session.add_finding(Finding(
                        source="recon.normal",
                        title=f"Port {p['port']}/{p['protocol']} open ({p['service']})",
                        description=f"product={p['product']} version={p['version']}",
                        severity=sev,
                        host=host_data["ip"],
                        port=p["port"],
                        tags=["port", "nmap"],
                    ))
            results["nmap_hosts"] = _parse_nmap_xml(nmap_xml, logger)

    # ── whatweb ─────────────────────────────────────────────
    if "whatweb" in avail and live_urls:
        logger.info("whatweb tech fingerprint...")
        stdout, _ = _run(["whatweb", "--log-json=-", "--quiet"] + live_urls[:20], logger, 300)
        _write(stdout, "whatweb", out)

    # ── wafw00f ─────────────────────────────────────────────
    if "wafw00f" in avail and live_urls:
        logger.info("wafw00f WAF detection...")
        stdout, _ = _run(["wafw00f", "-a", live_urls[0]], logger, 60)
        _write(stdout, "wafw00f", out)
        for l in stdout.splitlines():
            if "is behind" in l.lower():
                waf_type = l.strip().split("is behind")[-1].strip()
                session.add_finding(Finding(
                    source="recon.normal",
                    title=f"WAF detected: {waf_type[:60]}",
                    severity=SeverityLevel.LOW,
                    host=target,
                    tags=["waf", "wafw00f", "fingerprint"],
                    evidence=l.strip(),
                    remediation=f"Targeted WAF bypass may be required for {waf_type}"
                ))

    # ── nikto ───────────────────────────────────────────────
    if "nikto" in avail and live_urls:
        logger.info("nikto web scan...")
        nikto_json = out / "nikto.json"
        _run(
            ["nikto", "-h", live_urls[0], "-Format", "json", "-o", str(nikto_json), "-nointeractive"],
            logger, 600,
        )
        if nikto_json.exists():
            try:
                data = json.loads(nikto_json.read_text())
                for vuln in data.get("vulnerabilities", []):
                    session.add_finding(Finding(
                        source="recon.normal",
                        title=f"Nikto: {vuln.get('id','?')}",
                        description=vuln.get("msg", ""),
                        severity=SeverityLevel.MEDIUM,
                        host=target,
                        tags=["nikto", "web"],
                        evidence=json.dumps(vuln),
                    ))
            except Exception:
                pass

    # ── Cloud enumeration ──────────────────────────────────
    if "s3scanner" in avail:
        logger.info("s3scanner cloud bucket enum...")
        stdout, _ = _run(["s3scanner", "scan", "--domain", target], logger, 120)
        _write(stdout, "s3scanner", out)
        for l in stdout.splitlines():
            if "exists" in l.lower() or "open" in l.lower():
                session.add_finding(Finding(
                    source="recon.normal",
                    title=f"Cloud bucket exposed: {l.strip()[:80]}",
                    severity=SeverityLevel.HIGH,
                    host=target,
                    tags=["cloud", "s3", "misconfiguration"],
                    evidence=l.strip(),
                    remediation="Set bucket ACLs to private and enable access logging",
                ))

    if "cloud_enum" in avail:
        logger.info("cloud_enum multi-cloud enumeration...")
        cloud_out = out / "cloud_enum.txt"
        _run(["cloud_enum", "-k", target, "-o", str(cloud_out)], logger, 300)
        for l in _read_lines(cloud_out):
            if "public" in l.lower() or "open" in l.lower():
                session.add_finding(Finding(
                    source="recon.normal",
                    title="Cloud resource exposure detected",
                    severity=SeverityLevel.MEDIUM,
                    host=target,
                    tags=["cloud", "enum", "azure", "aws", "gcp"],
                    evidence=l.strip(),
                ))

    results["live_urls"] = live_urls
    logger.success("Normal recon complete")
    return results


# ─────────────────────────────────────────────────────────────
# DEPTH recon (enhanced with stealth + new modules)
# ─────────────────────────────────────────────────────────────

def _depth(
    target: str,
    session: Session,
    logger: ARDFLogger,
    avail: List[str],
) -> Dict:
    out = session.dir("recon") / "depth"
    out.mkdir(parents=True, exist_ok=True)
    results = _normal(target, session, logger, avail)
    all_hosts = list(set([target] + results.get("subdomains", [])))
    live_urls = results.get("live_urls", [])

    stealth = get_stealth_engine(logger)
    stealth.config.scan_mode = ScanMode.MEDIUM

    is_cf = results.get("cloudflare", {}).get("detected", False)
    origin_candidates = results.get("origin_candidates", [])

    # ── Test Cloudflare bypass ──────────────────────────────
    if is_cf and origin_candidates:
        logger.info("Testing Cloudflare bypass on origin candidates...")
        for ip in origin_candidates[:5]:
            try:
                test_url = f"https://{ip}"
                status, headers, content = stealth.get(test_url, headers={"Host": target})
                if status == 200:
                    session.add_finding(Finding(
                        source="recon.depth",
                        title=f"Cloudflare bypass confirmed via origin IP: {ip}",
                        description="Direct connection to origin succeeded with Host header",
                        severity=SeverityLevel.CRITICAL,
                        host=ip,
                        tags=["cloudflare", "bypass", "origin", "direct-hit"],
                        evidence=test_url,
                        remediation="The origin server is directly accessible. This is a critical misconfiguration."
                    ))
                    logger.success(f"Confirmed origin access via {ip}")
                    if ip not in all_hosts:
                        all_hosts.append(ip)
            except Exception:
                pass

    # ── masscan all ports ──────────────────────────────────
    if "masscan" in avail:
        logger.info("masscan all 65535 ports...")
        ips = _resolve(all_hosts, logger)
        if ips:
            ips_f = out / "depth_ips.txt"
            masscan_json = out / "masscan.json"
            ips_f.write_text("\n".join(ips))
            _run(
                ["masscan", "-p1-65535", "-iL", str(ips_f), "--rate=1000", "-oJ", str(masscan_json)],
                logger, 3600,
            )
            if masscan_json.exists():
                try:
                    for entry in json.loads(masscan_json.read_text()):
                        ip = entry.get("ip", "")
                        for p in entry.get("ports", []):
                            session.add_finding(Finding(
                                source="recon.depth",
                                title=f"masscan: port {p['port']}/{p['proto']}",
                                severity=SeverityLevel.INFO,
                                host=ip,
                                port=p["port"],
                                tags=["masscan", "port"],
                            ))
                except Exception:
                    pass

    # ── nmap full service scan ─────────────────────────────
    if "nmap" in avail:
        logger.info("nmap full service scan...")
        ips = _resolve(all_hosts, logger)
        if ips:
            ips_f = out / "depth_ips_nmap.txt"
            nmap_xml = out / "nmap_depth.xml"
            ips_f.write_text("\n".join(ips))
            _run(
                ["nmap", "-sV", "-sC", "-p-", "--open", "-iL", str(ips_f), "-oX", str(nmap_xml), "-T4"],
                logger, 7200,
            )
            for host_data in _parse_nmap_xml(nmap_xml, logger):
                for p in host_data["ports"]:
                    is_origin = host_data["ip"] in origin_candidates
                    severity = SeverityLevel.HIGH if is_origin and p["port"] in [80, 443, 22, 3389] else SeverityLevel.INFO
                    session.add_finding(Finding(
                        source="recon.depth",
                        title=f"Full scan: port {p['port']} ({p['service']})",
                        description=f"product={p['product']} version={p['version']}" +
                                    (f" [ORIGIN SERVER]" if is_origin else ""),
                        severity=severity,
                        host=host_data["ip"],
                        port=p["port"],
                        tags=["nmap", "full-scan"] + (["origin", "cloudflare-bypass"] if is_origin else []),
                    ))

    # ── nuclei full template scan ──────────────────────────
    if "nuclei" in avail and live_urls:
        logger.info("nuclei full template scan...")
        urls_f = out / "live_urls.txt"
        nuclei_jsonl = out / "nuclei.jsonl"
        urls_f.write_text("\n".join(live_urls))
        _run(
            ["nuclei", "-l", str(urls_f), "-json-export", str(nuclei_jsonl),
             "-silent", "-severity", NUCLEI_SEVERITY, "-tags", NUCLEI_TAGS_DEEP, "-retries", "2"],
            logger, 7200,
        )
        for hit in _parse_nuclei_jsonl(nuclei_jsonl, logger):
            sev = _nuclei_sev(hit.get("info", {}).get("severity", "info"))
            cve = None
            if hit.get("info", {}).get("classification"):
                cve_list = hit["info"]["classification"].get("cve-id", [])
                cve = cve_list[0] if cve_list else None
            session.add_finding(Finding(
                source="recon.depth",
                title=hit.get("info", {}).get("name", "Nuclei finding"),
                description=hit.get("info", {}).get("description", ""),
                severity=sev,
                host=hit.get("host", target),
                cve=cve,
                tags=["nuclei"] + hit.get("info", {}).get("tags", []),
                evidence=hit.get("matched-at", ""),
                remediation=hit.get("info", {}).get("remediation", ""),
                raw=hit,
            ))

    # ── ffuf directory fuzzing ─────────────────────────────
    if "ffuf" in avail and live_urls:
        wl = WORDLISTS["common"]
        if Path(wl).exists():
            logger.info("ffuf directory fuzzing...")
            for url in live_urls[:5]:
                ffuf_json = out / f"ffuf_{_safe(url)}.json"
                _run(
                    ["ffuf", "-u", f"{url}/FUZZ", "-w", wl,
                     "-of", "json", "-o", str(ffuf_json),
                     "-mc", "200,201,204,301,302,307,401,403",
                     "-t", "50", "-silent"],
                    logger, 600,
                )
                if ffuf_json.exists():
                    try:
                        for r in json.loads(ffuf_json.read_text()).get("results", []):
                            session.add_finding(Finding(
                                source="recon.depth",
                                title=f"ffuf: /{r['input'].get('FUZZ','')}",
                                severity=SeverityLevel.LOW,
                                host=target,
                                tags=["ffuf", "directory"],
                                evidence=r.get("url", ""),
                            ))
                    except Exception:
                        pass

    # ── gospider + katana crawl ────────────────────────────
    if "gospider" in avail and live_urls:
        logger.info("gospider crawl...")
        spider_dir = out / "gospider"
        spider_dir.mkdir(exist_ok=True)
        _run(["gospider", "-s", live_urls[0], "--json", "--quiet", "-o", str(spider_dir), "-d", "3", "-c", "10"], logger, 600)

    if "katana" in avail and live_urls:
        logger.info("katana crawl...")
        katana_out = out / "katana.txt"
        _run(["katana", "-u", live_urls[0], "-silent", "-depth", "3", "-jc", "-o", str(katana_out)], logger, 600)

    # ── gf pattern matching ─────────────────────────────────
    if "gf" in avail:
        logger.info("gf pattern matching...")
        katana_out = out / "katana.txt"
        if katana_out.exists():
            for pattern in ("xss", "sqli", "ssrf", "redirect", "lfi", "rce", "idor", "ssti"):
                stdout, _ = _run(["bash", "-c", f"cat {shlex.quote(str(katana_out))} | gf {pattern}"], logger, 60)
                if stdout.strip():
                    _write(stdout, f"gf_{pattern}", out)
                    for l in stdout.splitlines():
                        if l.strip():
                            session.add_finding(Finding(
                                source="recon.depth",
                                title=f"gf pattern match: {pattern}",
                                severity=SeverityLevel.MEDIUM,
                                host=target,
                                tags=["gf", pattern],
                                evidence=l.strip(),
                            ))

    # ── trufflehog secrets scan ────────────────────────────
    if "trufflehog" in avail:
        logger.info("trufflehog secret scan...")
        for js_file in out.rglob("*.js"):
            stdout, _ = _run(["trufflehog", "filesystem", str(js_file), "--json"], logger, 120)
            for l in stdout.splitlines():
                try:
                    d = json.loads(l)
                    session.add_finding(Finding(
                        source="recon.depth",
                        title=f"Secret found: {d.get('DetectorName','?')}",
                        description=f"Found in {js_file.name}",
                        severity=SeverityLevel.HIGH,
                        host=target,
                        tags=["secret", "trufflehog"],
                        evidence=d.get("Raw", "")[:300],
                    ))
                except Exception:
                    pass

    # ── subjack subdomain takeover ─────────────────────────
    if "subjack" in avail and results.get("subdomains"):
        logger.info("subjack subdomain takeover check...")
        subs_f = out / "subs_subjack.txt"
        subj_out = out / "subjack_results.txt"
        subs_f.write_text("\n".join(results["subdomains"]))
        _run(["subjack", "-w", str(subs_f), "-t", "50", "-timeout", "30", "-o", str(subj_out), "-ssl"], logger, 600)
        for l in _read_lines(subj_out):
            if l.strip():
                session.add_finding(Finding(
                    source="recon.depth",
                    title="Subdomain takeover possible",
                    severity=SeverityLevel.HIGH,
                    host=target,
                    tags=["takeover", "subjack"],
                    evidence=l.strip(),
                    remediation="Remove or update the dangling DNS CNAME record",
                ))

    # ── paramspider parameter mining ────────────────────────
    if "paramspider" in avail:
        logger.info("paramspider parameter mining...")
        _run(["paramspider", "-d", target, "--quiet"], logger, 300)
        param_file = Path(f"results/{target}.txt")
        if param_file.exists():
            param_file.rename(out / "paramspider_params.txt")

    # ── gowitness screenshots ──────────────────────────────
    if "gowitness" in avail and live_urls:
        logger.info("gowitness screenshots...")
        urls_f = out / "live_urls.txt"
        screens = out / "screenshots"
        screens.mkdir(exist_ok=True)
        urls_f.write_text("\n".join(live_urls[:50]))
        _run(["gowitness", "file", "-f", str(urls_f), "--screenshot-path", str(screens)], logger, 600)

    # ── wpscan ──────────────────────────────────────────────
    if "wpscan" in avail and live_urls:
        logger.info("wpscan WordPress scan...")
        for url in live_urls[:3]:
            wp_json = out / f"wpscan_{_safe(url)}.json"
            _run(["wpscan", "--url", url, "-o", str(wp_json), "--format", "json", "--no-banner", "-e", "ap,at,u"], logger, 600)
            if wp_json.exists():
                try:
                    data = json.loads(wp_json.read_text())
                    for vuln in data.get("vulnerabilities", []):
                        session.add_finding(Finding(
                            source="recon.depth",
                            title=f"WordPress vuln: {vuln.get('title','?')}",
                            severity=SeverityLevel.HIGH,
                            host=target,
                            tags=["wpscan", "wordpress"],
                            evidence=json.dumps(vuln)[:300],
                        ))
                except Exception:
                    pass

    logger.success("Depth recon complete")
    return results


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_recon(
    target: str,
    depth: str,
    session: Session,
    logger: Optional[ARDFLogger] = None,
) -> Dict[str, Any]:
    """
    Run reconnaissance against target at specified depth.

    Args:
        target  : hostname or IP to assess
        depth   : passive | normal | depth
        session : active ARDF session
        logger  : ARDFLogger instance

    Returns:
        Dict of discovered subdomains, urls, hosts, findings
    """
    if logger is None:
        logger = get_logger("recon")

    if depth not in ("passive", "normal", "depth"):
        logger.error(f"Unknown depth: {depth}")
        return {}

    logger.banner(f"RECON [{depth.upper()}] → {target}", style="bold green")

    avail = _avail_for_depth(depth)
    missing = [t for t, depths in TOOL_DEPTHS.items() if depth in depths and t not in avail]
    if missing:
        logger.warning(f"Missing tools (skipped): {', '.join(missing)}")
    logger.info(f"Available tools: {', '.join(avail)}")

    from modules.session import SessionStatus
    session.set_status(SessionStatus.RUNNING)

    try:
        if depth == "passive":
            results = _passive(target, session, logger, avail)
        elif depth == "normal":
            results = _normal(target, session, logger, avail)
        else:
            results = _depth(target, session, logger, avail)
    except Exception as e:
        logger.exception(f"Recon failed: {e}")
        session.set_status(SessionStatus.FAILED)
        return {}

    session.mark_module_done(f"recon.{depth}")

    # Save summary
    report_path = session.dir("recon") / f"recon_{depth}_summary.json"
    with open(report_path, "w") as f:
        json.dump(
            {k: list(v) if isinstance(v, set) else v
             for k, v in results.items()
             if isinstance(v, (str, list, set, dict, int, float, bool, type(None)))},
            f, indent=2, default=str,
        )

    logger.success(f"Recon [{depth}] done | findings={session.meta.findings_count} risk={session.meta.risk_score}")
    return results