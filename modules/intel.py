"""
modules/intel.py
─────────────────
Threat Intelligence module for ARDF.
Enriches findings with CVE data, Shodan, AbuseIPDB, VirusTotal,
and local Qwen2.5 AI-assisted analysis.

Sources
───────
  - NVD (NIST) CVE API v2          — no key required
  - Shodan   (optional API key)
  - AbuseIPDB (optional API key)
  - VirusTotal (optional API key)
  - Qwen2.5:0.5b via ollama        — local, private
"""

import os
import re
import json
import time
import socket
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from pathlib import Path
from typing  import Any, Dict, List, Optional

from modules.logger  import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# API keys — all optional, read from environment
# ─────────────────────────────────────────────────────────────

SHODAN_API_KEY    = os.environ.get("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_API_KEY        = os.environ.get("VT_API_KEY", "")

OLLAMA_MODEL   = os.environ.get("ARDF_AI_MODEL",   "qwen2.5:0.5b")
OLLAMA_TIMEOUT = int(os.environ.get("ARDF_AI_TIMEOUT", "60"))

NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_DELAY = 0.7


# ─────────────────────────────────────────────────────────────
# Low-level HTTP helper
# ─────────────────────────────────────────────────────────────

def _http_get(
    url:     str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    logger:  Optional[ARDFLogger] = None,
) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "ARDF/2.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if logger:
            logger.warning(f"HTTP {e.code} for {url}")
    except Exception as e:
        if logger:
            logger.warning(f"Request failed ({url}): {e}")
    return None


# ─────────────────────────────────────────────────────────────
# CVE / NVD
# ─────────────────────────────────────────────────────────────

class CVEClient:
    """Query the NIST NVD CVE API v2."""

    def lookup(
        self,
        cve_id: str,
        logger: Optional[ARDFLogger] = None,
    ) -> Optional[Dict[str, Any]]:
        url  = f"{NVD_API_BASE}?cveId={cve_id.upper()}"
        data = _http_get(url, logger=logger)
        if not data:
            return None
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._normalise(vulns[0].get("cve", {}))

    def search_by_keyword(
        self,
        keyword:     str,
        max_results: int = 10,
        logger:      Optional[ARDFLogger] = None,
    ) -> List[Dict[str, Any]]:
        params = urllib.parse.urlencode({
            "keywordSearch":  keyword,
            "resultsPerPage": max_results,
        })
        url  = f"{NVD_API_BASE}?{params}"
        data = _http_get(url, logger=logger)
        if not data:
            return []
        return [
            self._normalise(v.get("cve", {}))
            for v in data.get("vulnerabilities", [])
        ]

    def search_by_cpe(
        self,
        cpe:         str,
        max_results: int = 10,
        logger:      Optional[ARDFLogger] = None,
    ) -> List[Dict[str, Any]]:
        params = urllib.parse.urlencode({
            "cpeName":        cpe,
            "resultsPerPage": max_results,
        })
        url  = f"{NVD_API_BASE}?{params}"
        data = _http_get(url, logger=logger)
        if not data:
            return []
        return [
            self._normalise(v.get("cve", {}))
            for v in data.get("vulnerabilities", [])
        ]

    @staticmethod
    def _normalise(cve: Dict) -> Dict[str, Any]:
        cve_id   = cve.get("id", "")
        score    = None
        severity = "unknown"
        metrics  = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data     = entries[0].get("cvssData", {})
                score    = data.get("baseScore")
                severity = (
                    data.get("baseSeverity", "").lower()
                    or _score_to_severity(score)
                )
                break

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        refs = [r.get("url", "") for r in cve.get("references", [])][:5]

        return {
            "cve_id":      cve_id,
            "description": desc,
            "cvss_score":  score,
            "severity":    severity,
            "published":   cve.get("published", ""),
            "modified":    cve.get("lastModified", ""),
            "references":  refs,
        }


def _score_to_severity(score: Optional[float]) -> str:
    if score is None: return "unknown"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"


# ─────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────

class ShodanClient:
    BASE = "https://api.shodan.io"

    def __init__(self, api_key: str = SHODAN_API_KEY):
        self.api_key = api_key

    def _enabled(self) -> bool:
        return bool(self.api_key)

    def host(
        self,
        ip:     str,
        logger: Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        url  = f"{self.BASE}/shodan/host/{ip}?key={self.api_key}"
        data = _http_get(url, logger=logger)
        if not data or "error" in data:
            return None
        return {
            "ip":          ip,
            "org":         data.get("org", ""),
            "isp":         data.get("isp", ""),
            "country":     data.get("country_name", ""),
            "city":        data.get("city", ""),
            "os":          data.get("os", ""),
            "ports":       data.get("ports", []),
            "hostnames":   data.get("hostnames", []),
            "tags":        data.get("tags", []),
            "vulns":       list(data.get("vulns", {}).keys()),
            "last_update": data.get("last_update", ""),
        }

    def dns_reverse(
        self,
        ip:     str,
        logger: Optional[ARDFLogger] = None,
    ) -> List[str]:
        if not self._enabled():
            return []
        url  = f"{self.BASE}/dns/reverse?ips={ip}&key={self.api_key}"
        data = _http_get(url, logger=logger)
        return data.get(ip, []) if data else []

    def search(
        self,
        query:       str,
        max_results: int = 20,
        logger:      Optional[ARDFLogger] = None,
    ) -> List[Dict]:
        if not self._enabled():
            return []
        params = urllib.parse.urlencode({"query": query, "key": self.api_key})
        url    = f"{self.BASE}/shodan/host/search?{params}"
        data   = _http_get(url, logger=logger)
        if not data:
            return []
        return data.get("matches", [])[:max_results]


# ─────────────────────────────────────────────────────────────
# AbuseIPDB
# ─────────────────────────────────────────────────────────────

class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str = ABUSEIPDB_API_KEY):
        self.api_key = api_key

    def _enabled(self) -> bool:
        return bool(self.api_key)

    def check(
        self,
        ip:            str,
        max_age_days:  int = 30,
        logger:        Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        params = urllib.parse.urlencode({
            "ipAddress":    ip,
            "maxAgeInDays": max_age_days,
        })
        url  = f"{self.BASE}/check?{params}"
        data = _http_get(
            url,
            headers={"Key": self.api_key, "Accept": "application/json"},
            logger=logger,
        )
        if not data:
            return None
        d = data.get("data", {})
        return {
            "ip":            ip,
            "abuse_score":   d.get("abuseConfidenceScore", 0),
            "country":       d.get("countryCode", ""),
            "isp":           d.get("isp", ""),
            "domain":        d.get("domain", ""),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", ""),
            "is_tor":        d.get("isTor", False),
            "is_public":     d.get("isPublic", True),
        }

    def bulk_check(
        self,
        ips:    List[str],
        logger: Optional[ARDFLogger] = None,
    ) -> Dict[str, Optional[Dict]]:
        results = {}
        for ip in ips:
            results[ip] = self.check(ip, logger=logger)
            time.sleep(0.3)
        return results


# ─────────────────────────────────────────────────────────────
# VirusTotal
# ─────────────────────────────────────────────────────────────

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = VT_API_KEY):
        self.api_key = api_key

    def _enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def check_hash(
        self,
        file_hash: str,
        logger:    Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        url   = f"{self.BASE}/files/{file_hash}"
        data  = _http_get(url, headers=self._headers(), logger=logger)
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash":       file_hash,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "name":       attrs.get("meaningful_name", ""),
            "type":       attrs.get("type_description", ""),
        }

    def check_ip(
        self,
        ip:     str,
        logger: Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        url   = f"{self.BASE}/ip_addresses/{ip}"
        data  = _http_get(url, headers=self._headers(), logger=logger)
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip":         ip,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country":    attrs.get("country", ""),
            "owner":      attrs.get("as_owner", ""),
        }

    def check_url(
        self,
        url_to_check: str,
        logger:       Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        url_id = urllib.parse.quote_plus(
            urllib.parse.quote(url_to_check, safe="")
        )
        url   = f"{self.BASE}/urls/{url_id}"
        data  = _http_get(url, headers=self._headers(), logger=logger)
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "url":        url_to_check,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
        }

    def scan_file(
        self,
        filepath: Path,
        logger:   Optional[ARDFLogger] = None,
    ) -> Optional[Dict]:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as fh:
            while chunk := fh.read(8192):
                sha256.update(chunk)
        return self.check_hash(sha256.hexdigest(), logger=logger)


# ─────────────────────────────────────────────────────────────
# Qwen2.5 local AI analyst
# ─────────────────────────────────────────────────────────────

class QwenAnalyst:
    """
    Uses Qwen2.5:0.5b (via ollama) for local AI analysis.
    Completely offline — no data leaves the machine.
    """

    def __init__(
        self,
        model:   str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ):
        self.model   = model
        self.timeout = timeout

    def _ollama_available(self) -> bool:
        try:
            subprocess.run(
                ["which", "ollama"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _ask(self, prompt: str) -> str:
        try:
            result = subprocess.run(
                ["ollama", "run", self.model],
                input          = prompt,
                capture_output = True,
                text           = True,
                timeout        = self.timeout,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "[AI timeout]"
        except Exception as e:
            return f"[AI error: {e}]"

    def analyse_finding(self, finding: Finding) -> str:
        if not self._ollama_available():
            return ""
        prompt = (
            f"You are a cybersecurity expert. Briefly analyse this security finding "
            f"and suggest one concrete remediation step (max 3 sentences):\n\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Severity: {finding.severity.value}\n"
            f"Host: {finding.host}\n"
            f"CVE: {finding.cve or 'N/A'}\n"
            f"Evidence: {finding.evidence[:300]}\n"
        )
        return self._ask(prompt)

    def summarise_session(self, findings: List[Finding]) -> str:
        if not self._ollama_available() or not findings:
            return ""
        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        top = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title} ({f.host})"
            for f in sorted(findings, key=lambda x: x.severity.value)[:10]
        )
        prompt = (
            f"You are a senior penetration tester. Write a 3-paragraph executive summary "
            f"for a security assessment with these results:\n\n"
            f"Severity counts: {json.dumps(counts)}\n\n"
            f"Top findings:\n{top}\n\n"
            f"Keep it concise and professional. No bullet points."
        )
        return self._ask(prompt)

    def suggest_next_steps(
        self,
        target:            str,
        completed_modules: List[str],
        findings:          List[Finding],
    ) -> str:
        if not self._ollama_available():
            return ""
        high_sev = [f for f in findings if f.severity.value in ("critical", "high")]
        top      = "\n".join(f"- {f.title} ({f.host})" for f in high_sev[:5])
        prompt = (
            f"You are a security assessor. Based on these high/critical findings "
            f"for target '{target}', suggest 3 specific investigation steps. "
            f"Be concrete. No explanations.\n\n"
            f"Completed modules: {', '.join(completed_modules)}\n\n"
            f"High/Critical findings:\n{top or 'None yet'}"
        )
        return self._ask(prompt)

    def blue_team_advice(self, findings: List[Finding]) -> str:
        if not self._ollama_available() or not findings:
            return ""
        titles = "\n".join(f"- {f.title}" for f in findings[:15])
        prompt = (
            f"You are a Blue Team security engineer. Given these findings, "
            f"list 5 prioritised hardening actions (one line each, format: "
            f"'PRIORITY: action — tool/config'). No explanations.\n\n"
            f"Findings:\n{titles}"
        )
        return self._ask(prompt)


# ─────────────────────────────────────────────────────────────
# IOC Extractor
# ─────────────────────────────────────────────────────────────

class IOCExtractor:
    """Extract Indicators of Compromise from raw text."""

    _IP_RE       = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    _DOMAIN_RE   = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    )
    _URL_RE      = re.compile(r"https?://[^\s\"'<>]+")
    _HASH_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
    _HASH_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
    _HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
    _CVE_RE      = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    _EMAIL_RE    = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
    _PRIVATE     = re.compile(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)"
    )

    def extract(self, text: str) -> Dict[str, List[str]]:
        ips = [
            ip for ip in set(self._IP_RE.findall(text))
            if not self._PRIVATE.match(ip)
        ]
        return {
            "ips":             sorted(ips),
            "domains":         sorted(set(self._DOMAIN_RE.findall(text))),
            "urls":            sorted(set(self._URL_RE.findall(text))),
            "hashes_md5":      sorted(set(self._HASH_MD5.findall(text))),
            "hashes_sha1":     sorted(set(self._HASH_SHA1.findall(text))),
            "hashes_sha256":   sorted(set(self._HASH_SHA256.findall(text))),
            "cves":            sorted(set(self._CVE_RE.findall(text))),
            "emails":          sorted(set(self._EMAIL_RE.findall(text))),
        }

    def extract_from_findings(self, findings: List[Finding]) -> Dict[str, List[str]]:
        combined = " ".join(
            f"{f.title} {f.description} {f.evidence}"
            for f in findings
        )
        return self.extract(combined)


# ─────────────────────────────────────────────────────────────
# IntelEngine — orchestrates all of the above
# ─────────────────────────────────────────────────────────────

class IntelEngine:
    """
    High-level interface used by ardf.py and the orchestrator.

    Usage:
        engine = IntelEngine()
        report = engine.enrich_session(session, logger)
    """

    def __init__(self):
        self.cve    = CVEClient()
        self.shodan = ShodanClient()
        self.abuse  = AbuseIPDBClient()
        self.vt     = VirusTotalClient()
        self.ai     = QwenAnalyst()
        self.ioc    = IOCExtractor()

    # ── CVE enrichment ────────────────────────────────────────

    def enrich_cves(
        self,
        findings: List[Finding],
        logger:   ARDFLogger,
    ) -> Dict[str, Dict]:
        enriched = {}
        cve_ids  = {f.cve for f in findings if f.cve}
        for cve_id in cve_ids:
            logger.info(f"NVD lookup: {cve_id}")
            record = self.cve.lookup(cve_id, logger=logger)
            if record:
                enriched[cve_id] = record
                logger.success(
                    f"{cve_id} | score={record['cvss_score']} | {record['severity']}"
                )
            time.sleep(NVD_RATE_DELAY)
        return enriched

    # ── Shodan enrichment ─────────────────────────────────────

    def enrich_ips_shodan(
        self,
        ips:    List[str],
        logger: ARDFLogger,
    ) -> Dict[str, Dict]:
        if not self.shodan._enabled():
            logger.warning("SHODAN_API_KEY not set — skipping Shodan")
            return {}
        results = {}
        for ip in ips:
            logger.info(f"Shodan lookup: {ip}")
            data = self.shodan.host(ip, logger=logger)
            if data:
                results[ip] = data
                if data["vulns"]:
                    logger.finding(
                        f"Shodan CVEs for {ip}: {', '.join(data['vulns'][:5])}",
                        severity="high",
                        host=ip,
                    )
            time.sleep(1.0)
        return results

    # ── AbuseIPDB ─────────────────────────────────────────────

    def check_reputation(
        self,
        ips:    List[str],
        logger: ARDFLogger,
    ) -> Dict[str, Optional[Dict]]:
        if not self.abuse._enabled():
            logger.warning("ABUSEIPDB_API_KEY not set — skipping reputation check")
            return {}
        logger.info(f"AbuseIPDB check for {len(ips)} IPs")
        return self.abuse.bulk_check(ips, logger=logger)

    # ── IOC extraction ────────────────────────────────────────

    def extract_iocs(
        self,
        findings: List[Finding],
        logger:   ARDFLogger,
    ) -> Dict[str, List[str]]:
        iocs  = self.ioc.extract_from_findings(findings)
        total = sum(len(v) for v in iocs.values())
        logger.success(f"IOC extraction complete | {total} indicators")
        return iocs

    # ── AI analysis ───────────────────────────────────────────

    def ai_analyse(
        self,
        session: Session,
        logger:  ARDFLogger,
        mode:    str = "full",
    ) -> Dict[str, str]:
        findings = session.get_findings()
        if not findings:
            logger.warning("No findings to analyse")
            return {}

        logger.info("Running Qwen2.5 local AI analysis...")
        output: Dict[str, str] = {}

        output["summary"] = self.ai.summarise_session(findings)

        if mode in ("red", "full"):
            output["next_steps"] = self.ai.suggest_next_steps(
                target            = session.meta.target,
                completed_modules = session.meta.modules_done,
                findings          = findings,
            )

        if mode in ("blue", "full"):
            output["blue_advice"] = self.ai.blue_team_advice(findings)

        # Per-finding remediation for top critical/high
        top          = [
            f for f in findings
            if f.severity.value in ("critical", "high")
        ][:5]
        remediations = {}
        for f in top:
            rem = self.ai.analyse_finding(f)
            if rem:
                remediations[f.id] = rem
        output["remediations"] = remediations

        logger.success("AI analysis complete")
        return output

    # ── Full session enrichment pipeline ──────────────────────

    def enrich_session(
        self,
        session: Session,
        logger:  ARDFLogger,
    ) -> Dict[str, Any]:
        """
        One-call enrichment pipeline:
          1. Extract IOCs
          2. Enrich CVEs via NVD
          3. Shodan host lookup (if key available)
          4. AbuseIPDB reputation (if key available)
          5. Qwen2.5 AI analysis
          6. Save intel report to session folder
        """
        logger.banner("INTEL ENRICHMENT", style="bold yellow")
        findings = session.get_findings()

        # 1. IOCs
        iocs = self.extract_iocs(findings, logger)

        # 2. CVEs
        cve_records = self.enrich_cves(findings, logger)

        # 3. Shodan
        shodan_data = self.enrich_ips_shodan(iocs.get("ips", [])[:20], logger)

        # 4. AbuseIPDB
        abuse_data = self.check_reputation(iocs.get("ips", [])[:30], logger)
        for ip, rep in (abuse_data or {}).items():
            if rep and rep.get("abuse_score", 0) >= 50:
                session.add_finding(Finding(
                    source      = "intel",
                    title       = f"High-abuse-score IP: {ip}",
                    description = (
                        f"AbuseIPDB score {rep['abuse_score']}% | "
                        f"reports={rep['total_reports']} | isp={rep['isp']}"
                    ),
                    severity    = (
                        SeverityLevel.HIGH
                        if rep["abuse_score"] >= 80
                        else SeverityLevel.MEDIUM
                    ),
                    host        = ip,
                    tags        = ["abuseipdb", "reputation"],
                    evidence    = json.dumps(rep),
                ))

        # 5. AI analysis
        ai_output = self.ai_analyse(
            session = session,
            logger  = logger,
            mode    = session.meta.mode.value,
        )

        # 6. Persist
        report = {
            "session_id":   session.meta.session_id,
            "target":       session.meta.target,
            "iocs":         iocs,
            "cve_records":  cve_records,
            "shodan":       shodan_data,
            "abuse_ipdb":   {ip: d for ip, d in (abuse_data or {}).items() if d},
            "ai":           ai_output,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        report_path = session.dir("intel") / "intel_report.json"
        report_path.write_text(json.dumps(report, indent=2, default=str))
        logger.success(f"Intel report saved → {report_path}")

        session.mark_module_done("intel")
        return report


# ─────────────────────────────────────────────────────────────
# Convenience entry point
# ─────────────────────────────────────────────────────────────

_engine: Optional[IntelEngine] = None

def get_engine() -> IntelEngine:
    global _engine
    if _engine is None:
        _engine = IntelEngine()
    return _engine


def run_intel(
    session: Session,
    logger:  Optional[ARDFLogger] = None,
) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("intel")
    return get_engine().enrich_session(session, logger)
