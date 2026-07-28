"""
modules/intel.py
─────────────────
Threat Intelligence module for ARDF.
Enriches findings with CVE data from NVD only.
(Other intelligence sources moved to separate modules for cleanliness)

Sources
───────
  - NVD (NIST) CVE API v2          — no key required
  - Local Qwen2.5:0.5b via ollama — local, private (optional)
"""

import os
import re
import json
import time
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

    def search_by_version(
        self,
        product:   str,
        version:   str,
        max_results: int = 10,
        logger:    Optional[ARDFLogger] = None,
    ) -> List[Dict[str, Any]]:
        """Search CVEs for a specific product version."""
        keyword = f"{product} {version}"
        return self.search_by_keyword(keyword, max_results, logger)

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
            "impact": {
                "confidentiality": _get_impact(cve, "confidentiality"),
                "integrity": _get_impact(cve, "integrity"),
                "availability": _get_impact(cve, "availability"),
            }
        }


def _score_to_severity(score: Optional[float]) -> str:
    if score is None: return "unknown"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"


def _get_impact(cve: Dict, key: str) -> str:
    try:
        metrics = cve.get("metrics", {})
        for metric_type in ("cvssMetricV31", "cvssMetricV30"):
            if metric_type in metrics:
                return metrics[metric_type][0].get("cvssData", {}).get("impact", {}).get(key, "NONE")
        return "NONE"
    except Exception:
        return "NONE"


# ─────────────────────────────────────────────────────────────
# Local Qwen2.5 AI analyst (optional, local-only)
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
        if not self._ollama_available():
            return "[AI unavailable]"
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

    def analyse_cve(self, cve_record: Dict) -> str:
        """Get AI analysis of a CVE."""
        if not self._ollama_available() or not cve_record:
            return ""
        prompt = (
            f"You are a vulnerability analyst. Analyse this CVE briefly:\n"
            f"CVE: {cve_record.get('cve_id', '')}\n"
            f"Description: {cve_record.get('description', '')[:300]}\n"
            f"CVSS Score: {cve_record.get('cvss_score')}\n"
            f"Severity: {cve_record.get('severity')}\n\n"
            f"Provide: 1) Likely attack vector 2) Ease of exploitation 3) Recommended mitigation (max 3 sentences)"
        )
        return self._ask(prompt)

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


# ─────────────────────────────────────────────────────────────
# IntelEngine — orchestrates CVE enrichment + AI
# ─────────────────────────────────────────────────────────────

class IntelEngine:
    """
    High-level interface used by ardf.py and the orchestrator.
    Focused on CVE enrichment and AI analysis.
    """

    def __init__(self):
        self.cve = CVEClient()
        self.ai  = QwenAnalyst()

    # ── CVE enrichment ────────────────────────────────────────

    def enrich_cves(
        self,
        findings: List[Finding],
        logger:   ARDFLogger,
        with_ai:  bool = True,
    ) -> Dict[str, Dict]:
        """Enrich findings with CVE data from NVD."""
        enriched = {}
        cve_ids  = {f.cve for f in findings if f.cve}
        
        if not cve_ids:
            logger.info("No CVEs found to enrich")
            return {}
        
        logger.info(f"Enriching {len(cve_ids)} CVEs from NVD...")
        for cve_id in cve_ids:
            logger.info(f"NVD lookup: {cve_id}")
            record = self.cve.lookup(cve_id, logger=logger)
            if record:
                enriched[cve_id] = record
                logger.success(
                    f"{cve_id} | score={record['cvss_score']} | {record['severity']}"
                )
                # Add AI analysis if requested
                if with_ai:
                    analysis = self.ai.analyse_cve(record)
                    if analysis and not analysis.startswith("[AI"):
                        record["ai_analysis"] = analysis
            time.sleep(NVD_RATE_DELAY)
        
        logger.success(f"Enriched {len(enriched)} CVEs")
        return enriched

    def search_cves_by_product(
        self,
        product:   str,
        version:   Optional[str] = None,
        max_results: int = 20,
        logger:    Optional[ARDFLogger] = None,
    ) -> List[Dict]:
        """Search CVEs for a product."""
        keyword = product if not version else f"{product} {version}"
        return self.cve.search_by_keyword(keyword, max_results, logger)

    # ── AI analysis ───────────────────────────────────────────

    def ai_analyse(
        self,
        session: Session,
        logger:  ARDFLogger,
        mode:    str = "full",
    ) -> Dict[str, str]:
        """Run AI analysis on session findings."""
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

        # Per-finding remediation for top critical/high
        top          = [
            f for f in findings
            if f.severity.value in ("critical", "high")
        ][:5]
        remediations = {}
        for f in top:
            rem = self.ai.analyse_finding(f)
            if rem and not rem.startswith("[AI"):
                remediations[f.id] = rem
        output["remediations"] = remediations

        logger.success("AI analysis complete")
        return output

    # ── Full session enrichment pipeline ──────────────────────

    def enrich_session(
        self,
        session: Session,
        logger:  ARDFLogger,
        with_ai: bool = True,
    ) -> Dict[str, Any]:
        """
        One-call enrichment pipeline:
          1. Enrich CVEs via NVD
          2. Qwen2.5 AI analysis (optional)
          3. Save intel report to session folder
        """
        logger.banner("INTEL ENRICHMENT (CVE Focus)", style="bold yellow")
        findings = session.get_findings()

        # 1. CVEs
        cve_records = self.enrich_cves(findings, logger, with_ai)

        # 2. AI analysis (optional)
        ai_output = {}
        if with_ai and findings:
            ai_output = self.ai_analyse(
                session = session,
                logger  = logger,
                mode    = session.meta.mode.value,
            )

        # 3. Add findings for critical CVEs
        for cve_id, record in cve_records.items():
            if record.get("severity") in ("critical", "high"):
                # Check if finding already exists
                existing = False
                for f in findings:
                    if f.cve == cve_id:
                        existing = True
                        break
                if not existing:
                    session.add_finding(Finding(
                        source      = "intel.cve",
                        title       = f"CVE: {cve_id}",
                        description = record.get("description", "")[:300],
                        severity    = SeverityLevel.CRITICAL if record.get("severity") == "critical" else SeverityLevel.HIGH,
                        host        = session.meta.target,
                        cve         = cve_id,
                        tags        = ["cve", "nvd", "intel"],
                        evidence    = json.dumps(record.get("references", [])[:3]),
                        remediation = "Apply vendor patch or mitigations immediately"
                    ))

        # 4. Persist
        report = {
            "session_id":   session.meta.session_id,
            "target":       session.meta.target,
            "cve_records":  cve_records,
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
    with_ai: bool = True,
) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("intel")
    return get_engine().enrich_session(session, logger, with_ai)