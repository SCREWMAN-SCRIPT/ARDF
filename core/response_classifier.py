"""
core/response_classifier.py
─────────────────────────────
ResponseClassifier — classifies tool output and HTTP responses
to identify defensive measures and failure reasons.

Used by the orchestrator and tactician to decide what happened
after a tool ran and what to do next.
"""

import re
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────
# Signature sets
# ─────────────────────────────────────────────────────────────

WAF_SIGNATURES: List[Tuple[str, str]] = [
    (r"cloudflare",                  "cloudflare"),
    (r"mod_security|modsecurity",    "modsecurity"),
    (r"aws.?waf",                    "aws_waf"),
    (r"imperva|incapsula",           "imperva"),
    (r"akamai",                      "akamai"),
    (r"sucuri",                      "sucuri"),
    (r"barracuda",                   "barracuda"),
    (r"f5.big.?ip",                  "f5_bigip"),
    (r"fortiweb",                    "fortiweb"),
    (r"web application firewall",    "generic_waf"),
    (r"request blocked|access denied|blocked by",  "generic_waf"),
    (r"security policy violation",   "generic_waf"),
    (r"406 not acceptable",          "generic_waf"),
    (r"malicious request",           "generic_waf"),
]

IDS_SIGNATURES: List[str] = [
    r"intrusion detected",
    r"snort",
    r"suricata",
    r"blocked by ids",
    r"signature matched",
    r"threat detected",
    r"attack blocked",
]

RATE_LIMIT_SIGNATURES: List[str] = [
    r"429 too many requests",
    r"rate.?limit",
    r"too many requests",
    r"quota exceeded",
    r"retry.?after",
    r"slow down",
    r"throttle",
    r"request limit",
]

AUTH_SIGNATURES: List[str] = [
    r"401 unauthorized",
    r"403 forbidden",
    r"authentication required",
    r"login required",
    r"session expired",
    r"invalid.?token",
    r"not authenticated",
    r"permission denied",
]

TIMEOUT_SIGNATURES: List[str] = [
    r"timed? out",
    r"connection.?refused",
    r"no route to host",
    r"network.?unreachable",
    r"connection.?reset",
    r"\beof\b",
    r"broken pipe",
    r"deadline exceeded",
]

NETWORK_ERROR_SIGNATURES: List[str] = [
    r"name or service not known",
    r"could not resolve",
    r"dns.?error",
    r"socket.?error",
    r"failed to connect",
    r"connection.?refused",
]

BINARY_MISSING_SIGNATURES: List[str] = [
    r"no such file or directory",
    r"command not found",
    r"not found",
    r"cannot find",
    r"executable file not found",
]

SUCCESS_INDICATORS: List[str] = [
    r"\[+\]",
    r"vulnerable",
    r"injectable",
    r"confirmed",
    r"\bfound\b",
    r"\bopen\b",
    r"valid",
    r"cracked",
    r"success",
    r"critical",
    r"\bhigh\b",
    r"\bexposed\b",
    r"\bleak",
    r"\bsecret",
    r"takeover",
]

NO_RESULT_INDICATORS: List[str] = [
    r"no results",
    r"nothing found",
    r"0 results",
    r"not vulnerable",
    r"target seems to be",
    r"no open ports",
    r"empty",
    r"no findings",
]


# ─────────────────────────────────────────────────────────────
# HTTP status → classification
# ─────────────────────────────────────────────────────────────

HTTP_STATUS_MAP: Dict[int, str] = {
    200: "success",
    201: "success",
    204: "success",
    301: "redirect",
    302: "redirect",
    307: "redirect",
    400: "bad_request",
    401: "auth_required",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    429: "rate_limited",
    500: "server_error",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}


# ─────────────────────────────────────────────────────────────
# ResponseClassifier
# ─────────────────────────────────────────────────────────────

class ResponseClassifier:
    """
    Classifies tool output and HTTP responses to identify
    what happened during tool execution.

    Returns a classification dict used by the orchestrator
    and tactician to decide what to do next.
    """

    # ── Main classification entry point ───────────────────────

    def classify(
        self,
        stdout:      str = "",
        stderr:      str = "",
        return_code: int = 0,
        tool_name:   str = "",
    ) -> Dict:
        """
        Classify combined tool output.

        Returns:
            {
                failure_type    : str | None,
                waf_detected    : bool,
                waf_type        : str,
                ids_detected    : bool,
                rate_limited    : bool,
                auth_required   : bool,
                timed_out       : bool,
                network_error   : bool,
                binary_missing  : bool,
                has_findings    : bool,
                no_results      : bool,
                blocked         : bool,
                needs_retry     : bool,
                output_length   : int,
                success         : bool,
            }
        """
        combined = (stdout + " " + stderr).lower()

        waf_detected, waf_type = self._detect_waf(combined)
        ids_detected     = self._match_any(combined, IDS_SIGNATURES)
        rate_limited     = self._match_any(combined, RATE_LIMIT_SIGNATURES)
        auth_required    = self._match_any(combined, AUTH_SIGNATURES)
        timed_out        = self._match_any(combined, TIMEOUT_SIGNATURES)
        network_error    = self._match_any(combined, NETWORK_ERROR_SIGNATURES)
        binary_missing   = (
            return_code == 127 or
            (not stdout.strip() and self._match_any(stderr.lower(), BINARY_MISSING_SIGNATURES))
        )
        has_findings     = self._match_any(combined, SUCCESS_INDICATORS)
        no_results       = (
            not has_findings and
            (self._match_any(combined, NO_RESULT_INDICATORS) or
             (not stdout.strip() and return_code == 0))
        )

        blocked          = waf_detected or ids_detected or (return_code == 403)
        needs_retry      = timed_out or rate_limited or network_error

        # Determine primary failure type
        failure_type = None
        if binary_missing:
            failure_type = "binary_missing"
        elif waf_detected:
            failure_type = "waf_blocked"
        elif ids_detected:
            failure_type = "ids_blocked"
        elif rate_limited:
            failure_type = "rate_limited"
        elif auth_required and not has_findings:
            failure_type = "auth_required"
        elif timed_out:
            failure_type = "timeout"
        elif network_error:
            failure_type = "network_error"
        elif no_results and not has_findings:
            failure_type = "no_results"

        success = (
            has_findings or
            (return_code == 0 and stdout.strip() and not failure_type)
        )

        return {
            "failure_type":   failure_type,
            "waf_detected":   waf_detected,
            "waf_type":       waf_type,
            "ids_detected":   ids_detected,
            "rate_limited":   rate_limited,
            "auth_required":  auth_required,
            "timed_out":      timed_out,
            "network_error":  network_error,
            "binary_missing": binary_missing,
            "has_findings":   has_findings,
            "no_results":     no_results,
            "blocked":        blocked,
            "needs_retry":    needs_retry,
            "output_length":  len(stdout),
            "return_code":    return_code,
            "success":        success,
            "tool":           tool_name,
        }

    def classify_http(self, status_code: int, body: str = "") -> Dict:
        """Classify an HTTP response."""
        status_class = HTTP_STATUS_MAP.get(status_code, "unknown")
        body_lower   = body.lower()

        waf_detected, waf_type = self._detect_waf(body_lower)

        return {
            "status_code":  status_code,
            "status_class": status_class,
            "waf_detected": waf_detected,
            "waf_type":     waf_type,
            "auth_required":status_code in (401, 403),
            "rate_limited": status_code == 429,
            "server_error": status_code >= 500,
            "success":      200 <= status_code < 300,
            "redirect":     300 <= status_code < 400,
        }

    def is_successful_run(
        self,
        stdout:      str,
        stderr:      str,
        return_code: int,
    ) -> bool:
        """Quick check — did the tool produce useful output?"""
        result = self.classify(stdout=stdout, stderr=stderr, return_code=return_code)
        return result["success"] and not result["failure_type"]

    def extract_findings_count(self, stdout: str, tool_name: str) -> int:
        """
        Attempt to extract finding count from tool output.
        Tool-specific patterns for common Kali tools.
        """
        patterns = {
            "nuclei":     r"(\d+)\s+(?:findings?|templates?|issues?)",
            "nmap":       r"(\d+)\s+(?:open|filtered)\s+ports?",
            "ffuf":       r"(\d+)\s+(?:results?|matches?|words?)",
            "subfinder":  r"(\d+)\s+(?:subdomains?|hosts?|results?)",
            "sqlmap":     r"(\d+)\s+(?:parameter|injection|vulnerable)",
            "nikto":      r"(\d+)\s+(?:item|finding|vulnerabilit)",
        }
        pattern = patterns.get(tool_name.lower())
        if not pattern:
            # Generic count extraction
            match = re.search(r"(\d+)\s+(?:result|finding|vuln|issue|host)", stdout, re.I)
            return int(match.group(1)) if match else 0
        match = re.search(pattern, stdout, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    def summarise(self, classification: Dict) -> str:
        """Return a one-line human-readable summary of a classification."""
        if classification.get("binary_missing"):
            return "Tool binary not found"
        if classification.get("waf_detected"):
            return f"WAF detected ({classification.get('waf_type','unknown')})"
        if classification.get("ids_detected"):
            return "IDS/IPS blocked the request"
        if classification.get("rate_limited"):
            return "Rate limit hit — too many requests"
        if classification.get("timed_out"):
            return "Tool timed out"
        if classification.get("auth_required"):
            return "Authentication required"
        if classification.get("network_error"):
            return "Network error — host unreachable"
        if classification.get("no_results"):
            return "Tool ran successfully but found nothing"
        if classification.get("has_findings"):
            return "Findings detected"
        if classification.get("success"):
            return "Tool completed successfully"
        return "Unknown result"

    # ── Utilities ─────────────────────────────────────────────

    def _detect_waf(self, text: str) -> Tuple[bool, str]:
        """Detect WAF presence and identify the product."""
        for pattern, waf_name in WAF_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                return True, waf_name
        return False, ""

    def _match_any(self, text: str, patterns: List[str]) -> bool:
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False
