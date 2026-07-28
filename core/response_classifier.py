"""
core/response_classifier.py
───────────────────────────
Response classifier for ARDF.

Enhanced with Cloudflare-aware classification:
  - Detects Cloudflare challenge pages
  - Classifies WAF block responses
  - Identifies origin vs. CDN responses
  - Categorizes error responses
  - Extracts rate-limit information

The classifier analyses tool outputs and HTTP responses
to determine the nature of the response and suggest actions.
"""

import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Response Types
# ─────────────────────────────────────────────────────────────

class ResponseType(Enum):
    """Type of response received."""
    SUCCESS = "success"
    CLOUDFLARE_CHALLENGE = "cloudflare_challenge"
    CLOUDFLARE_BLOCK = "cloudflare_block"
    WAF_BLOCK = "waf_block"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    REDIRECT = "redirect"
    TIMEOUT = "timeout"
    EMPTY = "empty"
    MALFORMED = "malformed"
    ORIGIN = "origin"
    CACHED = "cached"
    AUTH_REQUIRED = "auth_required"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedResponse:
    """Classified response with metadata."""
    response_type: ResponseType
    confidence: float
    evidence: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: Optional[int] = None
    waf_type: Optional[str] = None
    rate_limit_info: Optional[Dict] = None
    redirect_url: Optional[str] = None
    challenge_type: Optional[str] = None  # js, captcha, etc.
    origin_ip: Optional[str] = None
    is_cached: bool = False
    suggested_action: str = ""


# ─────────────────────────────────────────────────────────────
# Response Classifier
# ─────────────────────────────────────────────────────────────

class ResponseClassifier:
    """
    Classify HTTP responses and tool outputs with Cloudflare awareness.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("classifier")
        self._patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Initialize regex patterns for classification."""
        return {
            "cloudflare": [
                re.compile(r"Cloudflare", re.I),
                re.compile(r"cf-", re.I),
                re.compile(r"cdn-cgi", re.I),
                re.compile(r"challenge-platform", re.I),
                re.compile(r"ray-id", re.I),
                re.compile(r"x-robot-tag", re.I)
            ],
            "waf": [
                re.compile(r"ModSecurity", re.I),
                re.compile(r"Web Application Firewall", re.I),
                re.compile(r"WAF", re.I),
                re.compile(r"Akamai", re.I),
                re.compile(r"CloudFront", re.I),
                re.compile(r"Imperva", re.I),
                re.compile(r"Incapsula", re.I)
            ],
            "rate_limit": [
                re.compile(r"rate limit", re.I),
                re.compile(r"too many requests", re.I),
                re.compile(r"429", re.I),
                re.compile(r"x-ratelimit", re.I),
                re.compile(r"retry-after", re.I)
            ],
            "challenge": [
                re.compile(r"captcha", re.I),
                re.compile(r"security check", re.I),
                re.compile(r"verifying", re.I),
                re.compile(r"please wait", re.I),
                re.compile(r"browser check", re.I)
            ],
            "error": [
                re.compile(r"error", re.I),
                re.compile(r"exception", re.I),
                re.compile(r"fatal", re.I),
                re.compile(r"panic", re.I)
            ]
        }

    # ── Classification methods ──────────────────────────────

    def classify_http_response(
        self,
        content: str,
        headers: Dict[str, str],
        status_code: int,
        url: str = ""
    ) -> ClassifiedResponse:
        """
        Classify an HTTP response.
        """
        evidence = []
        response_type = ResponseType.UNKNOWN
        confidence = 0.0
        waf_type = None
        challenge_type = None
        rate_limit_info = None
        redirect_url = None
        is_cached = False
        origin_ip = None
        suggested_action = ""

        # Check status code first
        if status_code >= 500:
            response_type = ResponseType.SERVER_ERROR
            confidence = 0.9
            suggested_action = "Retry with backoff"
        elif status_code == 429:
            response_type = ResponseType.RATE_LIMITED
            confidence = 0.95
            suggested_action = "Increase delay between requests"
            if "retry-after" in headers:
                try:
                    rate_limit_info = {"retry_after": int(headers["retry-after"])}
                except ValueError:
                    pass
        elif status_code == 403:
            # Check if Cloudflare block
            for pattern in self._patterns["cloudflare"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.CLOUDFLARE_BLOCK
                    confidence = 0.9
                    waf_type = "cloudflare"
                    suggested_action = "Try bypass techniques"
                    break
            if response_type == ResponseType.UNKNOWN:
                response_type = ResponseType.WAF_BLOCK
                confidence = 0.7
                suggested_action = "Check WAF rules or try different vectors"
        elif status_code == 302:
            response_type = ResponseType.REDIRECT
            confidence = 0.9
            redirect_url = headers.get("location", "")
            suggested_action = f"Follow redirect to {redirect_url[:50]}"

        # Check content for Cloudflare
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["cloudflare"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.CLOUDFLARE_CHALLENGE
                    confidence = 0.8
                    waf_type = "cloudflare"
                    evidence.append("Cloudflare signature found")
                    # Check challenge type
                    if "captcha" in (content or "").lower():
                        challenge_type = "captcha"
                    elif "browser" in (content or "").lower():
                        challenge_type = "js_challenge"
                    suggested_action = "Solve challenge or use bypass"
                    break

        # Check for rate limiting
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["rate_limit"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.RATE_LIMITED
                    confidence = 0.8
                    suggested_action = "Increase delay"
                    break

        # Check for WAF
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["waf"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.WAF_BLOCK
                    confidence = 0.7
                    waf_type = pattern.pattern
                    suggested_action = "Bypass WAF or use different vector"
                    break

        # Check if origin response (not CF)
        if response_type == ResponseType.UNKNOWN and status_code < 400:
            if "server" in headers:
                if "cloudflare" not in headers.get("server", "").lower():
                    response_type = ResponseType.ORIGIN
                    confidence = 0.7
                    suggested_action = "Direct origin attack possible"
                    # Try to extract origin IP from headers
                    if "x-forwarded-for" in headers:
                        origin_ip = headers["x-forwarded-for"].split(",")[0].strip()

        # Cache detection
        if "cf-cache-status" in headers:
            is_cached = True
            if response_type == ResponseType.UNKNOWN:
                response_type = ResponseType.CACHED
                confidence = 0.6

        # Default success
        if response_type == ResponseType.UNKNOWN and status_code < 400:
            response_type = ResponseType.SUCCESS
            confidence = 0.7
            suggested_action = "Proceed"

        return ClassifiedResponse(
            response_type=response_type,
            confidence=confidence,
            evidence=evidence,
            headers=headers,
            status_code=status_code,
            waf_type=waf_type,
            rate_limit_info=rate_limit_info,
            redirect_url=redirect_url,
            challenge_type=challenge_type,
            origin_ip=origin_ip,
            is_cached=is_cached,
            suggested_action=suggested_action
        )

    def classify_tool_output(self, stdout: str, stderr: str) -> ClassifiedResponse:
        """
        Classify tool output (stdout/stderr).
        """
        combined = f"{stdout}\n{stderr}"
        evidence = []
        response_type = ResponseType.UNKNOWN
        confidence = 0.5

        # Check for error patterns
        for pattern in self._patterns["error"]:
            if pattern.search(combined):
                response_type = ResponseType.CLIENT_ERROR
                confidence = 0.8
                evidence.append(f"Error pattern: {pattern.pattern}")
                break

        # Check for Cloudflare in output
        for pattern in self._patterns["cloudflare"]:
            if pattern.search(combined):
                if response_type == ResponseType.UNKNOWN:
                    response_type = ResponseType.CLOUDFLARE_CHALLENGE
                    confidence = 0.7
                evidence.append(f"Cloudflare pattern: {pattern.pattern}")
                break

        # Check for rate limiting
        for pattern in self._patterns["rate_limit"]:
            if pattern.search(combined):
                response_type = ResponseType.RATE_LIMITED
                confidence = 0.8
                evidence.append(f"Rate limit pattern: {pattern.pattern}")
                break

        # Empty output
        if not combined.strip():
            response_type = ResponseType.EMPTY
            confidence = 0.9
            evidence.append("Empty output")

        # Success if no errors
        if response_type == ResponseType.UNKNOWN and stdout.strip():
            response_type = ResponseType.SUCCESS
            confidence = 0.7
            evidence.append("Non-empty stdout")

        return ClassifiedResponse(
            response_type=response_type,
            confidence=confidence,
            evidence=evidence,
            suggested_action=self._get_action_for_type(response_type)
        )

    def _get_action_for_type(self, response_type: ResponseType) -> str:
        """Get suggested action for response type."""
        actions = {
            ResponseType.CLOUDFLARE_CHALLENGE: "Use Cloudflare bypass techniques",
            ResponseType.CLOUDFLARE_BLOCK: "IP is blocked by Cloudflare. Use proxy or rotation",
            ResponseType.WAF_BLOCK: "WAF detected. Try obfuscation or different vector",
            ResponseType.RATE_LIMITED: "Increase delay, add jitter, or rotate IP",
            ResponseType.SERVER_ERROR: "Retry with backoff (exponential)",
            ResponseType.ORIGIN: "Direct origin access possible",
            ResponseType.CACHED: "Cache hit — may need to bypass cache",
            ResponseType.REDIRECT: "Follow redirect",
            ResponseType.SUCCESS: "Proceed",
            ResponseType.EMPTY: "Check tool configuration",
            ResponseType.TIMEOUT: "Increase timeout or check network",
            ResponseType.AUTH_REQUIRED: "Add authentication",
            ResponseType.MALFORMED: "Check input format"
        }
        return actions.get(response_type, "Analyze manually")

    # ── Combined classification ──────────────────────────────

    def classify(
        self,
        http_content: str = "",
        http_headers: Dict = None,
        http_status: int = 0,
        stdout: str = "",
        stderr: str = "",
        url: str = ""
    ) -> Dict[str, Any]:
        """
        Classify combined HTTP response and tool output.
        """
        http_result = self.classify_http_response(
            http_content,
            http_headers or {},
            http_status,
            url
        )
        tool_result = self.classify_tool_output(stdout, stderr)

        # Combine classification
        combined_type = http_result.response_type
        if combined_type == ResponseType.UNKNOWN:
            combined_type = tool_result.response_type

        # Merge evidence
        evidence = list(set(http_result.evidence + tool_result.evidence))

        # Determine if Cloudflare is involved
        cloudflare_involved = (
            combined_type in [
                ResponseType.CLOUDFLARE_CHALLENGE,
                ResponseType.CLOUDFLARE_BLOCK
            ] or
            any("cloudflare" in e.lower() for e in evidence) or
            http_result.waf_type == "cloudflare"
        )

        return {
            "response_type": combined_type.value,
            "confidence": max(http_result.confidence, tool_result.confidence),
            "evidence": evidence,
            "status_code": http_result.status_code,
            "waf_type": http_result.waf_type,
            "cloudflare_involved": cloudflare_involved,
            "rate_limit_info": http_result.rate_limit_info,
            "origin_ip": http_result.origin_ip,
            "is_cached": http_result.is_cached,
            "suggested_action": http_result.suggested_action or tool_result.suggested_action,
            "headers": http_result.headers,
            "redirect_url": http_result.redirect_url,
            "challenge_type": http_result.challenge_type
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def classify_response(
    content: str = "",
    headers: Dict = None,
    status_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    url: str = "",
    logger: Optional[ARDFLogger] = None
) -> Dict[str, Any]:
    """
    Convenience function to classify a response.
    """
    if logger is None:
        logger = get_logger("classifier")

    classifier = ResponseClassifier(logger)
    result = classifier.classify(content, headers, status_code, stdout, stderr, url)

    logger.info(
        f"Classified as {result['response_type']} "
        f"(confidence: {result['confidence']:.2f}, "
        f"CF: {result['cloudflare_involved']})"
    )

    return result