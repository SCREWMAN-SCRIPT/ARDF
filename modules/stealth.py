"""
modules/stealth.py
──────────────────
Global Stealth Engine for ARDF.

Provides rate limiting, User-Agent rotation, proxy support,
CAPTCHA detection, and error backoff for all active modules.

All active scanning modules must use this engine to avoid
detection, blocking, and rate limiting.
"""

import time
import random
import json
import socket
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

class ScanMode(Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class StealthConfig:
    """Stealth engine configuration."""
    enabled: bool = True
    rate_limit: float = 2.0  # Requests per second
    jitter: float = 0.5      # Random delay variance (± seconds)
    user_agent_rotation: bool = True
    max_retries: int = 3
    retry_delay: int = 5
    captcha_detection: bool = True
    throttle_on_error: bool = True
    error_backoff: int = 60
    proxy_enabled: bool = False
    proxy_type: str = "socks5"
    proxy_address: str = "127.0.0.1:9050"
    proxy_username: str = ""
    proxy_password: str = ""
    scan_mode: ScanMode = ScanMode.LOW
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ])
    rate_limits: Dict[str, float] = field(default_factory=lambda: {
        "passive": 0.0,
        "low": 1.0,
        "medium": 5.0,
        "high": 20.0,
    })
    safe_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443, 22, 21, 25, 53, 143, 993, 110, 995, 587, 465])
    dangerous_ports: List[int] = field(default_factory=lambda: [3306, 5432, 1433, 27017, 6379, 9200, 9042, 5984, 7687])


# ─────────────────────────────────────────────────────────────
# Stealth Engine
# ─────────────────────────────────────────────────────────────

class StealthEngine:
    """
    Global stealth engine for rate limiting, User-Agent rotation,
    proxy support, and error handling.
    """

    def __init__(
        self,
        logger: Optional[ARDFLogger] = None,
        config: Optional[StealthConfig] = None,
        config_path: Optional[Path] = None,
    ):
        self.logger = logger or get_logger("stealth")
        self.config = config or self._load_config(config_path)
        self._last_request_time = 0.0
        self._current_ua_index = 0
        self._error_count = 0
        self._last_error_time = 0.0
        self._paused = False
        self._request_count = 0
        self._circuit_rotated = False

    def _load_config(self, config_path: Optional[Path]) -> StealthConfig:
        """Load stealth configuration from file."""
        config = StealthConfig()
        if config_path and config_path.exists():
            try:
                import yaml
                data = yaml.safe_load(config_path.read_text())
                stealth_data = data.get("stealth", {})
                if stealth_data:
                    config.enabled = stealth_data.get("enabled", True)
                    config.rate_limit = stealth_data.get("rate_limit", 2.0)
                    config.jitter = stealth_data.get("jitter", 0.5)
                    config.user_agent_rotation = stealth_data.get("user_agent_rotation", True)
                    config.max_retries = stealth_data.get("max_retries", 3)
                    config.retry_delay = stealth_data.get("retry_delay", 5)
                    config.captcha_detection = stealth_data.get("captcha_detection", True)
                    config.throttle_on_error = stealth_data.get("throttle_on_error", True)
                    config.error_backoff = stealth_data.get("error_backoff", 60)
                    config.proxy_enabled = stealth_data.get("proxy", {}).get("enabled", False)
                    config.proxy_type = stealth_data.get("proxy", {}).get("type", "socks5")
                    config.proxy_address = stealth_data.get("proxy", {}).get("address", "127.0.0.1:9050")
                    config.proxy_username = stealth_data.get("proxy", {}).get("username", "")
                    config.proxy_password = stealth_data.get("proxy", {}).get("password", "")
                    if stealth_data.get("user_agents"):
                        config.user_agents = stealth_data["user_agents"]
                    config.rate_limits = {
                        "passive": 0.0,
                        "low": 1.0,
                        "medium": 5.0,
                        "high": 20.0,
                    }
            except Exception as e:
                self.logger.warning(f"Failed to load stealth config: {e}")
        return config

    def _get_current_rate_limit(self) -> float:
        """Get current rate limit based on scan mode."""
        mode_key = self.config.scan_mode.value
        return self.config.rate_limits.get(mode_key, self.config.rate_limit)

    def _delay(self) -> None:
        """Apply rate limiting delay."""
        if not self.config.enabled:
            return

        if self._paused:
            return

        rate = self._get_current_rate_limit()
        if rate <= 0:
            return

        # Calculate delay based on rate limit
        min_delay = 1.0 / rate
        jitter = random.uniform(0, self.config.jitter)
        delay = min_delay + jitter

        # Check time since last request
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            sleep_time = delay - elapsed
            time.sleep(sleep_time)

        self._last_request_time = time.time()

    def _get_next_user_agent(self) -> str:
        """Get next User-Agent from rotation."""
        if not self.config.user_agents:
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        self._current_ua_index = (self._current_ua_index + 1) % len(self.config.user_agents)
        return self.config.user_agents[self._current_ua_index]

    def get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers with stealth applied."""
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        if custom_headers:
            headers.update(custom_headers)

        return headers

    def get_user_agent(self) -> str:
        """Get current User-Agent string."""
        if self.config.user_agent_rotation:
            return self._get_next_user_agent()
        return self.config.user_agents[0] if self.config.user_agents else "ARDF/2.0"

    def get_proxy_handler(self) -> Optional[Any]:
        """Get proxy handler for urllib.request."""
        if not self.config.proxy_enabled:
            return None

        proxy_address = self.config.proxy_address
        proxy_type = self.config.proxy_type

        if "://" not in proxy_address:
            proxy_address = f"{proxy_type}://{proxy_address}"

        if self.config.proxy_username and self.config.proxy_password:
            # Format: proto://user:pass@host:port
            import re
            if "://" in proxy_address:
                parts = proxy_address.split("://")
                proxy_address = f"{parts[0]}://{self.config.proxy_username}:{self.config.proxy_password}@{parts[1]}"

        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_address,
            "https": proxy_address,
        })
        return proxy_handler

    def check_captcha(self, content: str) -> bool:
        """Check if response contains CAPTCHA."""
        if not self.config.captcha_detection:
            return False

        patterns = [
            "captcha",
            "recaptcha",
            "verify you are human",
            "security check",
            "i'm not a robot",
            "are you a robot",
            "human verification",
            "enter the code",
            "challenge",
            "prove you are human",
        ]

        content_lower = content.lower()
        for pattern in patterns:
            if pattern in content_lower:
                return True
        return False

    def check_rate_limit(self, status_code: int, headers: Dict[str, str]) -> Tuple[bool, Optional[int]]:
        """Check if response indicates rate limiting."""
        if status_code == 429:
            retry_after = headers.get("retry-after")
            if retry_after:
                try:
                    return True, int(retry_after)
                except ValueError:
                    return True, 60
            return True, 60

        # Check headers for rate limit indicators
        for header in ["x-ratelimit-remaining", "x-ratelimit-limit", "ratelimit-remaining"]:
            if header in headers:
                if int(headers.get(header, 1)) <= 0:
                    return True, 60

        # Check for Cloudflare rate limit
        if "cf-ray" in headers and "too many" in str(headers):
            return True, 60

        return False, None

    def handle_error(self, error: Exception) -> bool:
        """Handle error with backoff."""
        if not self.config.throttle_on_error:
            return False

        self._error_count += 1
        self._last_error_time = time.time()

        # If too many errors, pause
        if self._error_count > 5:
            self.pause()
            self.logger.warning(f"Pausing due to {self._error_count} errors")
            return True

        # Exponential backoff
        backoff = self.config.error_backoff * (2 ** (self._error_count - 1))
        self.logger.warning(f"Backing off for {backoff}s")
        time.sleep(backoff)

        return False

    def pause(self) -> None:
        """Pause the stealth engine."""
        self._paused = True
        self.logger.info("Stealth engine paused")

    def resume(self) -> None:
        """Resume the stealth engine."""
        self._paused = False
        self._error_count = 0
        self.logger.info("Stealth engine resumed")

    def reset(self) -> None:
        """Reset stealth engine state."""
        self._last_request_time = 0.0
        self._error_count = 0
        self._last_error_time = 0.0
        self._paused = False
        self._request_count = 0

    def sleep(self, seconds: float) -> None:
        """Sleep with stealth considerations."""
        if self.config.jitter > 0:
            jitter = random.uniform(0, self.config.jitter)
            seconds += jitter
        time.sleep(seconds)

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: int = 30,
    ) -> Tuple[int, Dict[str, str], str]:
        """
        Make a stealth HTTP request.

        Returns:
            Tuple of (status_code, headers, content)
        """
        self._delay()
        self._request_count += 1

        # Build request
        request_headers = self.get_headers(headers)
        req = urllib.request.Request(url, headers=request_headers, method=method, data=data)

        # Configure proxy
        proxy_handler = self.get_proxy_handler()
        if proxy_handler:
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

        # Make request with retries
        for attempt in range(self.config.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                    headers_dict = {k.lower(): v for k, v in resp.getheaders()}
                    return resp.status, headers_dict, content
            except urllib.error.HTTPError as e:
                # Read error content
                try:
                    content = e.read().decode("utf-8", errors="ignore")
                except Exception:
                    content = ""
                headers_dict = {k.lower(): v for k, v in e.headers.items()}
                # Check if rate limited
                rate_limited, retry_after = self.check_rate_limit(e.code, headers_dict)
                if rate_limited:
                    self.logger.warning(f"Rate limited on {url}")
                    self.sleep(retry_after or 60)
                    continue
                # Check if CAPTCHA
                if self.check_captcha(content):
                    self.logger.warning(f"CAPTCHA detected on {url}")
                    self.pause()
                return e.code, headers_dict, content
            except urllib.error.URLError as e:
                self.logger.warning(f"URL error on attempt {attempt+1}: {e}")
                if attempt < self.config.max_retries:
                    self.sleep(self.config.retry_delay)
                else:
                    return 0, {}, f"Connection failed: {e}"
            except socket.timeout as e:
                self.logger.warning(f"Timeout on attempt {attempt+1}: {e}")
                if attempt < self.config.max_retries:
                    self.sleep(self.config.retry_delay)
                else:
                    return 0, {}, f"Timeout: {e}"
            except Exception as e:
                self.logger.error(f"Request failed: {e}")
                if attempt < self.config.max_retries:
                    self.sleep(self.config.retry_delay)
                else:
                    return 0, {}, f"Request failed: {e}"

        return 0, {}, "Max retries exceeded"

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, Dict[str, str], str]:
        """Convenience method for GET request."""
        return self.request(url, "GET", headers, timeout=timeout)

    def post(
        self,
        url: str,
        data: bytes,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Tuple[int, Dict[str, str], str]:
        """Convenience method for POST request."""
        return self.request(url, "POST", headers, data, timeout)


# ─────────────────────────────────────────────────────────────
# Global instance
# ─────────────────────────────────────────────────────────────

_stealth_engine: Optional[StealthEngine] = None


def get_stealth_engine(
    logger: Optional[ARDFLogger] = None,
    config_path: Optional[Path] = None,
) -> StealthEngine:
    """Get or create the global stealth engine instance."""
    global _stealth_engine
    if _stealth_engine is None:
        _stealth_engine = StealthEngine(logger, config_path=config_path)
    return _stealth_engine


def reset_stealth_engine() -> None:
    """Reset the global stealth engine."""
    global _stealth_engine
    if _stealth_engine:
        _stealth_engine.reset()