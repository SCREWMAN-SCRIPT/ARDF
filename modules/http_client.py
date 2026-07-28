"""
modules/http_client.py
─────────────────────
Resilient HTTP client for ARDF.

Features:
- `requests` session with retries
- Browser-like headers and optional X-Forwarded-For spoofing
- Cookie handling (initial probe then reuse)
- Cloudscraper fallback for common Cloudflare challenges
- Playwright and Selenium headless fallbacks for full JS rendering

All fallbacks are optional and only used when the corresponding packages
are available in the environment.
"""
from typing import Optional, Tuple, Dict, Any
import os
import yaml
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

_session: Optional[requests.Session] = None


def _load_config() -> Dict[str, Any]:
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "config", "ardf.yaml")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _init_session(proxy: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({
        "User-Agent": "ARDF/2.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    return s


def get_session(proxy: Optional[str] = None) -> requests.Session:
    global _session
    if _session is None or proxy:
        _session = _init_session(proxy=proxy)
    return _session


def _random_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _browser_like_headers(base: Optional[dict] = None) -> Dict[str, str]:
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ua += " (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://www.google.com/",
        "Cache-Control": "max-age=0",
    }
    if base:
        headers.update(base)
    return headers


def _try_cloudscraper(url: str, timeout: int, headers: Optional[dict], verify: bool, proxy: Optional[str]):
    try:
        import cloudscraper
    except Exception:
        return None
    try:
        cs = cloudscraper.create_scraper()
        if proxy:
            cs.proxies.update({"http": proxy, "https": proxy})
        resp = cs.get(url, timeout=timeout, headers=(headers or {}), allow_redirects=True, verify=verify)
        return resp
    except Exception:
        return None


def _try_selenium(url: str, timeout: int, headers: Optional[dict], proxy: Optional[str]):
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from webdriver_manager.chrome import ChromeDriverManager
    except Exception:
        return None
    try:
        options = Options()
        options.headless = True
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        if headers and headers.get('User-Agent'):
            options.add_argument(f"--user-agent={headers.get('User-Agent')}")
        if proxy:
            options.add_argument(f'--proxy-server={proxy}')

        driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
        driver.set_page_load_timeout(timeout)
        try:
            driver.get(url)
            body = driver.page_source
            status_code = 200
            class Resp:
                def __init__(self, text, status_code):
                    self.text = text
                    self.status_code = status_code
                    self.headers = {'Content-Type': 'text/html'}
                def json(self):
                    raise ValueError('no json')
            resp = Resp(body, status_code)
            return resp
        finally:
            try:
                driver.quit()
            except Exception:
                pass
    except Exception:
        return None


def _try_playwright(url: str, timeout: int, headers: Optional[dict], proxy: Optional[str]):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context_args = {}
            if headers and headers.get('User-Agent'):
                context_args['user_agent'] = headers.get('User-Agent')
            if proxy:
                context_args['proxy'] = {"server": proxy}
            context = browser.new_context(**context_args)
            page = context.new_page()
            page.goto(url, timeout=timeout * 1000)
            body = page.content()
            browser.close()
            class Resp:
                def __init__(self, text):
                    self.text = text
                    self.status_code = 200
                    self.headers = {'Content-Type': 'text/html'}
                def json(self):
                    raise ValueError('no json')
            return Resp(body)
    except Exception:
        return None


def fetch(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
    verify: bool = False,
    proxy: Optional[str] = None,
) -> Optional[requests.Response]:
    """Perform an HTTP request and return a Response-like object or None.

    Strategy:
    1. Use `requests` with browser-like headers and retries.
    2. If blocked (403/429/5xx), try `cloudscraper`.
    3. If still blocked, try Playwright (if installed), then Selenium.

    Proxy selection and rotation is governed by config/network in `ardf.yaml` or
    the `ARDF_PROXY` environment variable.
    """
    cfg = _load_config()
    if not proxy:
        proxy = os.environ.get("ARDF_PROXY")
        try:
            net = cfg.get("network", {}) or {}
            proxies = net.get("proxies", []) if net else []
            rotate = net.get("rotate_proxies", False) if net else False
            if proxies:
                proxy = random.choice(proxies) if rotate else proxies[0]
        except Exception:
            pass

    session = get_session(proxy=proxy)
    # Build headers
    bl_headers = _browser_like_headers(headers)
    # Optionally spoof X-Forwarded-For for simple WAF bypass heuristics
    try:
        netcfg = cfg.get("network", {}) or {}
        if netcfg.get("spoof_xff", True):
            bl_headers.setdefault("X-Forwarded-For", _random_ipv4())
    except Exception:
        pass

    # First attempt with requests
    try:
        resp = session.request(
            method=method,
            url=url,
            timeout=timeout,
            headers=bl_headers,
            allow_redirects=allow_redirects,
            verify=verify,
        )
        # If server indicates blockage, try fallbacks
        if resp is None or resp.status_code in (403, 429) or resp.status_code >= 500:
            # cloudscraper
            cs = _try_cloudscraper(url, timeout, bl_headers, verify, proxy)
            if cs:
                return cs
            # playwright
            pl = _try_playwright(url, timeout, bl_headers, proxy)
            if pl:
                return pl
            # selenium
            sel = _try_selenium(url, timeout, bl_headers, proxy)
            return sel or resp
        return resp
    except Exception:
        # Try fallbacks in order
        cs = _try_cloudscraper(url, timeout, bl_headers, verify, proxy)
        if cs:
            return cs
        pl = _try_playwright(url, timeout, bl_headers, proxy)
        if pl:
            return pl
        sel = _try_selenium(url, timeout, bl_headers, proxy)
        return sel
