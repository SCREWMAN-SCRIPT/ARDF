HTTP client
===========

This document describes the HTTP fallback strategies used by `modules/http_client.py`.

Fallback order:
- `requests` with browser-like headers and retries
- `cloudscraper` (if installed)
- `playwright` (if installed and browsers available)
- `selenium` + chromedriver (if installed)

Playwright setup (recommended for robust JS handling):
1. Install package:

```bash
pip install playwright
```

2. Install browsers:

```bash
python -m playwright install
```

Or use the Playwright Docker images if you prefer containerised execution.

Selenium (alternative):
- Install `selenium` and `webdriver-manager`:

```bash
pip install selenium webdriver-manager
```

- Ensure Chrome is available or use a Docker image with Chrome + chromedriver.

Docker option (Selenium):
- Use a prebuilt image like `selenium/standalone-chrome` and configure
  `config/ardf.yaml` `network.proxies` or `ARDF_PROXY` to route traffic.

Legal / Authorization
- Only use these bypass techniques against targets you have explicit
  authorization to test. ARDF contains a confirmation gate; keep records
  of authorization and scan logs.
