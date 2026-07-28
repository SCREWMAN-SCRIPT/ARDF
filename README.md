# ARDF — Autonomous Red/Blue Defense Framework

**Version:** 1.0.0 — NightHawk  
**Mode:** Offline-first | Local AI | Kali-native

---

## What It Is

ARDF is a local-first, AI-orchestrated cyber operations platform built on top of the full Kali toolchain. The AI does not replace your tools — it replaces the manual decision loop between them.

Every tool you already have on Kali becomes a callable primitive. The framework wraps them in an intelligent execution layer driven by natural language or a structured playbook, with human confirmation gates before any active testing.

**All inference runs locally via Ollama. No data leaves the machine.**

---

## Architecture

```
ardf/
├── ardf.py                    Main CLI entry point
├── requirements.txt
├── config/
│   ├── ardf.yaml              Global configuration
│   ├── playbooks/             Mission playbooks (YAML)
│   └── wordlists.yaml         Wordlist path registry
│
├── ai/                        Local AI layer (Ollama)
│   ├── local_model.py         Ollama interface
│   ├── planner.py             Objective → task plan
│   ├── analyst.py             Finding interpreter
│   ├── tactician.py           Failure handler
│   └── prompts/               Prompt templates
│
├── core/                      Orchestration engine
│   ├── orchestrator.py        Mission execution loop
│   ├── mission.py             Mission lifecycle
│   ├── task_graph.py          Dependency graph
│   ├── confirmation_gate.py   Human-in-the-loop gates
│   └── response_classifier.py Tool output classifier
│
├── modules/                   Execution primitives
│   ├── recon.py               Reconnaissance (passive/normal/depth)
│   ├── exploit.py             Exploitation modules
│   ├── intel.py               CVE, Shodan, AbuseIPDB, VirusTotal
│   ├── session.py             Session and findings management
│   ├── logger.py              Structured logging
│   ├── report.py              HTML report engine
│   ├── defense/               Blue team modules
│   │   ├── sigma_writer.py    Sigma detection rule generator
│   │   ├── hardening.py       Hardening script generator
│   │   ├── remediation.py     Remediation plan builder
│   │   └── monitor.py         Read-only security monitor
│   └── purple/                Purple team modules
│       ├── purple_runner.py   Parallel red+blue execution
│       └── coverage_mapper.py MITRE coverage analysis
│
├── interface/                 Terminal interface
│   ├── chat.py                Natural language command interface
│   ├── banner.py              Startup display
│   └── progress.py            Live progress display
│
├── playbook/                  Playbook system
│   ├── loader.py              YAML playbook loader
│   ├── executor.py            Playbook → mission plan
│   └── validator.py           Schema validator
│
├── graph/                     Finding relationship graph
│   ├── finding_graph.py       Node/edge graph builder
│   ├── attack_path.py         Multi-step path detector
│   └── kill_chain_mapper.py   MITRE kill chain mapper
│
├── daemon/                    Background services
│   ├── monitor_daemon.py      Continuous monitoring daemon
│   ├── scheduler.py           Passive job scheduler
│   └── alerter.py             Delta finding alerter
│
└── tests/                     Test suite
    ├── test_orchestrator.py
    ├── test_modules.py
    └── test_decision_engine.py
```

---

## Quick Start

### Prerequisites

```bash
# Python dependencies
pip install -r requirements.txt --break-system-packages

# Ollama (local AI)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:0.5b
ollama pull tinyllama:1.1b   # fallback model
```

### Basic usage

```bash
# Interactive chat interface
python ardf.py --chat

# Run passive OSINT on a target
python ardf.py --target example.com --depth passive

# Run a playbook
python ardf.py --target example.com --playbook passive
python ardf.py --target example.com --playbook web

# Natural language objective
python ardf.py --target example.com --objective "enumerate subdomains passively"

# Blue team — generate hardening report from existing session
python ardf.py --session <session_id> --harden

# Generate Sigma detection rules
python ardf.py --session <session_id> --sigma

# Generate MITRE coverage map
python ardf.py --session <session_id> --coverage

# Run security monitors (read-only)
python ardf.py --session <session_id> --monitor

# List all sessions
python ardf.py --sessions
```

### Run the test suite

```bash
pytest tests/ -v --tb=short
```

---

## HTTP client & WAF bypass

ARDF now includes an improved HTTP client used by recon and web modules. Key features:

- Automatic retries and browser-like headers to reduce simple WAF blocks.
- Cloudscraper fallback for common Cloudflare challenges.
- Playwright and Selenium headless fallbacks for full JS rendering when required.
- Proxy support and optional proxy rotation via `config/ardf.yaml` or `ARDF_PROXY` env var.
- X-Forwarded-For spoofing and cookie handling heuristics (used only when bypassing).

Setup notes:

1. Install Python requirements (includes `cloudscraper`, `selenium`, and `webdriver-manager`):

```bash
pip install -r requirements.txt
```

2. For Playwright (recommended for robust JS handling):

```bash
pip install playwright
python -m playwright install
```

3. For Selenium-based fallback (alternative):

```bash
pip install selenium webdriver-manager
# It's convenient to run a Chrome-enabled Selenium Docker container instead of
# managing local drivers: docker run -d -p 4444:4444 selenium/standalone-chrome
```

4. Configure proxies (optional): edit `config/ardf.yaml` under the `network` section and add `proxies:` and `rotate_proxies: true` if you want rotation.

See `docs/http_client.md` for full details and troubleshooting.

---

## Execution Modes

| Mode | Description |
|------|-------------|
| `red` | Offensive assessment — passive through active recon |
| `blue` | Defensive only — monitors, hardening, Sigma rules |
| `purple` | Simultaneous red + blue with detection correlation |
| `full` | Red + blue + intel + reporting |
| `osint` | Passive OSINT only — no direct target contact |

---

## Playbooks

Built-in playbooks in `config/playbooks/`:

| Name | Description |
|------|-------------|
| `full` | Full pentest — passive recon through reporting |
| `passive` | Passive OSINT — no direct target contact |
| `web` | Web application audit |
| `purple` | Purple team — attack + detect simultaneously |

---

## Capability Tiers

| Tier | Confirmation | Examples |
|------|-------------|---------|
| 1 | None | Passive recon, OSINT, monitoring |
| 2 | One-click yes/no | Active scanning, web audit |
| 3 | Typed CONFIRM | Any exploitation phase |

All Tier 2 and 3 tasks are gated behind explicit human confirmation.  
No autonomous offensive execution without operator approval.

---

## Output Structure

Each session creates:

```
output/sessions/<session_id>/
├── meta.json              Session metadata
├── findings.jsonl         All findings (append-only)
├── recon/                 Raw recon tool output
├── intel/                 Intel reports and CVE data
├── defense/               Monitor output and alerts
├── report/
│   ├── ardf_report_*.html      Full HTML report
│   ├── sigma_rules/            Sigma YAML rules
│   ├── hardening/              Hardening scripts
│   ├── remediation/            Remediation plan
│   └── purple/                 Coverage map and phase results
└── logs/
    ├── session_*.log           Plain text log
    ├── session_*.jsonl         Structured JSON log
    └── gate_audit.json         Confirmation gate audit trail
```

---

## Legal

This framework is intended for authorised security assessments only.  
Always obtain written permission before scanning or testing any system.  
The authors are not responsible for misuse.

---

## License

MIT
