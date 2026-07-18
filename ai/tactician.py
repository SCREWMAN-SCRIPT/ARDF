"""
ai/tactician.py
───────────────
Tactician — handles tool failures and defensive responses.

When a tool fails, gets blocked, or returns no results,
the Tactician selects an alternate approach automatically.

Responsibilities
────────────────
  - Classify failure reason (WAF, timeout, auth, IDS, no results)
  - Select alternate tool or technique for same objective
  - Apply tamper/bypass strategies for WAF-blocked tools
  - Adjust scan parameters (rate, threads, payloads)
  - Generate AI-assisted alternate command suggestions
  - Track retry history to avoid infinite loops
"""

import time
import json
from typing import Any, Dict, List, Optional, Tuple

from ai.local_model  import LocalModel, get_model, load_prompt
from modules.logger  import get_logger, ARDFLogger
from modules.session import Session


# ─────────────────────────────────────────────────────────────
# Failure type constants
# ─────────────────────────────────────────────────────────────

class FailureType:
    WAF_BLOCKED    = "waf_blocked"
    IDS_BLOCKED    = "ids_blocked"
    RATE_LIMITED   = "rate_limited"
    AUTH_REQUIRED  = "auth_required"
    TIMEOUT        = "timeout"
    BINARY_MISSING = "binary_missing"
    NO_RESULTS     = "no_results"
    PARSE_ERROR    = "parse_error"
    NETWORK_ERROR  = "network_error"
    UNKNOWN        = "unknown"


# ─────────────────────────────────────────────────────────────
# Alternate tool mappings
# ─────────────────────────────────────────────────────────────

# Primary tool → list of alternates in priority order
TOOL_ALTERNATES: Dict[str, List[str]] = {
    # Subdomain enumeration
    "subfinder":       ["amass", "dnsx", "puredns", "crt_sh_api"],
    "amass":           ["subfinder", "puredns", "dnsx"],
    "puredns":         ["massdns", "dnsx", "shuffledns"],

    # Web crawling
    "gospider":        ["katana", "hakrawler", "cariddi", "photon"],
    "katana":          ["gospider", "hakrawler", "cariddi"],
    "hakrawler":       ["gospider", "katana", "photon"],

    # Directory fuzzing
    "ffuf":            ["gobuster", "wfuzz", "dirsearch", "feroxbuster"],
    "gobuster":        ["ffuf", "wfuzz", "feroxbuster"],
    "wfuzz":           ["ffuf", "gobuster", "feroxbuster"],

    # SQL injection
    "sqlmap":          ["ghauri", "nosqlmap"],
    "ghauri":          ["sqlmap"],

    # XSS
    "dalfox":          ["xsstrike"],
    "xsstrike":        ["dalfox"],

    # Port scanning
    "nmap":            ["masscan", "rustscan", "naabu"],
    "masscan":         ["nmap", "rustscan", "naabu"],
    "rustscan":        ["nmap", "masscan"],

    # HTTP probing
    "httpx":           ["curl", "wget"],
    "nikto":           ["whatweb", "nuclei"],

    # Password attacks
    "hydra":           ["medusa", "crackmapexec"],
    "medusa":          ["hydra", "crackmapexec"],
    "hashcat":         ["john"],
    "john":            ["hashcat"],

    # LFI
    "lfimap":          ["ffuf", "wfuzz"],
    "fimap":           ["lfimap", "ffuf"],

    # SSRF
    "ssrfmap":         ["gopherus"],

    # Nuclei
    "nuclei":          ["nikto", "whatweb"],

    # SMB
    "crackmapexec":    ["smbmap", "enum4linux-ng"],
    "smbmap":          ["crackmapexec", "enum4linux-ng"],
    "enum4linux-ng":   ["crackmapexec", "smbmap"],

    # Screenshots
    "gowitness":       ["eyewitness", "aquatone"],
    "eyewitness":      ["gowitness", "aquatone"],

    # Secrets
    "trufflehog":      ["secretfinder", "gitdorker"],
    "secretfinder":    ["trufflehog"],
}

# WAF tamper strategies for sqlmap
SQLMAP_TAMPERS: Dict[str, List[str]] = {
    "generic": [
        "space2comment,between",
        "charencode,space2comment",
        "charunicodeencode,space2comment",
        "randomcase,space2comment",
        "space2randomblank,between",
        "greatest,ifnull2ifisnull,space2comment",
        "charencode,charunicodeencode,space2comment,between",
    ],
    "cloudflare": [
        "charencode,space2comment,between",
        "charunicodeencode,space2comment",
        "randomcase,charencode",
    ],
    "modsecurity": [
        "space2comment,between,charencode",
        "greatest,space2comment",
        "ifnull2ifisnull,space2comment",
    ],
    "aws_waf": [
        "space2randomblank,charunicodeencode",
        "randomcase,space2randomblank",
    ],
}

# Rate limiting backoff strategies
BACKOFF_STRATEGIES = [
    {"delay": 2,  "threads": 10, "label": "slow"},
    {"delay": 5,  "threads": 5,  "label": "very_slow"},
    {"delay": 10, "threads": 2,  "label": "crawl"},
    {"delay": 30, "threads": 1,  "label": "ultra_slow"},
]

# HTTP header rotation for WAF bypass
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.68.0",
    "python-requests/2.28.0",
]


# ─────────────────────────────────────────────────────────────
# RetryTracker — prevents infinite retry loops
# ─────────────────────────────────────────────────────────────

class RetryTracker:
    def __init__(self, max_retries: int = 3):
        self._counts: Dict[str, int] = {}
        self.max     = max_retries

    def can_retry(self, key: str) -> bool:
        return self._counts.get(key, 0) < self.max

    def record(self, key: str):
        self._counts[key] = self._counts.get(key, 0) + 1

    def retry_count(self, key: str) -> int:
        return self._counts.get(key, 0)

    def reset(self, key: str):
        self._counts.pop(key, None)


# ─────────────────────────────────────────────────────────────
# Tactician
# ─────────────────────────────────────────────────────────────

class Tactician:
    """
    Failure handler and alternate tactic selector.

    When a tool fails or is blocked, Tactician:
      1. Classifies the failure type
      2. Selects an alternate tool or modified approach
      3. Returns an adjusted command/config for re-execution
    """

    def __init__(
        self,
        session:  Session,
        logger:   Optional[ARDFLogger] = None,
        ai_model: Optional[LocalModel] = None,
    ):
        self.session  = session
        self.logger   = logger or get_logger("ai.tactician")
        self.ai       = ai_model or get_model(role="tactical", logger=self.logger)
        self.tracker  = RetryTracker(max_retries=3)
        self._prompt  = load_prompt("select_tactic")
        self._backoff_idx: Dict[str, int] = {}

    # ── Public entry point ────────────────────────────────────

    def handle_failure(
        self,
        tool_name:      str,
        failure_type:   str,
        original_cmd:   List[str],
        stdout:         str = "",
        stderr:         str = "",
        context:        Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Main entry point. Returns a tactic decision dict:

        {
          "action":       retry | switch_tool | modify_params |
                          apply_tamper | backoff | skip | abort,
          "tool":         str,
          "cmd":          [str],
          "reason":       str,
          "delay":        int,
          "modifications": dict,
        }
        """
        retry_key = f"{tool_name}:{failure_type}"

        if not self.tracker.can_retry(retry_key):
            self.logger.warning(
                f"Max retries reached for {tool_name} ({failure_type}). Skipping."
            )
            return self._decision("skip", tool_name, original_cmd,
                                  "Max retries exhausted")

        self.tracker.record(retry_key)
        attempt = self.tracker.retry_count(retry_key)

        self.logger.info(
            f"Handling {failure_type} for {tool_name} "
            f"(attempt {attempt}/3)"
        )

        handler = {
            FailureType.WAF_BLOCKED:    self._handle_waf,
            FailureType.IDS_BLOCKED:    self._handle_ids,
            FailureType.RATE_LIMITED:   self._handle_rate_limit,
            FailureType.AUTH_REQUIRED:  self._handle_auth,
            FailureType.TIMEOUT:        self._handle_timeout,
            FailureType.BINARY_MISSING: self._handle_missing_binary,
            FailureType.NO_RESULTS:     self._handle_no_results,
            FailureType.NETWORK_ERROR:  self._handle_network_error,
            FailureType.UNKNOWN:        self._handle_unknown,
        }.get(failure_type, self._handle_unknown)

        decision = handler(tool_name, original_cmd, stdout, stderr, context or {})

        self.logger.info(
            f"Tactic decision: {decision['action']} "
            f"tool={decision['tool']} reason={decision['reason'][:60]}"
        )
        return decision

    # ── Failure handlers ──────────────────────────────────────

    def _handle_waf(
        self,
        tool:    str,
        cmd:     List[str],
        stdout:  str,
        stderr:  str,
        context: Dict,
    ) -> Dict:
        """WAF detected — apply bypass techniques."""
        waf_type = self._detect_waf_type(stdout + stderr)
        attempt  = self.tracker.retry_count(f"{tool}:{FailureType.WAF_BLOCKED}")

        # sqlmap — rotate tamper scripts
        if tool == "sqlmap":
            tampers = SQLMAP_TAMPERS.get(waf_type, SQLMAP_TAMPERS["generic"])
            tamper  = tampers[min(attempt - 1, len(tampers) - 1)]
            new_cmd = self._replace_arg(cmd, "--tamper", tamper)
            new_cmd = self._add_args(new_cmd, ["--random-agent", "--delay=2"])
            return self._decision(
                "apply_tamper", tool, new_cmd,
                f"WAF ({waf_type}) detected — applying tamper: {tamper}",
                modifications={"tamper": tamper, "waf_type": waf_type}
            )

        # nuclei — reduce rate and add random-agent
        if tool == "nuclei":
            new_cmd = self._add_args(
                cmd, ["-rl", "5", "-c", "3", "-H", f"User-Agent: {USER_AGENTS[attempt % len(USER_AGENTS)]}"]
            )
            return self._decision(
                "modify_params", tool, new_cmd,
                "WAF detected — reducing nuclei rate and rotating UA",
            )

        # ffuf/gobuster — slow down and rotate UA
        if tool in ("ffuf", "gobuster", "wfuzz"):
            new_cmd = self._add_args(cmd, ["-H", f"User-Agent: {USER_AGENTS[attempt % len(USER_AGENTS)]}"])
            if tool == "ffuf":
                new_cmd = self._replace_arg(new_cmd, "-t", "5")
                new_cmd = self._add_args(new_cmd, ["-p", "0.5"])
            return self._decision(
                "modify_params", tool, new_cmd,
                "WAF detected — slowing request rate and rotating User-Agent",
            )

        # Generic — switch to alternate tool
        alternate = self._pick_alternate(tool)
        if alternate:
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"WAF blocked {tool} — switching to {alternate}",
            )

        return self._decision("skip", tool, cmd, f"WAF blocked {tool} — no bypass available")

    def _handle_ids(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """IDS detected — slow down significantly."""
        attempt = self.tracker.retry_count(f"{tool}:{FailureType.IDS_BLOCKED}")
        delay   = [5, 15, 30][min(attempt - 1, 2)]
        self.logger.warning(f"IDS detected — applying {delay}s delay")
        time.sleep(delay)

        # Reduce aggression
        new_cmd = cmd.copy()
        if "-T4" in new_cmd: new_cmd[new_cmd.index("-T4")] = "-T2"
        if "-T5" in new_cmd: new_cmd[new_cmd.index("-T5")] = "-T1"
        new_cmd = self._add_args(new_cmd, ["--randomize-hosts"])

        return self._decision(
            "retry", tool, new_cmd,
            f"IDS detected — reduced scan speed, {delay}s delay applied",
            delay=delay,
        )

    def _handle_rate_limit(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Rate limited — apply exponential backoff."""
        key     = f"{tool}:backoff"
        idx     = self._backoff_idx.get(key, 0)
        strat   = BACKOFF_STRATEGIES[min(idx, len(BACKOFF_STRATEGIES) - 1)]
        self._backoff_idx[key] = idx + 1

        self.logger.info(f"Rate limited — backing off {strat['delay']}s, threads={strat['threads']}")
        time.sleep(strat["delay"])

        new_cmd = self._set_threads(cmd, strat["threads"])
        return self._decision(
            "retry", tool, new_cmd,
            f"Rate limited — backoff {strat['delay']}s, threads={strat['threads']}",
            delay=strat["delay"],
            modifications={"strategy": strat["label"]},
        )

    def _handle_auth(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Auth required — check if we have credentials in session."""
        cred_findings = self.session.get_findings()
        creds = [f for f in cred_findings if "credentials" in " ".join(f.tags)]

        if creds:
            latest = creds[-1]
            # Try to extract user/pass from evidence
            cred_evidence = latest.evidence
            self.logger.info(f"Auth required — found credentials in session findings")
            return self._decision(
                "modify_params", tool, cmd,
                f"Auth required — credentials available from finding {latest.id}",
                modifications={"credential_finding": latest.id, "evidence": cred_evidence[:100]},
            )

        # No creds available — try alternate or skip
        alternate = self._pick_alternate(tool)
        if alternate:
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"Auth required for {tool}, no credentials — switching to {alternate}",
            )

        return self._decision(
            "skip", tool, cmd,
            "Auth required — no credentials available, skipping",
        )

    def _handle_timeout(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Timeout — retry with reduced scope or longer timeout."""
        attempt = self.tracker.retry_count(f"{tool}:{FailureType.TIMEOUT}")

        if attempt == 1:
            # First retry — increase timeout
            new_cmd = self._replace_arg(cmd, "--timeout", "120")
            new_cmd = self._replace_arg(new_cmd, "-timeout", "120")
            return self._decision(
                "retry", tool, new_cmd,
                "Timeout — retrying with extended timeout",
                delay=5,
            )

        if attempt == 2:
            # Second retry — reduce scope
            new_cmd = self._reduce_scope(cmd, tool)
            return self._decision(
                "retry", tool, new_cmd,
                "Timeout — retrying with reduced scope",
                delay=10,
            )

        # Final — switch to faster alternate
        alternate = self._pick_alternate(tool)
        if alternate:
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"Persistent timeout on {tool} — switching to {alternate}",
            )

        return self._decision("skip", tool, cmd, "Persistent timeout — skipping")

    def _handle_missing_binary(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Binary not found — switch to alternate immediately."""
        self.logger.warning(f"{tool} binary not found")
        alternate = self._pick_alternate(tool)

        if alternate:
            self.logger.info(f"Switching {tool} → {alternate}")
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"{tool} not installed — using {alternate}",
            )

        return self._decision(
            "skip", tool, cmd,
            f"{tool} not installed and no alternate available",
        )

    def _handle_no_results(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """No results returned — try broader approach or AI suggestion."""
        attempt = self.tracker.retry_count(f"{tool}:{FailureType.NO_RESULTS}")

        if attempt == 1:
            # Broaden wordlist or parameters
            new_cmd = self._broaden_wordlist(cmd, tool)
            if new_cmd != cmd:
                return self._decision(
                    "modify_params", tool, new_cmd,
                    "No results — switching to larger wordlist",
                )

        # Ask AI for alternate approach
        ai_suggestion = self._ai_suggest_alternate(tool, cmd, context)
        if ai_suggestion:
            return self._decision(
                "switch_tool", ai_suggestion["tool"],
                ai_suggestion["cmd"],
                f"No results from {tool} — AI suggested {ai_suggestion['tool']}",
            )

        alternate = self._pick_alternate(tool)
        if alternate:
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"No results from {tool} — trying {alternate}",
            )

        return self._decision("skip", tool, cmd, "No results — skipping after all attempts")

    def _handle_network_error(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Network error — wait and retry."""
        attempt = self.tracker.retry_count(f"{tool}:{FailureType.NETWORK_ERROR}")
        delay   = [10, 30, 60][min(attempt - 1, 2)]
        self.logger.warning(f"Network error — waiting {delay}s before retry")
        time.sleep(delay)
        return self._decision(
            "retry", tool, cmd,
            f"Network error — retrying after {delay}s",
            delay=delay,
        )

    def _handle_unknown(
        self, tool: str, cmd: List[str], stdout: str, stderr: str, context: Dict
    ) -> Dict:
        """Unknown failure — try AI, then alternate, then skip."""
        ai_suggestion = self._ai_suggest_alternate(tool, cmd, context)
        if ai_suggestion:
            return self._decision(
                "switch_tool", ai_suggestion["tool"],
                ai_suggestion["cmd"],
                f"Unknown failure on {tool} — AI suggested {ai_suggestion['tool']}",
            )
        alternate = self._pick_alternate(tool)
        if alternate:
            return self._decision(
                "switch_tool", alternate,
                self._build_alternate_cmd(alternate, cmd, context),
                f"Unknown failure on {tool} — trying {alternate}",
            )
        return self._decision("skip", tool, cmd, "Unknown failure — skipping")

    # ── AI alternate suggestion ───────────────────────────────

    def _ai_suggest_alternate(
        self,
        tool:    str,
        cmd:     List[str],
        context: Dict,
    ) -> Optional[Dict]:
        """Ask local AI for alternate tool/command suggestion."""
        if not self._prompt:
            return None

        prompt = self._prompt.format(
            tool        = tool,
            cmd         = " ".join(str(c) for c in cmd),
            target      = self.session.meta.target,
            context     = json.dumps(context, indent=2)[:400],
            alternates  = json.dumps(TOOL_ALTERNATES.get(tool, []), indent=2),
        )

        result = self.ai.json_generate(prompt=prompt, temperature=0.1)
        if not result:
            return None

        alt_tool = result.get("tool", "")
        alt_cmd  = result.get("cmd", [])

        if not alt_tool or not alt_cmd:
            return None

        return {"tool": alt_tool, "cmd": alt_cmd}

    # ── Utilities ─────────────────────────────────────────────

    def _decision(
        self,
        action:        str,
        tool:          str,
        cmd:           List[str],
        reason:        str,
        delay:         int = 0,
        modifications: Optional[Dict] = None,
    ) -> Dict:
        return {
            "action":        action,
            "tool":          tool,
            "cmd":           cmd,
            "reason":        reason,
            "delay":         delay,
            "modifications": modifications or {},
        }

    def _pick_alternate(self, tool: str) -> Optional[str]:
        """Pick first available alternate for a tool."""
        import subprocess
        for alt in TOOL_ALTERNATES.get(tool, []):
            try:
                subprocess.run(
                    ["which", alt],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return alt
            except subprocess.CalledProcessError:
                continue
        return None

    def _build_alternate_cmd(
        self,
        alternate: str,
        original_cmd: List[str],
        context: Dict,
    ) -> List[str]:
        """Build a basic command for alternate tool using context."""
        target = context.get("target", self.session.meta.target)
        url    = context.get("url", "")
        output = context.get("output", "")

        templates = {
            "amass":         ["amass", "enum", "-passive", "-d", target],
            "dnsx":          ["dnsx", "-d", target, "-a", "-silent"],
            "subfinder":     ["subfinder", "-d", target, "-silent"],
            "gobuster":      ["gobuster", "dir", "-u", url or f"http://{target}",
                              "-w", "/usr/share/wordlists/dirb/common.txt"],
            "ffuf":          ["ffuf", "-u", f"{url or 'http://'+target}/FUZZ",
                              "-w", "/usr/share/wordlists/dirb/common.txt"],
            "wfuzz":         ["wfuzz", "-c", "-z", "file,/usr/share/wordlists/dirb/common.txt",
                              "--hc", "404", f"{url or 'http://'+target}/FUZZ"],
            "katana":        ["katana", "-u", url or f"http://{target}", "-silent"],
            "hakrawler":     ["hakrawler", "-url", url or f"http://{target}"],
            "masscan":       ["masscan", target, "-p1-65535", "--rate=1000"],
            "nmap":          ["nmap", "-sV", "--top-ports", "1000", target],
            "hydra":         ["hydra", "-L", "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                              "-P", "/usr/share/wordlists/rockyou.txt", target, "ssh"],
            "medusa":        ["medusa", "-H", target, "-U",
                              "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                              "-P", "/usr/share/wordlists/rockyou.txt", "-M", "ssh"],
            "john":          ["john", "--wordlist=/usr/share/wordlists/rockyou.txt",
                              output or "hashes.txt"],
            "ghauri":        ["ghauri", "-u", url or f"http://{target}", "--batch"],
            "xsstrike":      ["xsstrike", "--url", url or f"http://{target}", "--crawl"],
            "smbmap":        ["smbmap", "-H", target],
            "enum4linux-ng": ["enum4linux-ng", target, "-A"],
            "eyewitness":    ["eyewitness", "--single", url or f"http://{target}"],
            "aquatone":      ["aquatone", "-url", url or f"http://{target}"],
            "nikto":         ["nikto", "-h", url or f"http://{target}"],
            "whatweb":       ["whatweb", url or f"http://{target}"],
            "secretfinder":  ["python3", "/opt/secretfinder/SecretFinder.py",
                              "-i", url or f"http://{target}", "-o", "cli"],
        }

        return templates.get(alternate, [alternate, target])

    def _detect_waf_type(self, text: str) -> str:
        text_lower = text.lower()
        if "cloudflare" in text_lower: return "cloudflare"
        if "mod_security" in text_lower: return "modsecurity"
        if "aws" in text_lower: return "aws_waf"
        if "imperva" in text_lower: return "imperva"
        if "akamai" in text_lower: return "akamai"
        return "generic"

    def _replace_arg(self, cmd: List[str], flag: str, value: str) -> List[str]:
        """Replace a flag's value in a command list."""
        new_cmd = cmd.copy()
        for i, arg in enumerate(new_cmd):
            if arg == flag and i + 1 < len(new_cmd):
                new_cmd[i + 1] = value
                return new_cmd
            if arg.startswith(f"{flag}="):
                new_cmd[i] = f"{flag}={value}"
                return new_cmd
        new_cmd += [flag, value]
        return new_cmd

    def _add_args(self, cmd: List[str], args: List[str]) -> List[str]:
        """Add arguments to command if not already present."""
        new_cmd = cmd.copy()
        for i in range(0, len(args), 2):
            flag  = args[i]
            value = args[i + 1] if i + 1 < len(args) else None
            if flag not in new_cmd:
                new_cmd.append(flag)
                if value:
                    new_cmd.append(value)
        return new_cmd

    def _set_threads(self, cmd: List[str], threads: int) -> List[str]:
        """Set thread count in command."""
        for flag in ("-t", "--threads", "-c", "--concurrency"):
            cmd = self._replace_arg(cmd, flag, str(threads))
        return cmd

    def _reduce_scope(self, cmd: List[str], tool: str) -> List[str]:
        """Reduce scan scope for timeout recovery."""
        new_cmd = cmd.copy()
        if tool == "nmap":
            if "-p-" in new_cmd:
                idx = new_cmd.index("-p-")
                new_cmd[idx] = "--top-ports"
                new_cmd.insert(idx + 1, "100")
        if tool == "masscan":
            new_cmd = self._replace_arg(new_cmd, "--rate", "100")
        return new_cmd

    def _broaden_wordlist(self, cmd: List[str], tool: str) -> List[str]:
        """Switch to a larger wordlist."""
        small  = "/usr/share/wordlists/dirb/common.txt"
        medium = "/usr/share/wordlists/dirb/big.txt"
        large  = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

        new_cmd = cmd.copy()
        for i, arg in enumerate(new_cmd):
            if small in arg:
                new_cmd[i] = arg.replace(small, medium)
                return new_cmd
            if medium in arg:
                new_cmd[i] = arg.replace(medium, large)
                return new_cmd
        return cmd
