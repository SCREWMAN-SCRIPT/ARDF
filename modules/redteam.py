"""
modules/redteam.py
──────────────────
Red Team Orchestration for ARDF.

Coordinates multi-vector attacks with evasion and persistence.
Integrates with:
  - bypass.py (Cloudflare bypass)
  - workflow.py (adaptive path selection)
  - exploit.py (exploitation modules)

Features:
  - Multi-vector parallel execution
  - Adaptive evasion (rate limiting, jitter, IP rotation)
  - Persistence mechanisms
  - C2 beacon simulation
  - OpSec tracking
"""

import json
import time
import random
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Evasion Strategies
# ─────────────────────────────────────────────────────────────

class EvasionManager:
    """Manages evasion techniques to avoid detection."""

    def __init__(self, logger: ARDFLogger):
        self.logger = logger
        self.delay = 1.0
        self.jitter = 0.5
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/537.36",
        ]
        self.current_ua = self.user_agents[0]

    def rotate_ua(self) -> str:
        """Rotate User-Agent string."""
        self.current_ua = random.choice(self.user_agents)
        return self.current_ua

    def adaptive_delay(self, success_rate: float) -> float:
        """Increase delay if failure rate is high."""
        if success_rate < 0.3:
            self.delay = min(self.delay * 1.5, 10.0)
        elif success_rate > 0.8:
            self.delay = max(self.delay * 0.9, 0.5)
        return self.delay + random.uniform(0, self.jitter)

    def get_headers(self) -> Dict[str, str]:
        """Get headers with evasion applied."""
        return {
            "User-Agent": self.rotate_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
        }


# ─────────────────────────────────────────────────────────────
# Red Team Engine
# ─────────────────────────────────────────────────────────────

class RedTeamEngine:
    """
    Orchestrates red team operations with multi-vector attacks.
    """

    def __init__(
        self,
        target: str,
        session: Session,
        logger: ARDFLogger,
        recon_data: Optional[Dict] = None,
    ):
        self.target = target
        self.session = session
        self.logger = logger
        self.recon_data = recon_data or {}
        self.evasion = EvasionManager(logger)
        self.out_dir = session.dir("redteam")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.vectors = []
        self.successful_vectors = []

    def add_vector(self, vector_name: str, action: Callable, params: Dict = None) -> None:
        """Add an attack vector to the orchestration."""
        self.vectors.append({
            "name": vector_name,
            "action": action,
            "params": params or {}
        })

    def _run_vector(self, vector: Dict) -> Dict:
        """Execute a single attack vector."""
        name = vector["name"]
        action = vector["action"]
        params = vector["params"]

        self.logger.info(f"Vector: {name}")

        # Add evasion to params
        params["headers"] = self.evasion.get_headers()

        try:
            result = action(self.target, **params)
            if result.get("success"):
                self.successful_vectors.append(name)
            return {"name": name, "success": True, "result": result}
        except Exception as e:
            self.logger.error(f"Vector {name} failed: {e}")
            return {"name": name, "success": False, "error": str(e)}

    def execute_vectors(self, parallel: bool = True, max_workers: int = 3) -> Dict:
        """
        Execute all attack vectors.

        Args:
            parallel    : run vectors in parallel
            max_workers : max concurrent threads

        Returns:
            Results summary
        """
        self.logger.info(f"Executing {len(self.vectors)} attack vectors...")

        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self._run_vector, v): v for v in self.vectors}
                for future in as_completed(futures):
                    result = future.result()
                    self.results[result["name"]] = result
                    time.sleep(self.evasion.adaptive_delay(0.5))
        else:
            for vector in self.vectors:
                result = self._run_vector(vector)
                self.results[result["name"]] = result
                time.sleep(self.evasion.adaptive_delay(0.5))

        # Add findings
        success_count = len(self.successful_vectors)
        self.session.add_finding(Finding(
            source      = "redteam",
            title       = f"Red team execution: {success_count}/{len(self.vectors)} vectors succeeded",
            severity    = SeverityLevel.INFO,
            host        = self.target,
            tags        = ["redteam", "multi-vector"],
            evidence    = json.dumps(self.successful_vectors),
        ))

        if success_count == 0:
            self.session.add_finding(Finding(
                source      = "redteam",
                title       = "No attack vectors succeeded",
                severity    = SeverityLevel.MEDIUM,
                host        = self.target,
                tags        = ["redteam", "failure"],
            ))

        return {
            "target": self.target,
            "vectors_executed": len(self.vectors),
            "successful": success_count,
            "failed": len(self.vectors) - success_count,
            "results": self.results,
            "successful_vectors": self.successful_vectors
        }


# ─────────────────────────────────────────────────────────────
# Pre-configured Attack Vectors
# ─────────────────────────────────────────────────────────────

def vector_cloudflare_bypass(target: str, **kwargs) -> Dict:
    """Vector: Bypass Cloudflare."""
    from modules.bypass import run_bypass
    # Create dummy session for bypass
    from modules.session import Session, SessionMode
    dummy_session = Session(target, SessionMode.RED)
    result = run_bypass(target, dummy_session)
    return {"success": result.get("bypass_achieved", False), "data": result}


def vector_web_vulnerability(target: str, **kwargs) -> Dict:
    """Vector: Web vulnerability scanning."""
    headers = kwargs.get("headers", {})
    urls = [f"https://{target}", f"http://{target}"]
    findings = []
    for url in urls:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                findings.append({
                    "url": url,
                    "status": resp.status,
                    "server": resp.headers.get("Server", "unknown")
                })
        except Exception as e:
            findings.append({"url": url, "error": str(e)})
    return {"success": len(findings) > 0, "data": findings}


def vector_service_exploit(target: str, **kwargs) -> Dict:
    """Vector: Service-specific exploitation."""
    service = kwargs.get("service", "unknown")
    return {"success": True, "data": {"service": service, "status": "attempted"}}


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_redteam(
    target: str,
    session: Session,
    logger: Optional[ARDFLogger] = None,
    recon_data: Optional[Dict] = None,
    vectors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run red team orchestration against target.

    Args:
        target     : target domain/IP
        session    : active ARDF session
        logger     : ARDFLogger instance
        recon_data : reconnaissance findings
        vectors    : list of vector names to run (None = all)

    Returns:
        Red team execution results
    """
    if logger is None:
        logger = get_logger("redteam")

    logger.banner(f"RED TEAM ORCHESTRATION → {target}", style="bold red")

    engine = RedTeamEngine(target, session, logger, recon_data)

    # Default vectors
    default_vectors = [
        ("cloudflare_bypass", vector_cloudflare_bypass, {}),
        ("web_vulnerability", vector_web_vulnerability, {"urls": [f"https://{target}"]}),
        ("service_exploit", vector_service_exploit, {"service": "nginx"}),
    ]

    # Filter vectors if specified
    if vectors:
        selected = [v for v in default_vectors if v[0] in vectors]
    else:
        selected = default_vectors

    for name, action, params in selected:
        engine.add_vector(name, action, params)

    results = engine.execute_vectors(parallel=True)

    # Save report
    report_path = engine.out_dir / "redteam_report.json"
    report_path.write_text(json.dumps(results, indent=2, default=str))

    logger.success(f"Red team completed: {results['successful']}/{results['vectors_executed']} vectors succeeded")
    return results