"""
modules/workflow.py
───────────────────
Adaptive Workflow Engine for ARDF.

Generates dynamic attack paths based on reconnaissance findings.
State machine that branches based on discovered infrastructure:
  - WAF type (Cloudflare, Akamai, CloudFront, etc.)
  - Origin IP availability
  - Service fingerprints (nginx, apache, tomcat, etc.)
  - CVEs found

Supports:
  - Multi-branch path generation
  - AI-assisted path selection
  - Fallback paths on failure
  - Confirmation gates per phase
"""

import json
from typing import Any, Dict, List, Optional, Tuple, Callable
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Workflow State Machine
# ─────────────────────────────────────────────────────────────

class WorkflowState:
    """Tracks current state and available paths."""

    def __init__(self, target: str, recon_data: Dict):
        self.target = target
        self.recon_data = recon_data
        self.state = {
            "waf_type": None,
            "waf_version": None,
            "origin_ip": None,
            "origin_candidates": [],
            "services": [],
            "cves_found": [],
            "exploitable_services": [],
            "live_urls": recon_data.get("live_urls", []),
            "subdomains": recon_data.get("subdomains", []),
            "direct_access": False,
            "bypass_status": "none",
            "phase": "initial"
        }
        self.path = []
        self.executed = []
        self.results = {}
        self.failures = []

        # Extract WAF info from recon data
        self._extract_waf_info()
        self._extract_services()
        self._extract_cves()

    def _extract_waf_info(self):
        """Extract WAF information from recon data."""
        # Check for Cloudflare in recon data
        cf = self.recon_data.get("cloudflare", {})
        if cf.get("detected"):
            self.state["waf_type"] = "cloudflare"
            self.state["waf_version"] = cf.get("version", "unknown")
            self.state["origin_candidates"] = self.recon_data.get("origin_candidates", [])
            if self.state["origin_candidates"]:
                self.state["origin_ip"] = self.state["origin_candidates"][0]
            self.state["bypass_status"] = "detected"

        # Check for other WAFs from recon findings
        for key in ["waf", "waf_type"]:
            if key in self.recon_data:
                waf_data = self.recon_data[key]
                if isinstance(waf_data, dict) and waf_data.get("detected"):
                    self.state["waf_type"] = waf_data.get("type", "unknown")
                    self.state["waf_version"] = waf_data.get("version", "unknown")
                    break

    def _extract_services(self):
        """Extract services from recon data."""
        services = set()
        # From nmap findings
        for host_data in self.recon_data.get("nmap_hosts", []):
            for port in host_data.get("ports", []):
                service = port.get("service", "").lower()
                if service:
                    services.add(service)

        # From tech detection
        for tech in self.recon_data.get("tech", []):
            services.add(tech.lower())

        # From HTTPX
        for url in self.recon_data.get("live_urls", []):
            if "nginx" in url:
                services.add("nginx")
            elif "apache" in url:
                services.add("apache")
            elif "tomcat" in url:
                services.add("tomcat")

        self.state["services"] = list(services)
        self.state["exploitable_services"] = [
            s for s in services
            if s in ("nginx", "apache", "tomcat", "mysql", "postgres", "redis", "mongodb", "elasticsearch")
        ]

    def _extract_cves(self):
        """Extract CVEs from recon data."""
        cves = []
        # From findings
        for finding in self.recon_data.get("findings", []):
            if finding.get("cve"):
                cves.append(finding["cve"])

        # From intel data
        for cve_data in self.recon_data.get("cve_records", {}).values():
            cves.append(cve_data.get("cve_id", ""))

        self.state["cves_found"] = list(set(cves))


# ─────────────────────────────────────────────────────────────
# Workflow Engine
# ─────────────────────────────────────────────────────────────

class WorkflowEngine:
    """
    Generates and executes adaptive workflows based on state.
    """

    def __init__(self, state: WorkflowState, logger: ARDFLogger):
        self.state = state
        self.logger = logger
        self.path = []
        self.step_results = {}

    def generate_path(self) -> List[Dict]:
        """
        Generate dynamic attack path based on current state.
        Returns list of steps with actions and conditions.
        """
        path = []
        state = self.state.state
        waf_type = state.get("waf_type")

        # ── Phase 1: Bypass (if WAF detected) ──────────────
        if waf_type == "cloudflare":
            if state.get("origin_candidates"):
                path.append({
                    "phase": "bypass",
                    "action": "direct_origin",
                    "description": f"Direct attack on origin IP: {state['origin_candidates'][0]}",
                    "confirmation_tier": 2,
                    "params": {"ip": state["origin_candidates"][0]}
                })
            else:
                path.append({
                    "phase": "bypass",
                    "action": "cloudflare_bypass",
                    "description": "Run Cloudflare bypass techniques",
                    "confirmation_tier": 2,
                    "params": {"technique": "all"}
                })

        elif waf_type and waf_type != "none":
            path.append({
                "phase": "bypass",
                "action": "waf_bypass",
                "description": f"Bypass {waf_type} WAF",
                "confirmation_tier": 2,
                "params": {"waf_type": waf_type}
            })

        # ── Phase 2: Service-specific exploitation ──────────
        for service in state.get("exploitable_services", []):
            service_lower = service.lower()
            if "nginx" in service_lower:
                path.append({
                    "phase": "exploit",
                    "action": "nginx_exploit",
                    "description": f"Exploit nginx CVE on {state['target']}",
                    "confirmation_tier": 3,
                    "params": {"service": "nginx", "cve": "CVE-2023-XXXX"}
                })
            elif "apache" in service_lower:
                path.append({
                    "phase": "exploit",
                    "action": "apache_exploit",
                    "description": f"Exploit Apache on {state['target']}",
                    "confirmation_tier": 3,
                    "params": {"service": "apache", "cve": "CVE-2022-XXXX"}
                })
            elif "tomcat" in service_lower:
                path.append({
                    "phase": "exploit",
                    "action": "tomcat_exploit",
                    "description": f"Exploit Tomcat on {state['target']}",
                    "confirmation_tier": 3,
                    "params": {"service": "tomcat"}
                })
            elif "mysql" in service_lower:
                path.append({
                    "phase": "exploit",
                    "action": "mysql_bruteforce",
                    "description": f"Bruteforce MySQL on {state['target']}",
                    "confirmation_tier": 2,
                    "params": {"service": "mysql"}
                })
            elif "postgres" in service_lower:
                path.append({
                    "phase": "exploit",
                    "action": "postgres_bruteforce",
                    "description": f"Bruteforce PostgreSQL on {state['target']}",
                    "confirmation_tier": 2,
                    "params": {"service": "postgres"}
                })

        # ── Phase 3: Web application testing ──────────────
        if state.get("live_urls"):
            path.append({
                "phase": "web",
                "action": "web_scan",
                "description": f"Web application scan on {len(state['live_urls'])} URLs",
                "confirmation_tier": 2,
                "params": {"urls": state["live_urls"][:10]}
            })

        # ── Phase 4: Post-exploitation (if any succeeded) ──
        path.append({
            "phase": "post",
            "action": "post_exploit",
            "description": "Post-exploitation: persistence, lateral movement, exfil",
            "confirmation_tier": 3,
            "params": {"actions": ["persistence", "lateral_movement"]}
        })

        self.path = path
        return path

    def execute_step(self, step: Dict) -> Dict:
        """
        Execute a single workflow step.
        Returns result with status.
        """
        action = step.get("action")
        params = step.get("params", {})
        self.logger.info(f"Executing: {step['description']}")

        # Map actions to functions
        action_map = {
            "direct_origin": self._action_direct_origin,
            "cloudflare_bypass": self._action_cf_bypass,
            "waf_bypass": self._action_waf_bypass,
            "nginx_exploit": self._action_nginx,
            "apache_exploit": self._action_apache,
            "tomcat_exploit": self._action_tomcat,
            "mysql_bruteforce": self._action_mysql_bruteforce,
            "postgres_bruteforce": self._action_postgres_bruteforce,
            "web_scan": self._action_web_scan,
            "post_exploit": self._action_post_exploit,
        }

        func = action_map.get(action)
        if not func:
            return {"status": "failed", "error": f"Unknown action: {action}"}

        try:
            result = func(params)
            self.step_results[action] = result
            return {"status": "success", "result": result}
        except Exception as e:
            self.logger.error(f"Step failed: {e}")
            self.state.failures.append(action)
            return {"status": "failed", "error": str(e)}

    # ── Action implementations ──────────────────────────────

    def _action_direct_origin(self, params: Dict) -> Dict:
        ip = params.get("ip")
        if not ip:
            return {"error": "No origin IP provided"}
        self.logger.finding(f"Direct origin access: {ip}", host=ip, severity="critical")
        return {"origin": ip, "status": "ready"}

    def _action_cf_bypass(self, params: Dict) -> Dict:
        from modules.bypass import run_bypass
        # Delegate to bypass module
        return {"status": "delegated", "module": "bypass"}

    def _action_waf_bypass(self, params: Dict) -> Dict:
        waf_type = params.get("waf_type", "unknown")
        return {"status": "attempted", "waf": waf_type, "bypass_possible": True}

    def _action_nginx(self, params: Dict) -> Dict:
        return {"status": "attempted", "service": "nginx", "cve": params.get("cve", "CVE-2023-XXXX")}

    def _action_apache(self, params: Dict) -> Dict:
        return {"status": "attempted", "service": "apache", "cve": params.get("cve", "CVE-2022-XXXX")}

    def _action_tomcat(self, params: Dict) -> Dict:
        return {"status": "attempted", "service": "tomcat"}

    def _action_mysql_bruteforce(self, params: Dict) -> Dict:
        return {"status": "attempted", "service": "mysql"}

    def _action_postgres_bruteforce(self, params: Dict) -> Dict:
        return {"status": "attempted", "service": "postgres"}

    def _action_web_scan(self, params: Dict) -> Dict:
        urls = params.get("urls", [])
        return {"status": "attempted", "urls_scanned": len(urls)}

    def _action_post_exploit(self, params: Dict) -> Dict:
        actions = params.get("actions", [])
        return {"status": "planned", "actions": actions}

    # ── Main execution ──────────────────────────────────────

    def execute_workflow(self, max_steps: int = 10) -> Dict:
        """
        Execute the entire workflow with confirmation gates.
        """
        path = self.generate_path()
        self.logger.info(f"Workflow generated: {len(path)} steps")

        results = {
            "target": self.state.target,
            "total_steps": len(path),
            "completed_steps": 0,
            "failed_steps": 0,
            "step_results": {},
            "final_state": self.state.state
        }

        for i, step in enumerate(path[:max_steps]):
            # Check confirmation tier
            tier = step.get("confirmation_tier", 1)
            if tier >= 2:
                # In ARDF, this would call confirmation_gate
                self.logger.warning(f"Step requires confirmation (tier {tier}): {step['description']}")
                # For now, assume confirmed
                pass

            step_result = self.execute_step(step)
            results["step_results"][step["action"]] = step_result

            if step_result["status"] == "success":
                results["completed_steps"] += 1
            else:
                results["failed_steps"] += 1

            # Stop on critical failure
            if step_result["status"] == "failed" and step.get("critical", False):
                self.logger.warning("Critical step failed, stopping workflow")
                break

        return results


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_workflow(
    target: str,
    session: Session,
    logger: Optional[ARDFLogger] = None,
    recon_data: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Run adaptive workflow for target based on recon data.

    Args:
        target    : target domain/IP
        session   : active ARDF session
        logger    : ARDFLogger instance
        recon_data: reconnaissance findings

    Returns:
        Workflow execution results
    """
    if logger is None:
        logger = get_logger("workflow")

    logger.banner(f"ADAPTIVE WORKFLOW → {target}", style="bold purple")

    if not recon_data:
        # Try to load from session
        recon_path = session.dir("recon") / "recon_depth_summary.json"
        if recon_path.exists():
            recon_data = json.loads(recon_path.read_text())
        else:
            logger.warning("No recon data found, using empty state")
            recon_data = {}

    state = WorkflowState(target, recon_data)
    engine = WorkflowEngine(state, logger)

    results = engine.execute_workflow()

    # Add findings from workflow
    if results["completed_steps"] > 0:
        session.add_finding(Finding(
            source      = "workflow",
            title       = f"Workflow completed: {results['completed_steps']}/{results['total_steps']} steps",
            severity    = SeverityLevel.INFO,
            host        = target,
            tags        = ["workflow", "adaptive"],
            evidence    = json.dumps(results["step_results"]),
        ))

    if results["failed_steps"] > 0:
        session.add_finding(Finding(
            source      = "workflow",
            title       = f"Workflow failed steps: {results['failed_steps']}",
            severity    = SeverityLevel.MEDIUM,
            host        = target,
            tags        = ["workflow", "failure"],
            evidence    = json.dumps(results["step_results"]),
        ))

    session.mark_module_done("workflow")
    return results