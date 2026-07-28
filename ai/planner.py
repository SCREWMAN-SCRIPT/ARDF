"""
ai/planner.py
─────────────
AI Planning module for ARDF.

Enhanced with Cloudflare-aware planning:
  - Detects Cloudflare in reconnaissance data
  - Generates bypass-first plans when CF detected
  - Prioritizes origin discovery before exploitation
  - Builds dependency graphs with bypass prerequisites

The planner converts high-level objectives into executable task graphs
with dependency resolution and confirmation tiers.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

@dataclass
class Task:
    """A single task in the execution plan."""
    id: str
    name: str
    module: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    confirmation_tier: int = 1  # 1=auto, 2=yes/no, 3=typed CONFIRM
    critical: bool = False
    description: str = ""


@dataclass
class Plan:
    """Complete execution plan with tasks and metadata."""
    objective: str
    target: str
    tasks: List[Task]
    context: Dict[str, Any] = field(default_factory=dict)
    estimated_steps: int = 0
    risk_level: str = "medium"


# ─────────────────────────────────────────────────────────────
# Planner Class
# ─────────────────────────────────────────────────────────────

class Planner:
    """
    AI-driven mission planner with Cloudflare awareness.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("planner")
        self._plan_cache: Dict[str, Plan] = {}

    # ── Objective parsing ────────────────────────────────────

    def parse_objective(self, objective: str) -> Dict[str, Any]:
        """Parse natural language objective into structured intent."""
        objective_lower = objective.lower()
        intent = {
            "type": "unknown",
            "target": None,
            "depth": "normal",
            "bypass_required": False,
            "exploit_type": None,
            "post_exploit": False
        }

        # Detect target
        target_match = re.search(r'(?:target|against|on)\s+([a-zA-Z0-9.-]+)', objective_lower)
        if target_match:
            intent["target"] = target_match.group(1)

        # Detect depth
        if "deep" in objective_lower or "depth" in objective_lower:
            intent["depth"] = "depth"
        elif "passive" in objective_lower or "osint" in objective_lower:
            intent["depth"] = "passive"
        else:
            intent["depth"] = "normal"

        # Detect bypass requirement
        if any(word in objective_lower for word in ["bypass", "cloudflare", "waf", "origin"]):
            intent["bypass_required"] = True

        # Detect exploit type
        if "web" in objective_lower or "app" in objective_lower:
            intent["exploit_type"] = "web"
        elif "network" in objective_lower:
            intent["exploit_type"] = "network"
        elif "credential" in objective_lower or "password" in objective_lower:
            intent["exploit_type"] = "credential"

        # Detect post-exploit
        if any(word in objective_lower for word in ["persist", "lateral", "exfil", "post"]):
            intent["post_exploit"] = True

        # Classify objective type
        if "recon" in objective_lower:
            intent["type"] = "recon"
        elif "exploit" in objective_lower or "attack" in objective_lower:
            intent["type"] = "exploit"
        elif "purple" in objective_lower:
            intent["type"] = "purple"
        elif "blue" in objective_lower or "defend" in objective_lower:
            intent["type"] = "blue"
        else:
            intent["type"] = "full"

        return intent

    # ── Cloudflare-aware plan generation ─────────────────────

    def generate_plan(
        self,
        objective: str,
        target: str,
        recon_data: Optional[Dict[str, Any]] = None,
        existing_findings: Optional[List[Finding]] = None,
    ) -> Plan:
        """
        Generate an execution plan from an objective.

        Args:
            objective: Natural language objective
            target: Target domain/IP
            recon_data: Existing reconnaissance data (for context)
            existing_findings: Existing findings (for context)

        Returns:
            Plan object with task list
        """
        self.logger.info(f"Generating plan for: {objective}")

        intent = self.parse_objective(objective)
        context = {
            "intent": intent,
            "target": target,
            "recon_data": recon_data or {},
            "findings": existing_findings or []
        }

        # Detect Cloudflare from recon data
        cloudflare_detected = self._detect_cloudflare(recon_data, existing_findings)
        origin_candidates = self._get_origin_candidates(recon_data, existing_findings)

        tasks = []

        # ── Phase 1: Reconnaissance ──────────────────────────
        if intent["type"] in ("recon", "full", "purple"):
            depth = intent.get("depth", "normal")
            tasks.append(Task(
                id="recon_1",
                name=f"Reconnaissance ({depth})",
                module="recon",
                action="run_recon",
                params={"depth": depth},
                confirmation_tier=1,
                description=f"Run {depth} reconnaissance on {target}"
            ))

        # ── Phase 2: Cloudflare Bypass (if detected) ────────
        if cloudflare_detected and intent.get("bypass_required", True):
            tasks.append(Task(
                id="bypass_1",
                name="Cloudflare Bypass",
                module="bypass",
                action="run_bypass",
                params={"technique": "all"},
                depends_on=["recon_1"] if tasks else [],
                confirmation_tier=2,
                critical=True,
                description=f"Bypass Cloudflare on {target} to find origin IP"
            ))

            # If origin candidates already exist, add direct attack
            if origin_candidates:
                tasks.append(Task(
                    id="origin_1",
                    name=f"Direct Origin Attack ({origin_candidates[0]})",
                    module="workflow",
                    action="direct_origin",
                    params={"ip": origin_candidates[0]},
                    depends_on=["bypass_1"],
                    confirmation_tier=2,
                    critical=True,
                    description=f"Directly attack origin IP {origin_candidates[0]}"
                ))

        # ── Phase 3: Exploitation ────────────────────────────
        if intent["type"] in ("exploit", "full", "purple"):
            exploit_type = intent.get("exploit_type", "web")

            if exploit_type == "web":
                tasks.append(Task(
                    id="exploit_web_1",
                    name="Web Application Exploitation",
                    module="exploit",
                    action="web_scan",
                    params={"mode": "web"},
                    depends_on=["origin_1"] if any(t.id == "origin_1" for t in tasks) else ["recon_1"],
                    confirmation_tier=3,
                    critical=True,
                    description="Run web application exploitation"
                ))
            elif exploit_type == "network":
                tasks.append(Task(
                    id="exploit_net_1",
                    name="Network Exploitation",
                    module="exploit",
                    action="network_scan",
                    params={"mode": "network"},
                    depends_on=["origin_1"] if any(t.id == "origin_1" for t in tasks) else ["recon_1"],
                    confirmation_tier=3,
                    critical=True,
                    description="Run network exploitation"
                ))
            else:
                tasks.append(Task(
                    id="exploit_full_1",
                    name="Full Exploitation",
                    module="exploit",
                    action="full",
                    params={"mode": "full"},
                    depends_on=["origin_1"] if any(t.id == "origin_1" for t in tasks) else ["recon_1"],
                    confirmation_tier=3,
                    critical=True,
                    description="Run full exploitation"
                ))

        # ── Phase 4: Post-Exploitation ───────────────────────
        if intent.get("post_exploit", False) and intent["type"] in ("exploit", "full"):
            tasks.append(Task(
                id="post_1",
                name="Post-Exploitation",
                module="redteam",
                action="post_exploit",
                params={"actions": ["persistence", "lateral_movement", "exfil"]},
                depends_on=["exploit_web_1", "exploit_net_1", "exploit_full_1"],
                confirmation_tier=3,
                description="Run post-exploitation actions"
            ))

        # ── Phase 5: Reporting ───────────────────────────────
        if intent["type"] in ("full", "purple"):
            tasks.append(Task(
                id="report_1",
                name="Generate Report",
                module="report",
                action="generate_report",
                params={"purple_mode": intent["type"] == "purple"},
                depends_on=[t.id for t in tasks if t.id.startswith("exploit") or t.id.startswith("recon")],
                confirmation_tier=1,
                description="Generate HTML report"
            ))

        # Build plan
        plan = Plan(
            objective=objective,
            target=target,
            tasks=tasks,
            context=context,
            estimated_steps=len(tasks),
            risk_level=self._calculate_risk(tasks)
        )

        self._plan_cache[target] = plan
        self.logger.success(f"Plan generated with {len(tasks)} tasks")

        return plan

    # ── Cloudflare detection helpers ─────────────────────────

    def _detect_cloudflare(
        self,
        recon_data: Optional[Dict],
        findings: Optional[List[Finding]]
    ) -> bool:
        """Check if Cloudflare was detected in recon data or findings."""
        if recon_data:
            # Check for Cloudflare in recon data
            cf = recon_data.get("cloudflare", {})
            if cf.get("detected"):
                return True
            if recon_data.get("waf_type") == "cloudflare":
                return True

        if findings:
            for f in findings:
                if "cloudflare" in f.tags or "waf" in f.tags:
                    if "cloudflare" in f.title.lower() or "cf-" in f.title.lower():
                        return True
        return False

    def _get_origin_candidates(
        self,
        recon_data: Optional[Dict],
        findings: Optional[List[Finding]]
    ) -> List[str]:
        """Extract origin candidates from recon data or findings."""
        candidates = []

        if recon_data:
            candidates.extend(recon_data.get("origin_candidates", []))
            cf = recon_data.get("cloudflare", {})
            candidates.extend(cf.get("origin_candidates", []))

        if findings:
            for f in findings:
                if "origin" in f.tags and f.host:
                    candidates.append(f.host)

        # Deduplicate
        return list(dict.fromkeys(candidates))

    def _calculate_risk(self, tasks: List[Task]) -> str:
        """Calculate risk level based on tasks."""
        if any(t.confirmation_tier == 3 and t.critical for t in tasks):
            return "high"
        if any(t.confirmation_tier == 2 for t in tasks):
            return "medium"
        return "low"

    # ── Plan execution helpers ──────────────────────────────

    def get_task_dependencies(self, plan: Plan) -> Dict[str, List[str]]:
        """Get dependency graph for tasks."""
        return {t.id: t.depends_on for t in plan.tasks}

    def get_execution_order(self, plan: Plan) -> List[Task]:
        """Get topological execution order."""
        visited = set()
        order = []
        task_map = {t.id: t for t in plan.tasks}

        def dfs(task_id: str):
            if task_id in visited:
                return
            visited.add(task_id)
            for dep in task_map.get(task_id, Task("", "", "", "", {})).depends_on:
                if dep in task_map:
                    dfs(dep)
            order.append(task_map[task_id])

        for task in plan.tasks:
            if task.id not in visited:
                dfs(task.id)

        return order

    def suggest_next_steps(
        self,
        plan: Plan,
        completed_task_ids: List[str]
    ) -> List[Task]:
        """Suggest next tasks based on completed tasks."""
        completed = set(completed_task_ids)
        ready = []

        for task in plan.tasks:
            if task.id in completed:
                continue
            if all(dep in completed for dep in task.depends_on):
                ready.append(task)

        return ready

    # ── Export plan ──────────────────────────────────────────

    def export_plan(self, plan: Plan, path: Path) -> None:
        """Export plan to JSON file."""
        data = {
            "objective": plan.objective,
            "target": plan.target,
            "estimated_steps": plan.estimated_steps,
            "risk_level": plan.risk_level,
            "tasks": [
                {
                    "id": t.id,
                    "name": t.name,
                    "module": t.module,
                    "action": t.action,
                    "params": t.params,
                    "depends_on": t.depends_on,
                    "confirmation_tier": t.confirmation_tier,
                    "critical": t.critical,
                    "description": t.description
                }
                for t in plan.tasks
            ]
        }
        path.write_text(json.dumps(data, indent=2, default=str))


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def create_plan(
    objective: str,
    target: str,
    recon_data: Optional[Dict] = None,
    findings: Optional[List[Finding]] = None,
    logger: Optional[ARDFLogger] = None,
) -> Plan:
    """
    Convenience function to create a plan.

    Args:
        objective: Natural language objective
        target: Target domain/IP
        recon_data: Reconnaissance data for context
        findings: Existing findings for context
        logger: ARDFLogger instance

    Returns:
        Plan object
    """
    if logger is None:
        logger = get_logger("planner")
    planner = Planner(logger)
    return planner.generate_plan(objective, target, recon_data, findings)