"""
ai/planner.py
─────────────
MissionPlanner — converts a natural language objective or
a target specification into an ordered task execution plan.

Flow
────
  1. User provides objective (natural language or structured)
  2. Planner asks local AI to decompose into tasks
  3. Tasks are validated against available modules
  4. Dependency graph is returned for the orchestrator

Output schema
─────────────
  {
    "mission_id": str,
    "objective":  str,
    "mode":       red|blue|purple|osint,
    "tasks": [
      {
        "id":        str,
        "name":      str,
        "module":    str,
        "function":  str,
        "args":      dict,
        "depends_on": [str],
        "priority":  int,
        "timeout":   int,
        "confirm":   bool,
        "tags":      [str]
      }
    ]
  }
"""

import json
import uuid
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai.local_model  import LocalModel, get_model, load_prompt
from modules.logger  import get_logger, ARDFLogger
from modules.session import Session


# ─────────────────────────────────────────────────────────────
# Known module registry — what the planner can schedule
# ─────────────────────────────────────────────────────────────

MODULE_REGISTRY: Dict[str, Dict] = {
    "recon_passive": {
        "module":   "modules.recon",
        "function": "run_recon",
        "args":     {"depth": "passive"},
        "tags":     ["recon", "passive", "osint"],
        "timeout":  60,
        "confirm":  False,
    },
    "recon_normal": {
        "module":   "modules.recon",
        "function": "run_recon",
        "args":     {"depth": "normal"},
        "tags":     ["recon", "active", "portscan"],
        "timeout":  120,
        "confirm":  False,
    },
    "recon_depth": {
        "module":   "modules.recon",
        "function": "run_recon",
        "args":     {"depth": "depth"},
        "tags":     ["recon", "deep", "nuclei", "fuzzing"],
        "timeout":  240,
        "confirm":  False,
    },
    "intel_enrich": {
        "module":   "modules.intel",
        "function": "run_intel",
        "args":     {},
        "tags":     ["intel", "cve", "enrichment"],
        "timeout":  30,
        "confirm":  False,
    },
    "exploit_web": {
        "module":   "modules.exploit",
        "function": "run_exploit",
        "args":     {"mode": "web"},
        "tags":     ["exploit", "web", "sqli", "xss"],
        "timeout":  180,
        "confirm":  True,
    },
    "exploit_network": {
        "module":   "modules.exploit",
        "function": "run_exploit",
        "args":     {"mode": "network"},
        "tags":     ["exploit", "network", "smb"],
        "timeout":  180,
        "confirm":  True,
    },
    "exploit_password": {
        "module":   "modules.exploit",
        "function": "run_exploit",
        "args":     {"mode": "password"},
        "tags":     ["exploit", "passwords", "bruteforce"],
        "timeout":  120,
        "confirm":  True,
    },
    "exploit_post": {
        "module":   "modules.exploit",
        "function": "run_exploit",
        "args":     {"mode": "post"},
        "tags":     ["exploit", "post", "privesc"],
        "timeout":  120,
        "confirm":  True,
    },
    "report_generate": {
        "module":   "modules.report",
        "function": "generate_report",
        "args":     {},
        "tags":     ["report", "output"],
        "timeout":  10,
        "confirm":  False,
    },
}

# Maps keywords in objectives to task names
KEYWORD_TASK_MAP: Dict[str, List[str]] = {
    "passive":      ["recon_passive", "intel_enrich", "report_generate"],
    "osint":        ["recon_passive", "intel_enrich", "report_generate"],
    "recon":        ["recon_passive", "recon_normal", "intel_enrich", "report_generate"],
    "full":         list(MODULE_REGISTRY.keys()),
    "pentest":      list(MODULE_REGISTRY.keys()),
    "web":          ["recon_passive", "recon_normal", "recon_depth", "intel_enrich",
                     "exploit_web", "report_generate"],
    "network":      ["recon_passive", "recon_normal", "intel_enrich",
                     "exploit_network", "report_generate"],
    "exploit":      ["recon_passive", "recon_normal", "intel_enrich",
                     "exploit_web", "exploit_network", "report_generate"],
    "password":     ["recon_passive", "recon_normal", "intel_enrich",
                     "exploit_password", "report_generate"],
    "post":         ["exploit_post", "report_generate"],
    "report":       ["report_generate"],
    "intel":        ["intel_enrich"],
    "cve":          ["intel_enrich", "report_generate"],
    "enumerate":    ["recon_passive", "recon_normal", "intel_enrich", "report_generate"],
    "scan":         ["recon_normal", "intel_enrich", "report_generate"],
    "audit":        ["recon_passive", "recon_normal", "recon_depth",
                     "intel_enrich", "exploit_web", "report_generate"],
}

# Default task dependency order
TASK_DEPENDENCIES: Dict[str, List[str]] = {
    "recon_passive":   [],
    "recon_normal":    ["recon_passive"],
    "recon_depth":     ["recon_normal"],
    "intel_enrich":    ["recon_passive"],
    "exploit_web":     ["recon_normal", "intel_enrich"],
    "exploit_network": ["recon_normal", "intel_enrich"],
    "exploit_password":["exploit_web", "exploit_network"],
    "exploit_post":    ["exploit_password"],
    "report_generate": ["intel_enrich"],
}


# ─────────────────────────────────────────────────────────────
# MissionPlanner
# ─────────────────────────────────────────────────────────────

class MissionPlanner:
    """
    Converts a user objective into an ordered task execution plan.

    Two planning modes:
      - rule_based : keyword matching → fast, deterministic, offline-safe
      - ai_assisted: Qwen2.5 decomposition → flexible, handles novel requests
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
        ai_model: Optional[LocalModel] = None,
    ):
        self.session  = session
        self.logger   = logger or get_logger("ai.planner")
        self.ai       = ai_model or get_model(role="planning", logger=self.logger)
        self._prompt_template = load_prompt("plan_mission")

    # ── Public entry point ────────────────────────────────────

    def plan(
        self,
        objective:  str,
        mode:       str = "auto",
        use_ai:     bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a mission plan from a natural language objective.

        Args:
            objective : plain-English description of what to do
            mode      : red | blue | purple | osint | auto
            use_ai    : use local AI for decomposition (else rule-based only)

        Returns:
            Mission plan dict with ordered task list
        """
        self.logger.info(f"Planning mission: '{objective[:80]}...' mode={mode}")

        # Detect mode from objective if auto
        if mode == "auto":
            mode = self._detect_mode(objective)

        # Try AI planning first, fall back to rule-based
        plan = None
        if use_ai:
            plan = self._ai_plan(objective, mode)

        if not plan:
            self.logger.info("Using rule-based planner fallback")
            plan = self._rule_plan(objective, mode)

        # Validate and enrich
        plan = self._validate_plan(plan)
        plan = self._inject_session_context(plan)

        self.logger.success(
            f"Plan ready | tasks={len(plan['tasks'])} mode={plan['mode']}"
        )
        return plan

    def plan_from_finding(
        self,
        finding_title: str,
        finding_severity: str,
        host: str,
    ) -> Dict[str, Any]:
        """
        Generate a focused follow-up plan from a specific finding.
        Used by the orchestrator when a critical finding triggers expansion.
        """
        objective = (
            f"Investigate and exploit this {finding_severity} severity finding: "
            f"'{finding_title}' on host {host}. "
            f"Focus on confirming exploitability and finding lateral movement paths."
        )
        return self.plan(objective, mode="red", use_ai=True)

    def plan_from_playbook(
        self,
        phases: List[Dict],
        mode:   str,
    ) -> Dict[str, Any]:
        """
        Convert a loaded playbook phase list into a mission plan.
        Used by playbook/executor.py.
        """
        mission_id = uuid.uuid4().hex[:8]
        tasks = []
        for i, phase in enumerate(phases):
            task_id = phase.get("id", f"task_{i:02d}")
            tasks.append({
                "id":         task_id,
                "name":       phase.get("name", task_id),
                "module":     phase.get("module", ""),
                "function":   phase.get("function", ""),
                "args":       self._extract_args(phase),
                "depends_on": phase.get("depends_on", []),
                "priority":   i,
                "timeout":    phase.get("timeout_minutes", 60) * 60,
                "confirm":    phase.get("confirmation", False),
                "confirm_msg":phase.get("confirmation_message", ""),
                "condition":  phase.get("condition", ""),
                "tags":       phase.get("tags", []),
            })
        return {
            "mission_id": mission_id,
            "objective":  f"Execute {mode} playbook",
            "mode":       mode,
            "tasks":      tasks,
            "source":     "playbook",
        }

    # ── AI-assisted planning ──────────────────────────────────

    def _ai_plan(self, objective: str, mode: str) -> Optional[Dict]:
        """Ask local AI to decompose the objective into tasks."""
        if not self._prompt_template:
            return None

        available_tasks = json.dumps(
            {k: {"tags": v["tags"], "description": self._task_description(k)}
             for k, v in MODULE_REGISTRY.items()},
            indent=2,
        )

        prompt = self._prompt_template.format(
            objective       = objective,
            mode            = mode,
            target          = self.session.meta.target,
            available_tasks = available_tasks,
            mission_id      = uuid.uuid4().hex[:8],
        )

        self.logger.info("Asking local AI to decompose mission...")
        result = self.ai.json_generate(prompt=prompt, temperature=0.1)

        if not result or "tasks" not in result:
            self.logger.warning("AI planner returned invalid structure")
            return None

        # Normalise AI output to our schema
        return self._normalise_ai_plan(result, objective, mode)

    def _normalise_ai_plan(
        self,
        raw:       Dict,
        objective: str,
        mode:      str,
    ) -> Dict:
        tasks = []
        for i, t in enumerate(raw.get("tasks", [])):
            task_id = t.get("id", f"ai_task_{i:02d}")
            # Map AI task name to known module
            module_key = self._resolve_module_key(t.get("name", ""), t.get("tags", []))
            if not module_key:
                continue
            reg = MODULE_REGISTRY[module_key]
            tasks.append({
                "id":         task_id,
                "name":       t.get("name", module_key),
                "module":     reg["module"],
                "function":   reg["function"],
                "args":       {**reg["args"], **t.get("args", {})},
                "depends_on": t.get("depends_on", TASK_DEPENDENCIES.get(module_key, [])),
                "priority":   t.get("priority", i),
                "timeout":    t.get("timeout", reg["timeout"]) * 60,
                "confirm":    t.get("confirm", reg["confirm"]),
                "confirm_msg":t.get("confirm_msg", ""),
                "tags":       t.get("tags", reg["tags"]),
            })
        return {
            "mission_id": raw.get("mission_id", uuid.uuid4().hex[:8]),
            "objective":  objective,
            "mode":       mode,
            "tasks":      tasks,
            "source":     "ai",
        }

    # ── Rule-based planning ───────────────────────────────────

    def _rule_plan(self, objective: str, mode: str) -> Dict:
        """Fast keyword-based task selection."""
        obj_lower  = objective.lower()
        task_set   = set()

        for keyword, tasks in KEYWORD_TASK_MAP.items():
            if keyword in obj_lower:
                task_set.update(tasks)

        # Mode-based defaults
        if not task_set:
            if mode in ("red", "purple"):
                task_set = set(MODULE_REGISTRY.keys())
            elif mode == "osint":
                task_set = {"recon_passive", "intel_enrich", "report_generate"}
            else:
                task_set = {"recon_passive", "recon_normal", "intel_enrich", "report_generate"}

        # Always include report
        task_set.add("report_generate")

        # Build ordered task list respecting dependencies
        ordered = self._topological_sort(list(task_set))
        tasks   = []
        for i, key in enumerate(ordered):
            if key not in MODULE_REGISTRY:
                continue
            reg = MODULE_REGISTRY[key]
            deps = [d for d in TASK_DEPENDENCIES.get(key, []) if d in task_set]
            tasks.append({
                "id":         key,
                "name":       key.replace("_", " ").title(),
                "module":     reg["module"],
                "function":   reg["function"],
                "args":       reg["args"].copy(),
                "depends_on": deps,
                "priority":   i,
                "timeout":    reg["timeout"] * 60,
                "confirm":    reg["confirm"],
                "confirm_msg": f"Ready to run {key.replace('_',' ')}. Confirm?",
                "tags":       reg["tags"],
            })

        return {
            "mission_id": uuid.uuid4().hex[:8],
            "objective":  objective,
            "mode":       mode,
            "tasks":      tasks,
            "source":     "rule_based",
        }

    # ── Helpers ───────────────────────────────────────────────

    def _detect_mode(self, objective: str) -> str:
        obj = objective.lower()
        if any(k in obj for k in ("purple", "detect", "blue team", "defense")):
            return "purple"
        if any(k in obj for k in ("osint", "passive", "footprint")):
            return "osint"
        if any(k in obj for k in ("harden", "monitor", "blue")):
            return "blue"
        return "red"

    def _resolve_module_key(self, name: str, tags: List[str]) -> Optional[str]:
        """Map AI-generated task name/tags to a registry key."""
        name_lower = name.lower().replace(" ", "_")
        if name_lower in MODULE_REGISTRY:
            return name_lower
        for key in MODULE_REGISTRY:
            if key in name_lower or name_lower in key:
                return key
        for tag in tags:
            for key, reg in MODULE_REGISTRY.items():
                if tag in reg["tags"]:
                    return key
        return None

    def _topological_sort(self, task_keys: List[str]) -> List[str]:
        """Sort tasks respecting dependencies."""
        visited = set()
        result  = []

        def visit(key: str):
            if key in visited or key not in MODULE_REGISTRY:
                return
            visited.add(key)
            for dep in TASK_DEPENDENCIES.get(key, []):
                if dep in task_keys:
                    visit(dep)
            result.append(key)

        for key in task_keys:
            visit(key)
        return result

    def _validate_plan(self, plan: Dict) -> Dict:
        """Ensure all tasks have required fields."""
        valid_tasks = []
        for task in plan.get("tasks", []):
            if not task.get("module") or not task.get("function"):
                self.logger.warning(f"Skipping invalid task: {task.get('id','?')}")
                continue
            task.setdefault("args", {})
            task.setdefault("depends_on", [])
            task.setdefault("priority", 99)
            task.setdefault("timeout", 3600)
            task.setdefault("confirm", False)
            task.setdefault("confirm_msg", "")
            task.setdefault("tags", [])
            valid_tasks.append(task)
        plan["tasks"] = valid_tasks
        return plan

    def _inject_session_context(self, plan: Dict) -> Dict:
        """Inject target and session info into all task args."""
        for task in plan.get("tasks", []):
            task["args"]["target"]     = self.session.meta.target
            task["args"]["session_id"] = self.session.meta.session_id
        plan["target"]     = self.session.meta.target
        plan["session_id"] = self.session.meta.session_id
        return plan

    def _extract_args(self, phase: Dict) -> Dict:
        skip = {
            "id","name","module","function","depends_on",
            "confirmation","confirmation_message","timeout_minutes",
            "on_failure","condition","tags","outputs","inputs",
            "tools","red_actions","blue_actions","mitre_mapping",
            "settings",
        }
        return {k: v for k, v in phase.items() if k not in skip}

    def _task_description(self, key: str) -> str:
        descriptions = {
            "recon_passive":    "Passive OSINT — subdomain enum, WHOIS, crt.sh, email harvest",
            "recon_normal":     "Active recon — httpx, nmap top-1000, web crawl, tech fingerprint",
            "recon_depth":      "Deep recon — masscan, nuclei, ffuf, JS analysis, secret scanning",
            "intel_enrich":     "CVE lookup, Shodan, AbuseIPDB, AI analysis of findings",
            "exploit_web":      "Web exploitation — SQLi, XSS, RCE, SSRF, LFI, SSTI, JWT attacks",
            "exploit_network":  "Network exploitation — SMB, SSL audit, SNMP, RDP, SSH",
            "exploit_password": "Password attacks — hashcat, john, hydra, medusa",
            "exploit_post":     "Post-exploitation — linpeas, pspy, chisel tunnels",
            "report_generate":  "Generate HTML report with all findings, IOCs, kill chain",
        }
        return descriptions.get(key, key)
