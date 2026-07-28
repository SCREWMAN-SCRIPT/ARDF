"""
core/mission.py
───────────────
Mission definition and playbook loader for ARDF.

Enhanced with workflow playbooks:
  - Load YAML playbooks with workflow definitions
  - Support conditional branching based on findings
  - Define confirmation tiers per phase
  - Handle Cloudflare-specific playbooks
  - Support adaptive playbook selection

Playbook format:
  phases:
    - name: recon
      module: recon
      depth: normal
      condition: always
      confirmation_tier: 1

    - name: bypass
      module: bypass
      condition: cloudflare_detected
      confirmation_tier: 2
"""

import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

from modules.logger import get_logger, ARDFLogger
from modules.session import Session


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

@dataclass
class MissionPhase:
    """A single phase in a mission playbook."""
    name: str
    module: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    condition: str = "always"
    confirmation_tier: int = 1
    depends_on: List[str] = field(default_factory=list)
    critical: bool = False
    retry_count: int = 0
    timeout: int = 3600


@dataclass
class MissionPlaybook:
    """Complete mission playbook definition."""
    name: str
    description: str
    version: str = "1.0"
    target_type: str = "any"
    execution_mode: str = "red"
    phases: List[MissionPhase] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    fallback_playbook: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Mission Loader
# ─────────────────────────────────────────────────────────────

class MissionLoader:
    """
    Load and validate mission playbooks.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("mission")
        self.playbook_dir = Path("config/playbooks")
        self._cache: Dict[str, MissionPlaybook] = {}

    def load_playbook(self, name: str) -> Optional[MissionPlaybook]:
        """
        Load a playbook by name from config/playbooks/.
        """
        if name in self._cache:
            return self._cache[name]

        # Try multiple paths
        paths = [
            self.playbook_dir / f"{name}.yaml",
            self.playbook_dir / f"{name}.yml",
            Path(f"config/playbooks/{name}.yaml"),
            Path(f"config/playbooks/{name}.yml"),
        ]

        for path in paths:
            if path.exists():
                try:
                    data = yaml.safe_load(path.read_text())
                    playbook = self._parse_playbook(data, name)
                    self._cache[name] = playbook
                    self.logger.success(f"Loaded playbook: {name} ({len(playbook.phases)} phases)")
                    return playbook
                except Exception as e:
                    self.logger.error(f"Failed to load playbook {name}: {e}")
                    return None

        self.logger.warning(f"Playbook not found: {name}")
        return None

    def _parse_playbook(self, data: Dict, name: str) -> MissionPlaybook:
        """Parse YAML data into MissionPlaybook."""
        phases = []
        for phase_data in data.get("phases", []):
            phases.append(MissionPhase(
                name=phase_data.get("name", "unknown"),
                module=phase_data.get("module", ""),
                action=phase_data.get("action", ""),
                params=phase_data.get("params", {}),
                condition=phase_data.get("condition", "always"),
                confirmation_tier=phase_data.get("confirmation_tier", 1),
                depends_on=phase_data.get("depends_on", []),
                critical=phase_data.get("critical", False),
                retry_count=phase_data.get("retry_count", 0),
                timeout=phase_data.get("timeout", 3600)
            ))

        return MissionPlaybook(
            name=data.get("name", name),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            target_type=data.get("target_type", "any"),
            execution_mode=data.get("execution_mode", "red"),
            phases=phases,
            variables=data.get("variables", {}),
            fallback_playbook=data.get("fallback_playbook")
        )

    def list_playbooks(self) -> List[str]:
        """List all available playbooks."""
        playbooks = []
        for path in self.playbook_dir.glob("*.yaml"):
            playbooks.append(path.stem)
        for path in self.playbook_dir.glob("*.yml"):
            if path.stem not in playbooks:
                playbooks.append(path.stem)
        return sorted(playbooks)

    def create_playbook_from_workflow(self, workflow_data: Dict) -> MissionPlaybook:
        """
        Create a playbook from workflow execution results.
        Useful for capturing successful workflows.
        """
        name = workflow_data.get("name", f"workflow_{int(time.time())}")
        phases = []

        for step in workflow_data.get("steps", []):
            phases.append(MissionPhase(
                name=step.get("name", "unknown"),
                module=step.get("module", ""),
                action=step.get("action", ""),
                params=step.get("params", {}),
                condition=step.get("condition", "always"),
                confirmation_tier=step.get("confirmation_tier", 1),
                critical=step.get("critical", False)
            ))

        return MissionPlaybook(
            name=name,
            description=f"Generated from workflow: {workflow_data.get('description', '')}",
            phases=phases,
            variables=workflow_data.get("variables", {})
        )


# ─────────────────────────────────────────────────────────────
# Mission Executor
# ─────────────────────────────────────────────────────────────

class MissionExecutor:
    """
    Execute mission playbooks with dynamic branching.
    """

    def __init__(
        self,
        session: Session,
        playbook: MissionPlaybook,
        logger: Optional[ARDFLogger] = None,
        context: Optional[Dict] = None
    ):
        self.session = session
        self.playbook = playbook
        self.logger = logger or get_logger("mission")
        self.context = context or {}
        self.results = {}
        self.completed_phases = []
        self.failed_phases = []

    def evaluate_condition(self, condition: str) -> bool:
        """Evaluate a phase condition."""
        if condition == "always":
            return True
        if condition == "never":
            return False

        # Cloudflare conditions
        if condition == "cloudflare_detected":
            # Check recon data for Cloudflare
            recon_path = self.session.dir("recon") / "recon_passive_summary.json"
            if recon_path.exists():
                try:
                    data = json.loads(recon_path.read_text())
                    return data.get("cloudflare", {}).get("detected", False)
                except Exception:
                    pass
            return False

        if condition == "bypass_succeeded":
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    return data.get("bypass_achieved", False)
                except Exception:
                    pass
            return False

        if condition == "origin_known":
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    return bool(data.get("origin_candidates"))
                except Exception:
                    pass
            return False

        # Generic condition check from context
        if condition.startswith("ctx."):
            key = condition[4:]
            return self.context.get(key, False)

        return True

    def execute_phase(self, phase: MissionPhase) -> Dict:
        """Execute a single mission phase."""
        self.logger.info(f"Executing phase: {phase.name} ({phase.module}.{phase.action})")

        # Check condition
        if not self.evaluate_condition(phase.condition):
            self.logger.info(f"Skipping phase {phase.name} (condition not met)")
            return {"status": "skipped", "reason": f"condition: {phase.condition}"}

        # Dynamic module import
        try:
            module = __import__(f"modules.{phase.module}", fromlist=[""])
            func = getattr(module, phase.action)
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Module/action not found: {phase.module}.{phase.action}")
            return {"status": "failed", "error": str(e)}

        # Execute with retry
        for attempt in range(phase.retry_count + 1):
            try:
                # Build params with context
                params = phase.params.copy()
                params["session"] = self.session
                params["logger"] = self.logger

                # Add context variables
                for key, value in self.context.items():
                    if key not in params:
                        params[key] = value

                result = func(**params)
                return {"status": "success", "result": result}
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt == phase.retry_count:
                    return {"status": "failed", "error": str(e)}

        return {"status": "failed", "error": "Max retries exceeded"}

    def execute(self) -> Dict[str, Any]:
        """
        Execute all phases in the playbook.
        """
        self.logger.banner(f"MISSION: {self.playbook.name}", style="bold blue")

        # Phase 1: Validate dependencies
        phase_names = {p.name for p in self.playbook.phases}
        for phase in self.playbook.phases:
            for dep in phase.depends_on:
                if dep not in phase_names:
                    self.logger.warning(f"Phase {phase.name} depends on missing phase: {dep}")

        # Execute phases in order
        for phase in self.playbook.phases:
            # Skip if already completed
            if phase.name in self.completed_phases:
                continue

            # Check dependencies
            for dep in phase.depends_on:
                if dep not in self.completed_phases:
                    self.logger.warning(f"Phase {phase.name} waiting for dependency: {dep}")
                    continue

            result = self.execute_phase(phase)
            self.results[phase.name] = result

            if result["status"] == "success":
                self.completed_phases.append(phase.name)
                # Update context with results
                if result.get("result"):
                    self.context[phase.name] = result["result"]
            else:
                self.failed_phases.append(phase.name)
                if phase.critical:
                    self.logger.error(f"Critical phase failed: {phase.name}")
                    break

        # Return summary
        return {
            "playbook": self.playbook.name,
            "total_phases": len(self.playbook.phases),
            "completed": len(self.completed_phases),
            "failed": len(self.failed_phases),
            "results": self.results,
            "context": self.context
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_mission(
    session: Session,
    playbook_name: str,
    logger: Optional[ARDFLogger] = None,
    context: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Run a mission playbook.

    Args:
        session: Active ARDF session
        playbook_name: Name of playbook to run
        logger: ARDFLogger instance
        context: Additional context variables

    Returns:
        Mission execution results
    """
    if logger is None:
        logger = get_logger("mission")

    loader = MissionLoader(logger)
    playbook = loader.load_playbook(playbook_name)

    if not playbook:
        return {"status": "failed", "error": f"Playbook not found: {playbook_name}"}

    executor = MissionExecutor(session, playbook, logger, context or {})
    return executor.execute()