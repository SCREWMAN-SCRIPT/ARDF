"""
core/orchestrator.py
────────────────────
Mission Orchestrator for ARDF.

Enhanced with workflow state management:
  - Tracks execution state across modules
  - Handles Cloudflare bypass workflows
  - Manages dynamic branching based on findings
  - Integrates with confirmation gates
  - Supports pause/resume of complex workflows

The orchestrator is the central execution engine that
coordinates all modules and manages the mission lifecycle.
"""

import json
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Workflow State Management
# ─────────────────────────────────────────────────────────────

class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    BYPASSING = "bypassing"
    WAITING_CONFIRMATION = "waiting_confirmation"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class WorkflowPhase(Enum):
    INITIAL = "initial"
    RECONNAISSANCE = "reconnaissance"
    BYPASS = "bypass"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"


@dataclass
class WorkflowState:
    """Current state of the workflow execution."""
    status: WorkflowStatus = WorkflowStatus.PENDING
    phase: WorkflowPhase = WorkflowPhase.INITIAL
    current_task: Optional[str] = None
    completed_tasks: List[str] = field(default_factory=list)
    failed_tasks: List[str] = field(default_factory=list)
    waiting_for: Optional[str] = None
    bypass_status: str = "not_attempted"  # not_attempted | in_progress | completed | failed
    origin_ip: Optional[str] = None
    waf_type: Optional[str] = None
    cloudflare_version: Optional[str] = None
    branch_path: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: Optional[float] = None
    updated_at: Optional[float] = None


# ─────────────────────────────────────────────────────────────
# Orchestrator Class
# ─────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Mission orchestrator with workflow state management.
    """

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        state_path: Optional[Path] = None
    ):
        self.session = session
        self.logger = logger or get_logger("orchestrator")
        self.state_path = state_path or session.dir("core") / "workflow_state.json"
        self.state = self._load_state() or WorkflowState()
        self._modules = {}
        self._registered_handlers = {}
        self._current_plan = None

    # ── State persistence ─────────────────────────────────────

    def _load_state(self) -> Optional[WorkflowState]:
        """Load workflow state from disk."""
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text())
                return WorkflowState(
                    status=WorkflowStatus(data.get("status", "pending")),
                    phase=WorkflowPhase(data.get("phase", "initial")),
                    current_task=data.get("current_task"),
                    completed_tasks=data.get("completed_tasks", []),
                    failed_tasks=data.get("failed_tasks", []),
                    waiting_for=data.get("waiting_for"),
                    bypass_status=data.get("bypass_status", "not_attempted"),
                    origin_ip=data.get("origin_ip"),
                    waf_type=data.get("waf_type"),
                    cloudflare_version=data.get("cloudflare_version"),
                    branch_path=data.get("branch_path", []),
                    results=data.get("results", {}),
                    errors=data.get("errors", []),
                    started_at=data.get("started_at"),
                    updated_at=data.get("updated_at")
                )
            except Exception as e:
                self.logger.warning(f"Failed to load state: {e}")
        return None

    def _save_state(self) -> None:
        """Save workflow state to disk."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {
                "status": self.state.status.value,
                "phase": self.state.phase.value,
                "current_task": self.state.current_task,
                "completed_tasks": self.state.completed_tasks,
                "failed_tasks": self.state.failed_tasks,
                "waiting_for": self.state.waiting_for,
                "bypass_status": self.state.bypass_status,
                "origin_ip": self.state.origin_ip,
                "waf_type": self.state.waf_type,
                "cloudflare_version": self.state.cloudflare_version,
                "branch_path": self.state.branch_path,
                "results": self.state.results,
                "errors": self.state.errors[-100:],
                "started_at": self.state.started_at,
                "updated_at": time.time()
            }
            self.state_path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")

    # ── State transitions ─────────────────────────────────────

    def set_status(self, status: WorkflowStatus) -> None:
        """Update workflow status."""
        self.state.status = status
        self.state.updated_at = time.time()
        self._save_state()

    def set_phase(self, phase: WorkflowPhase) -> None:
        """Update workflow phase."""
        self.state.phase = phase
        self.state.updated_at = time.time()
        self._save_state()

    def set_current_task(self, task_id: str) -> None:
        """Set current executing task."""
        self.state.current_task = task_id
        self.state.updated_at = time.time()
        self._save_state()

    def mark_task_completed(self, task_id: str, result: Any = None) -> None:
        """Mark a task as completed."""
        if task_id not in self.state.completed_tasks:
            self.state.completed_tasks.append(task_id)
        if result is not None:
            self.state.results[task_id] = result
        self.state.current_task = None
        self.state.updated_at = time.time()
        self._save_state()

    def mark_task_failed(self, task_id: str, error: str) -> None:
        """Mark a task as failed."""
        if task_id not in self.state.failed_tasks:
            self.state.failed_tasks.append(task_id)
        self.state.errors.append(f"{task_id}: {error}")
        self.state.current_task = None
        self.state.updated_at = time.time()
        self._save_state()

    def set_bypass_status(self, status: str, origin_ip: Optional[str] = None) -> None:
        """Update Cloudflare bypass status."""
        self.state.bypass_status = status
        if origin_ip:
            self.state.origin_ip = origin_ip
        self.state.updated_at = time.time()
        self._save_state()

    def set_waf_info(self, waf_type: str, version: Optional[str] = None) -> None:
        """Set WAF information."""
        self.state.waf_type = waf_type
        self.state.cloudflare_version = version
        self.state.updated_at = time.time()
        self._save_state()

    # ── Phase execution ───────────────────────────────────────

    def execute_phase(self, phase: WorkflowPhase, params: Dict = None) -> Dict:
        """
        Execute a specific phase of the workflow.
        """
        self.set_phase(phase)
        self.set_status(WorkflowStatus.RUNNING)
        result = {"phase": phase.value, "status": "running", "tasks": []}

        if phase == WorkflowPhase.INITIAL:
            result = self._execute_initial(params or {})
        elif phase == WorkflowPhase.RECONNAISSANCE:
            result = self._execute_reconnaissance(params or {})
        elif phase == WorkflowPhase.BYPASS:
            result = self._execute_bypass(params or {})
        elif phase == WorkflowPhase.EXPLOITATION:
            result = self._execute_exploitation(params or {})
        elif phase == WorkflowPhase.POST_EXPLOIT:
            result = self._execute_post_exploit(params or {})
        elif phase == WorkflowPhase.REPORTING:
            result = self._execute_reporting(params or {})

        return result

    def _execute_initial(self, params: Dict) -> Dict:
        """Initial phase: validate and prepare."""
        target = self.session.meta.target
        self.logger.info(f"Initialising workflow for {target}")

        # Check if we have recon data
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            result = {"status": "completed", "has_recon": True}
            self.set_phase(WorkflowPhase.RECONNAISSANCE)
        else:
            result = {"status": "completed", "has_recon": False}
            self.set_phase(WorkflowPhase.RECONNAISSANCE)

        return result

    def _execute_reconnaissance(self, params: Dict) -> Dict:
        """Reconnaissance phase."""
        depth = params.get("depth", "normal")
        self.logger.info(f"Running reconnaissance at {depth} depth")

        # Check if recon already exists
        recon_path = self.session.dir("recon") / f"recon_{depth}_summary.json"
        if recon_path.exists():
            self.logger.info("Recon data already exists, loading")
            try:
                data = json.loads(recon_path.read_text())
                # Check for Cloudflare in recon data
                if data.get("cloudflare", {}).get("detected"):
                    self.set_waf_info("cloudflare", data.get("cloudflare", {}).get("version"))
                    self.set_bypass_status("detected")
                    self.set_phase(WorkflowPhase.BYPASS)
                else:
                    self.set_phase(WorkflowPhase.EXPLOITATION)
                return {"status": "completed", "using_existing": True, "data": data}
            except Exception:
                pass

        # Execute recon
        from modules.recon import run_recon
        try:
            result = run_recon(
                target=self.session.meta.target,
                depth=depth,
                session=self.session,
                logger=self.logger
            )

            # Check for Cloudflare
            if result.get("cloudflare", {}).get("detected"):
                self.set_waf_info("cloudflare", result.get("cloudflare", {}).get("version"))
                self.set_bypass_status("detected")
                self.set_phase(WorkflowPhase.BYPASS)
            else:
                self.set_phase(WorkflowPhase.EXPLOITATION)

            return {"status": "completed", "result": result}
        except Exception as e:
            self.logger.error(f"Recon failed: {e}")
            return {"status": "failed", "error": str(e)}

    def _execute_bypass(self, params: Dict) -> Dict:
        """Cloudflare bypass phase."""
        self.logger.info("Executing Cloudflare bypass phase")

        # Check if bypass already done
        bypass_path = self.session.dir("bypass") / "bypass_report.json"
        if bypass_path.exists():
            try:
                data = json.loads(bypass_path.read_text())
                if data.get("bypass_achieved"):
                    self.set_bypass_status("completed", data.get("best_candidate"))
                    self.set_phase(WorkflowPhase.EXPLOITATION)
                    return {"status": "completed", "using_existing": True, "data": data}
            except Exception:
                pass

        # Execute bypass
        from modules.bypass import run_bypass
        try:
            result = run_bypass(
                target=self.session.meta.target,
                session=self.session,
                logger=self.logger
            )

            if result.get("bypass_achieved"):
                self.set_bypass_status("completed", result.get("best_candidate"))
            else:
                self.set_bypass_status("failed")

            self.set_phase(WorkflowPhase.EXPLOITATION)
            return {"status": "completed", "result": result}
        except Exception as e:
            self.logger.error(f"Bypass failed: {e}")
            self.set_bypass_status("failed")
            return {"status": "failed", "error": str(e)}

    def _execute_exploitation(self, params: Dict) -> Dict:
        """Exploitation phase."""
        self.logger.info("Executing exploitation phase")

        mode = params.get("mode", "full")
        from modules.exploit import run_exploit

        try:
            # Pass recon data if available
            recon_data = None
            recon_path = self.session.dir("recon") / "recon_depth_summary.json"
            if recon_path.exists():
                try:
                    recon_data = json.loads(recon_path.read_text())
                except Exception:
                    pass

            result = run_exploit(
                session=self.session,
                logger=self.logger,
                mode=mode,
                recon_data=recon_data,
                workflow_enabled=True,
                multi_vector_enabled=True
            )

            self.set_phase(WorkflowPhase.POST_EXPLOIT)
            return {"status": "completed", "result": result}
        except Exception as e:
            self.logger.error(f"Exploitation failed: {e}")
            return {"status": "failed", "error": str(e)}

    def _execute_post_exploit(self, params: Dict) -> Dict:
        """Post-exploitation phase."""
        self.logger.info("Executing post-exploitation phase")

        from modules.redteam import run_redteam

        try:
            result = run_redteam(
                target=self.session.meta.target,
                session=self.session,
                logger=self.logger,
                vectors=["cloudflare_bypass", "web_vulnerability"] if self.state.bypass_status == "completed" else None
            )

            self.set_phase(WorkflowPhase.REPORTING)
            return {"status": "completed", "result": result}
        except Exception as e:
            self.logger.error(f"Post-exploit failed: {e}")
            return {"status": "failed", "error": str(e)}

    def _execute_reporting(self, params: Dict) -> Dict:
        """Reporting phase."""
        self.logger.info("Generating reports")

        from modules.report import generate_report

        try:
            report_path = generate_report(
                session=self.session,
                logger=self.logger,
                open_browser=False,
                purple_mode=self.session.meta.mode.value == "purple"
            )

            self.set_status(WorkflowStatus.COMPLETED)
            return {"status": "completed", "report_path": str(report_path)}
        except Exception as e:
            self.logger.error(f"Reporting failed: {e}")
            self.set_status(WorkflowStatus.FAILED)
            return {"status": "failed", "error": str(e)}

    # ── Full workflow execution ──────────────────────────────

    def run_full_workflow(self, params: Dict = None) -> Dict:
        """
        Execute full workflow from start to finish.
        """
        params = params or {}
        self.state.started_at = time.time()
        self.set_status(WorkflowStatus.RUNNING)

        results = {
            "target": self.session.meta.target,
            "phases": {},
            "final_status": "running"
        }

        # Phase 1: Initial
        results["phases"]["initial"] = self.execute_phase(WorkflowPhase.INITIAL, params)

        # Phase 2: Reconnaissance
        if self.state.phase.value in ["initial", "reconnaissance"]:
            results["phases"]["reconnaissance"] = self.execute_phase(
                WorkflowPhase.RECONNAISSANCE,
                {"depth": params.get("depth", "normal")}
            )

        # Phase 3: Bypass (if Cloudflare detected)
        if self.state.bypass_status == "detected":
            results["phases"]["bypass"] = self.execute_phase(
                WorkflowPhase.BYPASS,
                params.get("bypass_params", {})
            )

        # Phase 4: Exploitation
        if self.state.phase.value in ["reconnaissance", "bypass", "exploitation"]:
            results["phases"]["exploitation"] = self.execute_phase(
                WorkflowPhase.EXPLOITATION,
                {"mode": params.get("exploit_mode", "full")}
            )

        # Phase 5: Post-exploit
        if self.state.phase.value in ["exploitation", "post_exploit"]:
            results["phases"]["post_exploit"] = self.execute_phase(
                WorkflowPhase.POST_EXPLOIT,
                params.get("post_exploit_params", {})
            )

        # Phase 6: Reporting
        if self.state.phase.value in ["post_exploit", "reporting"]:
            results["phases"]["reporting"] = self.execute_phase(
                WorkflowPhase.REPORTING,
                params.get("report_params", {})
            )

        # Final status
        results["final_status"] = self.state.status.value
        results["execution_time"] = time.time() - self.state.started_at

        # Save final state
        self._save_state()
        return results

    # ── Resume workflow ──────────────────────────────────────

    def resume_workflow(self) -> Dict:
        """
        Resume a paused or failed workflow.
        """
        if self.state.status in (WorkflowStatus.COMPLETED, WorkflowStatus.PAUSED):
            self.set_status(WorkflowStatus.RUNNING)

            # Determine which phase to resume
            phase = self.state.phase
            if phase == WorkflowPhase.INITIAL:
                return self.execute_phase(phase)
            elif phase == WorkflowPhase.RECONNAISSANCE:
                return self.execute_phase(phase, {"depth": "normal"})
            elif phase == WorkflowPhase.BYPASS:
                return self.execute_phase(phase)
            elif phase == WorkflowPhase.EXPLOITATION:
                return self.execute_phase(phase, {"mode": "full"})
            elif phase == WorkflowPhase.POST_EXPLOIT:
                return self.execute_phase(phase)
            elif phase == WorkflowPhase.REPORTING:
                return self.execute_phase(phase)

        return {"status": "cannot_resume", "reason": f"Current status: {self.state.status.value}"}


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_orchestrator(
    session: Session,
    logger: Optional[ARDFLogger] = None,
    params: Dict = None,
    resume: bool = False,
) -> Dict[str, Any]:
    """
    Run or resume the orchestrator for a session.

    Args:
        session: Active ARDF session
        logger: ARDFLogger instance
        params: Execution parameters
        resume: Resume existing workflow

    Returns:
        Orchestration results
    """
    if logger is None:
        logger = get_logger("orchestrator")

    logger.banner("MISSION ORCHESTRATOR", style="bold green")

    orchestrator = Orchestrator(session, logger)

    if resume:
        results = orchestrator.resume_workflow()
    else:
        results = orchestrator.run_full_workflow(params or {})

    logger.success(f"Orchestration complete: {results.get('final_status', 'unknown')}")
    return results