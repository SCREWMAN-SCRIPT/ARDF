"""
core/orchestrator.py
─────────────────────
Orchestrator — the central execution engine of ARDF.

Responsibilities
────────────────
  - Accept a mission plan from MissionPlanner
  - Build a TaskGraph and execute tasks in dependency order
  - Pass every sensitive task through ConfirmationGate
  - Classify tool output after each run
  - Hand failures to the Tactician for alternate selection
  - Update mission state and session findings continuously
  - Emit progress events for the interface layer

Design constraints
──────────────────
  - Every task with confirm=True stops and waits for human input
  - No autonomous execution of exploit tasks without confirmation
  - All tool calls go through module functions — never raw shell exec
  - Failures are logged, not silently swallowed
"""

import importlib
import json
import time
import traceback
from typing import Any, Callable, Dict, List, Optional

from core.mission             import Mission, MissionStatus
from core.task_graph          import TaskGraph, Task, TaskStatus
from core.confirmation_gate   import ConfirmationGate, GateDecision
from core.response_classifier import ResponseClassifier
from ai.analyst               import FindingAnalyst
from ai.tactician             import Tactician, FailureType
from modules.session          import Session
from modules.logger           import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Central execution engine.

    Takes a Mission with an attached plan and executes it
    task by task, with confirmation gates, failure handling,
    and continuous finding analysis.
    """

    def __init__(
        self,
        session:         Session,
        logger:          Optional[ARDFLogger] = None,
        auto_approve:    bool = False,
        non_interactive: bool = False,
        max_retries:     int  = 2,
    ):
        self.session         = session
        self.logger          = logger or get_logger("core.orchestrator")
        self.max_retries     = max_retries
        self.classifier      = ResponseClassifier()
        self.gate            = ConfirmationGate(
            logger          = self.logger,
            auto_approve    = auto_approve,
            non_interactive = non_interactive,
            audit_path      = session.dir("logs") / "gate_audit.json",
        )
        self._analyst:    Optional[FindingAnalyst] = None
        self._tactician:  Optional[Tactician]      = None
        self._on_progress: Optional[Callable]      = None

    # ── Public API ────────────────────────────────────────────

    def run(self, mission: Mission) -> Dict[str, Any]:
        """
        Execute a mission from start to finish.

        Args:
            mission : Mission object with an attached plan

        Returns:
            Execution summary dict
        """
        if not mission.plan:
            raise ValueError("Mission has no plan — call MissionPlanner.plan() first")

        self.logger.banner(
            f"MISSION START — {self.session.meta.target}",
            style="bold cyan",
        )
        self.logger.info(f"Objective : {mission.objective[:80]}")
        self.logger.info(f"Mode      : {mission.mode.upper()}")
        self.logger.info(f"Tasks     : {len(mission.plan.get('tasks', []))}")

        # Build task graph
        try:
            graph = TaskGraph(mission.plan, logger=self.logger)
        except ValueError as e:
            mission.fail(str(e))
            return {"error": str(e), "status": "failed"}

        # Initialise AI components lazily
        self._init_ai(mission)

        mission.start()

        # ── Main execution loop ───────────────────────────────
        for task in graph.execution_generator():

            if mission.should_abort:
                self.logger.warning("Mission abort signal received")
                break

            if mission.should_pause:
                self.logger.info("Mission paused — waiting for resume()")
                while mission.should_pause and not mission.should_abort:
                    time.sleep(2)

            # Evaluate optional condition
            if not self._evaluate_condition(task, mission):
                self.logger.info(f"Task {task.id} condition not met — skipping")
                task.mark_skipped("condition not met")
                mission.mark_task_skipped(task.id, "condition not met")
                continue

            # Confirmation gate
            if task.confirm:
                decision = self.gate.request(
                    task_id   = task.id,
                    task_name = task.name,
                    target    = self.session.meta.target,
                    message   = task.confirm_msg,
                    tier      = 3 if "post" in task.id else 2,
                )
                if decision != GateDecision.APPROVED:
                    task.mark_skipped(f"gate {decision}")
                    mission.mark_task_skipped(task.id, f"gate {decision}")
                    self._emit_progress(mission, graph, task, "skipped")
                    continue

            # Execute task with retry loop
            success = self._execute_with_retry(task, mission, graph)

            if success:
                mission.mark_task_complete(task.id)
            else:
                mission.mark_task_failed(task.id)
                # Check if we should abort on critical failure
                if self._should_abort_on_failure(task, mission):
                    mission.abort(f"Critical task {task.id} failed")
                    break

            self._emit_progress(mission, graph, task,
                                "completed" if success else "failed")

            # Run post-task AI analysis every few tasks
            if len(mission.completed_tasks) % 3 == 0:
                self._run_ai_analysis(mission)

        # ── Finalise mission ──────────────────────────────────
        self.gate.save_audit_log()

        if mission.status not in (MissionStatus.ABORTED, MissionStatus.FAILED):
            mission.complete()

        summary = self._build_summary(mission, graph)
        self._save_summary(summary, mission)

        self.logger.banner("MISSION COMPLETE", style="bold green")
        self.logger.success(
            f"Status={mission.status.value} | "
            f"Findings={self.session.meta.findings_count} | "
            f"Risk={self.session.meta.risk_score} | "
            f"Duration={mission.duration_str()}"
        )
        return summary

    def set_progress_callback(self, callback: Callable):
        """Set a callback function called after each task completes."""
        self._on_progress = callback

    # ── Task execution ────────────────────────────────────────

    def _execute_with_retry(
        self,
        task:    Task,
        mission: Mission,
        graph:   TaskGraph,
    ) -> bool:
        """
        Execute a task with retry logic on failure.
        Returns True if task succeeded, False if all retries exhausted.
        """
        for attempt in range(1, self.max_retries + 2):
            if attempt > 1:
                self.logger.info(f"Retry {attempt-1}/{self.max_retries} for task {task.id}")

            mission.mark_task_running(task.id)
            task.mark_running()

            before_count = self.session.meta.findings_count
            result       = self._execute_task(task)
            after_count  = self.session.meta.findings_count

            classification = self.classifier.classify(
                stdout      = result.get("stdout", ""),
                stderr      = result.get("stderr", ""),
                return_code = result.get("return_code", 0),
                tool_name   = task.name,
            )

            # Log classification summary
            self.logger.info(
                f"Task {task.id} classification: "
                f"{self.classifier.summarise(classification)}"
            )

            # New findings created
            if after_count > before_count:
                self.logger.success(
                    f"Task {task.id}: "
                    f"{after_count - before_count} new findings"
                )

            # Success — task produced results or ran cleanly
            if not classification.get("failure_type") or classification.get("has_findings"):
                task.mark_completed(result)
                return True

            # Failure — ask tactician for alternate approach
            failure_type = classification.get("failure_type", "unknown")
            self.logger.warning(
                f"Task {task.id} failed: {failure_type} "
                f"(attempt {attempt})"
            )

            if attempt <= self.max_retries and task.can_retry:
                tactic = self._get_tactic(task, failure_type, result)
                if tactic and tactic.get("action") not in ("skip", "abort"):
                    self.logger.info(f"Tactic: {tactic['action']} — {tactic['reason'][:60]}")
                    task.retries += 1
                    if tactic.get("delay", 0) > 0:
                        time.sleep(tactic["delay"])
                    # Apply tactic modifications to task args
                    self._apply_tactic(task, tactic)
                    continue

            # All retries or tactic says skip
            task.mark_failed(failure_type)
            return False

        task.mark_failed("max_retries_exceeded")
        return False

    def _execute_task(self, task: Task) -> Dict:
        """
        Execute a single task by calling its module function.
        Returns dict with stdout, stderr, return_code, result.
        """
        self.logger.info(f"Executing: {task.name} ({task.module}.{task.function})")

        try:
            # Dynamically import and call the module function
            module = importlib.import_module(task.module)
            fn     = getattr(module, task.function)

            # Build function arguments
            args = self._build_args(task)

            start  = time.time()
            result = fn(**args)
            elapsed = time.time() - start

            self.logger.info(
                f"Task {task.id} ran in {elapsed:.1f}s"
            )

            # Normalise result
            if isinstance(result, dict):
                return {
                    "stdout":      result.get("output", ""),
                    "stderr":      result.get("error", ""),
                    "return_code": 0 if result else 1,
                    "result":      result,
                }
            return {
                "stdout":      str(result) if result else "",
                "stderr":      "",
                "return_code": 0 if result is not None else 1,
                "result":      {},
            }

        except ModuleNotFoundError as e:
            msg = f"Module not found: {task.module} — {e}"
            self.logger.error(msg)
            return {"stdout": "", "stderr": msg, "return_code": 127, "result": {}}

        except AttributeError as e:
            msg = f"Function not found: {task.function} in {task.module} — {e}"
            self.logger.error(msg)
            return {"stdout": "", "stderr": msg, "return_code": 1, "result": {}}

        except Exception as e:
            msg = f"Task {task.id} raised exception: {e}"
            self.logger.error(msg)
            self.logger.debug(traceback.format_exc())
            return {"stdout": "", "stderr": str(e), "return_code": 1, "result": {}}

    # ── Argument building ─────────────────────────────────────

    def _build_args(self, task: Task) -> Dict:
        """
        Build keyword arguments for a module function call.
        Injects session and logger automatically.
        """
        args = task.args.copy()

        # Always inject session and logger
        args["session"] = self.session
        args["logger"]  = self.logger

        # Map common arg aliases
        if "target" not in args:
            args["target"] = self.session.meta.target
        if "depth" not in args and task.function == "run_recon":
            args["depth"] = "passive"

        return args

    # ── Tactic integration ────────────────────────────────────

    def _get_tactic(
        self,
        task:         Task,
        failure_type: str,
        result:       Dict,
    ) -> Optional[Dict]:
        """Ask Tactician for alternate approach on failure."""
        if not self._tactician:
            return None
        try:
            return self._tactician.handle_failure(
                tool_name    = task.name,
                failure_type = failure_type,
                original_cmd = [],
                stdout       = result.get("stdout", ""),
                stderr       = result.get("stderr", ""),
                context      = {"target": self.session.meta.target},
            )
        except Exception as e:
            self.logger.debug(f"Tactician error: {e}")
            return None

    def _apply_tactic(self, task: Task, tactic: Dict):
        """Apply tactic modifications to a task's args."""
        mods = tactic.get("modifications", {})
        if mods:
            task.args.update(mods)

    # ── AI analysis ───────────────────────────────────────────

    def _run_ai_analysis(self, mission: Mission):
        """Run periodic AI analysis on accumulated findings."""
        if not self._analyst:
            return
        try:
            findings = self.session.get_findings()
            if not findings:
                return
            analysis = self._analyst.interpret_findings(
                findings, use_ai=True
            )
            chains = analysis.get("chains", [])
            if chains:
                self.logger.info(
                    f"AI detected {len(chains)} attack chain(s): "
                    f"{', '.join(c['name'] for c in chains[:3])}"
                )
        except Exception as e:
            self.logger.debug(f"AI analysis error: {e}")

    # ── Condition evaluation ──────────────────────────────────

    def _evaluate_condition(self, task: Task, mission: Mission) -> bool:
        """
        Evaluate a task's optional condition string.
        Simple evaluator — supports basic comparisons only.
        """
        condition = task.condition
        if not condition:
            return True

        # Very simple condition evaluator — no eval()
        # Supports: "phase_id.output_key != []"
        # and: "phase_id.output_key != null"
        try:
            if "!= []" in condition:
                key = condition.split("!=")[0].strip()
                parts = key.split(".")
                if len(parts) >= 2:
                    task_id = parts[0]
                    prev = mission.task_by_id(task_id)
                    if prev and prev.get("result"):
                        field = parts[1] if len(parts) > 1 else ""
                        value = prev["result"].get(field, [])
                        return bool(value)
            if "!= null" in condition:
                return True
        except Exception:
            pass
        return True

    # ── Abort decision ────────────────────────────────────────

    def _should_abort_on_failure(self, task: Task, mission: Mission) -> bool:
        """Decide whether a task failure should abort the mission."""
        # Only abort if task has on_failure=abort in plan
        plan_task = mission.task_by_id(task.id)
        if plan_task:
            return plan_task.get("on_failure") == "abort"
        return False

    # ── Progress events ───────────────────────────────────────

    def _emit_progress(
        self,
        mission: Mission,
        graph:   TaskGraph,
        task:    Task,
        status:  str,
    ):
        """Emit progress event to registered callback."""
        if not self._on_progress:
            return
        try:
            event = {
                "type":           "task_update",
                "task_id":        task.id,
                "task_name":      task.name,
                "task_status":    status,
                "mission_status": mission.status.value,
                "graph_summary":  graph.summary(),
                "findings_count": self.session.meta.findings_count,
                "risk_score":     self.session.meta.risk_score,
                "duration":       mission.duration_str(),
                "timestamp":      time.time(),
            }
            self._on_progress(event)
        except Exception as e:
            self.logger.debug(f"Progress callback error: {e}")

    # ── AI initialisation ─────────────────────────────────────

    def _init_ai(self, mission: Mission):
        """Lazily initialise AI components."""
        try:
            self._analyst   = FindingAnalyst(self.session, self.logger)
            self._tactician = Tactician(self.session, self.logger)
        except Exception as e:
            self.logger.warning(f"AI components unavailable: {e} — continuing without AI")

    # ── Summary ───────────────────────────────────────────────

    def _build_summary(self, mission: Mission, graph: TaskGraph) -> Dict:
        findings = self.session.get_findings()
        return {
            "mission_id":    mission.mission_id,
            "session_id":    self.session.meta.session_id,
            "target":        self.session.meta.target,
            "objective":     mission.objective,
            "mode":          mission.mode,
            "status":        mission.status.value,
            "duration":      mission.duration_str(),
            "graph_summary": graph.summary(),
            "findings": {
                "total":    len(findings),
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high":     sum(1 for f in findings if f.severity.value == "high"),
                "medium":   sum(1 for f in findings if f.severity.value == "medium"),
                "low":      sum(1 for f in findings if f.severity.value == "low"),
            },
            "risk_score":    self.session.meta.risk_score,
            "modules_run":   self.session.meta.modules_done,
            "gate_decisions":self.gate.get_audit_log(),
        }

    def _save_summary(self, summary: Dict, mission: Mission):
        """Save execution summary to session logs."""
        out = self.session.dir("logs") / f"execution_{mission.mission_id}.json"
        out.write_text(
            json.dumps(summary, indent=2, default=str),
            encoding="utf-8",
        )
        self.logger.info(f"Execution summary saved → {out}")
