"""
core/mission.py
────────────────
Mission — the top-level unit of work in ARDF.

A mission wraps a session and owns the full lifecycle:
  created → planned → running → paused → completed | failed

Each mission has one objective, one target, one mode,
and an ordered task list produced by the planner.
"""

import json
import time
import uuid
from datetime import datetime
from enum     import Enum
from pathlib  import Path
from typing   import Any, Dict, List, Optional

from modules.session import Session, SessionStatus
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Mission status
# ─────────────────────────────────────────────────────────────

class MissionStatus(str, Enum):
    CREATED   = "created"
    PLANNED   = "planned"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    ABORTED   = "aborted"


# ─────────────────────────────────────────────────────────────
# Mission
# ─────────────────────────────────────────────────────────────

class Mission:
    """
    Top-level mission container.

    Wraps a Session and adds:
      - Objective tracking
      - Task plan storage
      - Lifecycle state machine
      - Execution metrics
      - Pause / resume support
    """

    def __init__(
        self,
        session:   Session,
        objective: str,
        mode:      str = "red",
        logger:    Optional[ARDFLogger] = None,
    ):
        self.session        = session
        self.objective      = objective
        self.mode           = mode
        self.logger         = logger or get_logger("core.mission")
        self.mission_id     = f"mission_{uuid.uuid4().hex[:8]}"
        self.status         = MissionStatus.CREATED
        self.plan:          Optional[Dict]  = None
        self.current_task:  Optional[str]   = None
        self.completed_tasks: List[str]     = []
        self.failed_tasks:    List[str]     = []
        self.skipped_tasks:   List[str]     = []
        self.start_time:    Optional[float] = None
        self.end_time:      Optional[float] = None
        self.metrics:       Dict[str, Any]  = {}
        self._pause_flag:   bool            = False
        self._abort_flag:   bool            = False

    # ── Lifecycle ─────────────────────────────────────────────

    def set_plan(self, plan: Dict):
        """Attach a task plan produced by MissionPlanner."""
        self.plan   = plan
        self.status = MissionStatus.PLANNED
        self.logger.success(
            f"Mission {self.mission_id} planned | "
            f"tasks={len(plan.get('tasks', []))} | "
            f"mode={self.mode}"
        )

    def start(self):
        """Mark mission as running."""
        self.status     = MissionStatus.RUNNING
        self.start_time = time.time()
        self.session.set_status(SessionStatus.RUNNING)
        self.logger.info(
            f"Mission {self.mission_id} started | "
            f"target={self.session.meta.target} | "
            f"objective={self.objective[:60]}"
        )

    def pause(self):
        """Request a pause after the current task completes."""
        self._pause_flag = True
        self.status      = MissionStatus.PAUSED
        self.session.set_status(SessionStatus.PAUSED)
        self.logger.warning(f"Mission {self.mission_id} paused")

    def resume(self):
        """Resume from pause."""
        self._pause_flag = False
        self.status      = MissionStatus.RUNNING
        self.session.set_status(SessionStatus.RUNNING)
        self.logger.info(f"Mission {self.mission_id} resumed")

    def abort(self, reason: str = ""):
        """Abort the mission immediately."""
        self._abort_flag = True
        self.status      = MissionStatus.ABORTED
        self.end_time    = time.time()
        self.session.set_status(SessionStatus.FAILED)
        self.logger.error(
            f"Mission {self.mission_id} aborted"
            + (f": {reason}" if reason else "")
        )

    def complete(self):
        """Mark mission as successfully completed."""
        self.status   = MissionStatus.COMPLETED
        self.end_time = time.time()
        self.session.set_status(SessionStatus.COMPLETED)
        self._compute_metrics()
        self.logger.success(
            f"Mission {self.mission_id} completed | "
            f"duration={self.duration_str()} | "
            f"findings={self.session.meta.findings_count} | "
            f"risk={self.session.meta.risk_score}"
        )

    def fail(self, reason: str = ""):
        """Mark mission as failed."""
        self.status   = MissionStatus.FAILED
        self.end_time = time.time()
        self.session.set_status(SessionStatus.FAILED)
        self.logger.error(
            f"Mission {self.mission_id} failed"
            + (f": {reason}" if reason else "")
        )

    # ── Task tracking ─────────────────────────────────────────

    def mark_task_running(self, task_id: str):
        self.current_task = task_id
        self.logger.info(f"Task running: {task_id}")

    def mark_task_complete(self, task_id: str):
        if task_id not in self.completed_tasks:
            self.completed_tasks.append(task_id)
        self.current_task = None
        self.logger.success(f"Task complete: {task_id}")

    def mark_task_failed(self, task_id: str, reason: str = ""):
        if task_id not in self.failed_tasks:
            self.failed_tasks.append(task_id)
        self.current_task = None
        self.logger.error(
            f"Task failed: {task_id}"
            + (f" — {reason}" if reason else "")
        )

    def mark_task_skipped(self, task_id: str, reason: str = ""):
        if task_id not in self.skipped_tasks:
            self.skipped_tasks.append(task_id)
        self.logger.warning(
            f"Task skipped: {task_id}"
            + (f" — {reason}" if reason else "")
        )

    # ── State checks ──────────────────────────────────────────

    @property
    def should_pause(self) -> bool:
        return self._pause_flag

    @property
    def should_abort(self) -> bool:
        return self._abort_flag

    @property
    def is_active(self) -> bool:
        return self.status in (MissionStatus.RUNNING, MissionStatus.PLANNED)

    @property
    def remaining_tasks(self) -> List[Dict]:
        if not self.plan:
            return []
        done = set(self.completed_tasks + self.failed_tasks + self.skipped_tasks)
        return [
            t for t in self.plan.get("tasks", [])
            if t["id"] not in done
        ]

    def task_by_id(self, task_id: str) -> Optional[Dict]:
        if not self.plan:
            return None
        for task in self.plan.get("tasks", []):
            if task["id"] == task_id:
                return task
        return None

    def all_tasks_done(self) -> bool:
        if not self.plan:
            return True
        total = len(self.plan.get("tasks", []))
        done  = (
            len(self.completed_tasks) +
            len(self.failed_tasks) +
            len(self.skipped_tasks)
        )
        return done >= total

    # ── Metrics ───────────────────────────────────────────────

    def _compute_metrics(self):
        """Compute final mission metrics."""
        duration = (
            self.end_time - self.start_time
            if self.start_time and self.end_time
            else 0
        )
        findings = self.session.get_findings()
        self.metrics = {
            "duration_seconds":  round(duration, 2),
            "total_findings":    len(findings),
            "critical_findings": sum(1 for f in findings if f.severity.value == "critical"),
            "high_findings":     sum(1 for f in findings if f.severity.value == "high"),
            "risk_score":        self.session.meta.risk_score,
            "tasks_completed":   len(self.completed_tasks),
            "tasks_failed":      len(self.failed_tasks),
            "tasks_skipped":     len(self.skipped_tasks),
            "modules_run":       self.session.meta.modules_done,
        }

    def duration_str(self) -> str:
        if not self.start_time:
            return "0s"
        elapsed = (self.end_time or time.time()) - self.start_time
        if elapsed < 60:
            return f"{elapsed:.0f}s"
        if elapsed < 3600:
            return f"{elapsed/60:.1f}m"
        return f"{elapsed/3600:.1f}h"

    # ── Serialisation ─────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            "mission_id":       self.mission_id,
            "session_id":       self.session.meta.session_id,
            "objective":        self.objective,
            "mode":             self.mode,
            "target":           self.session.meta.target,
            "status":           self.status.value,
            "start_time":       self.start_time,
            "end_time":         self.end_time,
            "duration":         self.duration_str(),
            "tasks_completed":  self.completed_tasks,
            "tasks_failed":     self.failed_tasks,
            "tasks_skipped":    self.skipped_tasks,
            "current_task":     self.current_task,
            "remaining_tasks":  len(self.remaining_tasks),
            "metrics":          self.metrics,
        }

    def save(self, output_dir: Optional[Path] = None):
        """Persist mission state to disk."""
        out = output_dir or self.session.dir("logs")
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"mission_{self.mission_id}.json"
        path.write_text(
            json.dumps(self.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

    def __repr__(self) -> str:
        return (
            f"<Mission id={self.mission_id} "
            f"status={self.status.value} "
            f"target={self.session.meta.target} "
            f"tasks={len(self.completed_tasks)}/{len(self.plan.get('tasks',[]) if self.plan else [])}>"
        )
