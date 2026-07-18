"""
core/task_graph.py
───────────────────
TaskGraph — dependency graph and execution ordering for mission tasks.

Responsibilities
────────────────
  - Build a directed acyclic graph from a task list
  - Topological sort respecting dependencies
  - Track task status through execution
  - Detect circular dependencies
  - Identify tasks ready to run (all deps satisfied)
"""

import json
import time
from enum    import Enum
from pathlib import Path
from typing  import Dict, Generator, List, Optional, Set

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Task status
# ─────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING   = "pending"
    READY     = "ready"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"
    BLOCKED   = "blocked"


# ─────────────────────────────────────────────────────────────
# Task
# ─────────────────────────────────────────────────────────────

class Task:
    """
    Single executable unit within a mission plan.
    """

    def __init__(self, task_dict: Dict):
        self.id          = task_dict["id"]
        self.name        = task_dict.get("name", self.id)
        self.module      = task_dict.get("module", "")
        self.function    = task_dict.get("function", "")
        self.args        = task_dict.get("args", {})
        self.depends_on  = task_dict.get("depends_on", [])
        self.priority    = task_dict.get("priority", 99)
        self.timeout     = task_dict.get("timeout", 3600)
        self.confirm     = task_dict.get("confirm", False)
        self.confirm_msg = task_dict.get("confirm_msg", "")
        self.condition   = task_dict.get("condition", "")
        self.tags        = task_dict.get("tags", [])
        self.status      = TaskStatus.PENDING
        self.start_time: Optional[float]  = None
        self.end_time:   Optional[float]  = None
        self.result:     Optional[Dict]   = None
        self.error:      Optional[str]    = None
        self.retries:    int              = 0
        self.max_retries: int             = task_dict.get("max_retries", 2)

    # ── State transitions ─────────────────────────────────────

    def mark_ready(self):
        self.status = TaskStatus.READY

    def mark_running(self):
        self.status     = TaskStatus.RUNNING
        self.start_time = time.time()

    def mark_completed(self, result: Optional[Dict] = None):
        self.status   = TaskStatus.COMPLETED
        self.end_time = time.time()
        self.result   = result or {}

    def mark_failed(self, error: str = ""):
        self.status   = TaskStatus.FAILED
        self.end_time = time.time()
        self.error    = error

    def mark_skipped(self, reason: str = ""):
        self.status = TaskStatus.SKIPPED
        self.error  = reason

    def mark_blocked(self):
        self.status = TaskStatus.BLOCKED

    # ── Computed properties ───────────────────────────────────

    @property
    def is_done(self) -> bool:
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.SKIPPED,
        )

    @property
    def succeeded(self) -> bool:
        return self.status == TaskStatus.COMPLETED

    @property
    def duration(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)

    @property
    def can_retry(self) -> bool:
        return self.retries < self.max_retries

    def to_dict(self) -> Dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "module":      self.module,
            "function":    self.function,
            "status":      self.status.value,
            "priority":    self.priority,
            "depends_on":  self.depends_on,
            "confirm":     self.confirm,
            "tags":        self.tags,
            "duration":    self.duration,
            "retries":     self.retries,
            "error":       self.error,
        }

    def __repr__(self) -> str:
        return f"<Task id={self.id} status={self.status.value} priority={self.priority}>"


# ─────────────────────────────────────────────────────────────
# TaskGraph
# ─────────────────────────────────────────────────────────────

class TaskGraph:
    """
    Directed acyclic graph of mission tasks.

    Builds from a plan dict, validates dependencies,
    and yields tasks in execution-ready order.
    """

    def __init__(
        self,
        plan:   Dict,
        logger: Optional[ARDFLogger] = None,
    ):
        self.plan   = plan
        self.logger = logger or get_logger("core.task_graph")
        self.tasks: Dict[str, Task] = {}
        self._build(plan.get("tasks", []))

    # ── Construction ──────────────────────────────────────────

    def _build(self, task_list: List[Dict]):
        """Build task objects and validate graph."""
        # Build task objects
        for task_dict in task_list:
            task = Task(task_dict)
            self.tasks[task.id] = task

        # Validate dependencies exist
        for task in self.tasks.values():
            for dep_id in task.depends_on:
                if dep_id not in self.tasks:
                    self.logger.warning(
                        f"Task {task.id} depends on unknown task {dep_id} — removing dependency"
                    )
                    task.depends_on = [d for d in task.depends_on if d != dep_id]

        # Check for circular dependencies
        cycles = self._detect_cycles()
        if cycles:
            self.logger.error(f"Circular dependencies detected: {cycles}")
            raise ValueError(f"Task graph has circular dependencies: {cycles}")

        # Mark initially ready tasks
        self._update_ready_status()

        self.logger.info(
            f"Task graph built | tasks={len(self.tasks)} | "
            f"ready={len(self.ready_tasks)}"
        )

    # ── Graph traversal ───────────────────────────────────────

    def topological_order(self) -> List[Task]:
        """
        Return tasks in topological order — dependencies first.
        Tasks at same level are sorted by priority (lower = first).
        """
        visited = set()
        result  = []

        def visit(task_id: str):
            if task_id in visited or task_id not in self.tasks:
                return
            visited.add(task_id)
            task = self.tasks[task_id]
            for dep_id in task.depends_on:
                visit(dep_id)
            result.append(task)

        # Visit all tasks sorted by priority
        for task_id in sorted(
            self.tasks.keys(),
            key=lambda tid: self.tasks[tid].priority
        ):
            visit(task_id)

        return result

    def execution_generator(self) -> Generator[Task, None, None]:
        """
        Yield tasks one at a time in dependency order.
        Skips tasks whose dependencies failed or were skipped.
        Respects task status updates between yields.
        """
        ordered = self.topological_order()
        for task in ordered:
            if task.is_done:
                continue
            # Check if dependencies are satisfied
            if self._deps_satisfied(task):
                task.mark_ready()
                yield task
            else:
                self.logger.warning(
                    f"Task {task.id} blocked — dependencies not satisfied"
                )
                task.mark_blocked()

    def next_ready(self) -> Optional[Task]:
        """Return the next task ready to run, or None."""
        self._update_ready_status()
        ready = sorted(
            [t for t in self.tasks.values() if t.status == TaskStatus.READY],
            key=lambda t: t.priority,
        )
        return ready[0] if ready else None

    # ── Status management ─────────────────────────────────────

    def _update_ready_status(self):
        """Mark all tasks ready whose dependencies are satisfied."""
        for task in self.tasks.values():
            if task.status == TaskStatus.PENDING:
                if self._deps_satisfied(task):
                    task.mark_ready()
                else:
                    task.status = TaskStatus.PENDING

    def _deps_satisfied(self, task: Task) -> bool:
        """Check if all dependencies of a task have completed."""
        for dep_id in task.depends_on:
            dep = self.tasks.get(dep_id)
            if dep is None:
                continue
            if dep.status == TaskStatus.FAILED:
                # Dependency failed → task is blocked
                return False
            if dep.status == TaskStatus.SKIPPED:
                # Dependency skipped → allow through (non-critical dep)
                continue
            if dep.status != TaskStatus.COMPLETED:
                # Dependency not done yet
                return False
        return True

    def _detect_cycles(self) -> List[str]:
        """Detect circular dependencies using DFS."""
        visited:     Set[str] = set()
        in_stack:    Set[str] = set()
        cycle_nodes: List[str] = []

        def dfs(task_id: str) -> bool:
            visited.add(task_id)
            in_stack.add(task_id)
            task = self.tasks.get(task_id)
            if not task:
                in_stack.discard(task_id)
                return False
            for dep_id in task.depends_on:
                if dep_id not in visited:
                    if dfs(dep_id):
                        cycle_nodes.append(dep_id)
                        return True
                elif dep_id in in_stack:
                    cycle_nodes.append(dep_id)
                    return True
            in_stack.discard(task_id)
            return False

        for task_id in self.tasks:
            if task_id not in visited:
                if dfs(task_id):
                    break

        return cycle_nodes

    # ── Computed views ────────────────────────────────────────

    @property
    def ready_tasks(self) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.READY]

    @property
    def pending_tasks(self) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]

    @property
    def completed_tasks(self) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]

    @property
    def failed_tasks(self) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.FAILED]

    @property
    def all_done(self) -> bool:
        return all(t.is_done for t in self.tasks.values())

    @property
    def has_failures(self) -> bool:
        return any(t.status == TaskStatus.FAILED for t in self.tasks.values())

    # ── Summary ───────────────────────────────────────────────

    def summary(self) -> Dict:
        return {
            "total":     len(self.tasks),
            "pending":   len(self.pending_tasks),
            "ready":     len(self.ready_tasks),
            "completed": len(self.completed_tasks),
            "failed":    len(self.failed_tasks),
            "skipped":   len([t for t in self.tasks.values() if t.status == TaskStatus.SKIPPED]),
            "blocked":   len([t for t in self.tasks.values() if t.status == TaskStatus.BLOCKED]),
        }

    def to_dict(self) -> Dict:
        return {
            "plan_id": self.plan.get("mission_id", ""),
            "summary": self.summary(),
            "tasks":   [t.to_dict() for t in self.topological_order()],
        }

    def __len__(self) -> int:
        return len(self.tasks)

    def __repr__(self) -> str:
        s = self.summary()
        return (
            f"<TaskGraph tasks={s['total']} "
            f"completed={s['completed']} "
            f"failed={s['failed']} "
            f"pending={s['pending']}>"
        )
