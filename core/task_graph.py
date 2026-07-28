"""
core/task_graph.py
──────────────────
Task dependency graph with dynamic branching for ARDF.

Enhanced with dynamic branching:
  - Conditional task execution based on findings
  - Branch selection based on Cloudflare status
  - Parallel execution of independent tasks
  - Fallback branches on failure
  - Dynamic task generation from workflow state

The task graph manages dependencies and execution order
with support for branching based on runtime conditions.
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import deque
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

@dataclass
class TaskNode:
    """A node in the task dependency graph."""
    id: str
    name: str
    module: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: str = "always"
    branch: str = "main"
    is_branch_node: bool = False
    branches: List[str] = field(default_factory=list)
    confirmation_tier: int = 1
    critical: bool = False
    timeout: int = 3600
    retry_count: int = 0


@dataclass
class TaskGraph:
    """Complete task dependency graph."""
    name: str
    target: str
    nodes: List[TaskNode] = field(default_factory=list)
    branches: Dict[str, List[TaskNode]] = field(default_factory=dict)
    branch_conditions: Dict[str, str] = field(default_factory=dict)
    default_branch: str = "main"
    execution_order: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Task Graph Builder
# ─────────────────────────────────────────────────────────────

class TaskGraphBuilder:
    """
    Build task dependency graphs with dynamic branching.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("task_graph")
        self.nodes: List[TaskNode] = []
        self.branches: Dict[str, List[TaskNode]] = {}
        self.branch_conditions: Dict[str, str] = {}

    def add_task(
        self,
        id: str,
        name: str,
        module: str,
        action: str,
        depends_on: Optional[List[str]] = None,
        condition: str = "always",
        branch: str = "main",
        confirmation_tier: int = 1,
        critical: bool = False,
        params: Optional[Dict] = None
    ) -> None:
        """Add a task node to the graph."""
        node = TaskNode(
            id=id,
            name=name,
            module=module,
            action=action,
            params=params or {},
            depends_on=depends_on or [],
            condition=condition,
            branch=branch,
            confirmation_tier=confirmation_tier,
            critical=critical
        )
        self.nodes.append(node)

        # Add to branch
        if branch not in self.branches:
            self.branches[branch] = []
        self.branches[branch].append(node)

    def add_branch(self, name: str, condition: str, tasks: List[Dict]) -> None:
        """Add a conditional branch."""
        self.branch_conditions[name] = condition
        for task_data in tasks:
            self.add_task(
                branch=name,
                condition=condition,
                **task_data
            )

    def add_cloudflare_branches(self, target: str) -> None:
        """
        Add Cloudflare-specific branches.
        """
        # Main branch (no Cloudflare)
        self.add_branch("main", "always", [
            {"id": "recon_main", "name": "Standard Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "normal"}},
            {"id": "exploit_main", "name": "Standard Exploitation", "module": "exploit", "action": "run_exploit", "params": {"mode": "full"}}
        ])

        # Cloudflare branch
        self.add_branch("cloudflare", "cloudflare_detected", [
            {"id": "recon_cf", "name": "Cloudflare Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "normal"}},
            {"id": "bypass_cf", "name": "Cloudflare Bypass", "module": "bypass", "action": "run_bypass", "params": {"technique": "all"}},
            {"id": "origin_attack", "name": "Direct Origin Attack", "module": "workflow", "action": "direct_origin", "params": {"ip": "{{bypass_cf.best_candidate}}"}},
            {"id": "exploit_origin", "name": "Origin Exploitation", "module": "exploit", "action": "run_exploit", "params": {"mode": "full"}}
        ])

        # Fallback branch (bypass failed)
        self.add_branch("fallback", "bypass_failed", [
            {"id": "recon_fallback", "name": "Fallback Reconnaissance", "module": "recon", "action": "run_recon", "params": {"depth": "depth"}},
            {"id": "social_engineering", "name": "Social Engineering", "module": "redteam", "action": "social_engineering", "params": {"vector": "phishing"}},
            {"id": "supply_chain", "name": "Supply Chain Attack", "module": "redteam", "action": "supply_chain", "params": {}}
        ])

    def build(self) -> TaskGraph:
        """Build the complete task graph."""
        # Validate dependencies
        node_ids = {n.id for n in self.nodes}
        for node in self.nodes:
            for dep in node.depends_on:
                if dep not in node_ids:
                    self.logger.warning(f"Node {node.id} depends on missing node: {dep}")

        return TaskGraph(
            name="dynamic_task_graph",
            target="current",
            nodes=self.nodes,
            branches=self.branches,
            branch_conditions=self.branch_conditions,
            default_branch="main"
        )


# ─────────────────────────────────────────────────────────────
# Task Graph Executor
# ─────────────────────────────────────────────────────────────

class TaskGraphExecutor:
    """
    Execute task graph with dynamic branching.
    """

    def __init__(
        self,
        graph: TaskGraph,
        session: Session,
        logger: Optional[ARDFLogger] = None
    ):
        self.graph = graph
        self.session = session
        self.logger = logger or get_logger("task_graph")
        self.completed: Set[str] = set()
        self.failed: Set[str] = set()
        self.skipped: Set[str] = set()
        self.results: Dict[str, Any] = {}
        self.branch_selected: Optional[str] = None

    def evaluate_condition(self, condition: str) -> bool:
        """Evaluate a branch condition."""
        if condition == "always":
            return True

        # Cloudflare conditions
        if condition == "cloudflare_detected":
            # Check recon data
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

        if condition == "bypass_failed":
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    return not data.get("bypass_achieved", False)
                except Exception:
                    pass
            return False

        # Check if a specific task succeeded
        if condition.startswith("task_succeeded."):
            task_id = condition[15:]
            return task_id in self.completed

        # Check if a specific task failed
        if condition.startswith("task_failed."):
            task_id = condition[12:]
            return task_id in self.failed

        return True

    def select_branch(self, node: TaskNode) -> str:
        """
        Determine which branch to follow from a branch node.
        """
        if not node.is_branch_node or not node.branches:
            return node.branch

        for branch in node.branches:
            condition = self.graph.branch_conditions.get(branch, "never")
            if self.evaluate_condition(condition):
                self.branch_selected = branch
                return branch

        return self.graph.default_branch

    def get_ready_tasks(self) -> List[TaskNode]:
        """Get tasks ready for execution."""
        ready = []
        for node in self.graph.nodes:
            if node.id in self.completed or node.id in self.failed or node.id in self.skipped:
                continue

            # Check if all dependencies are satisfied
            deps_met = all(dep in self.completed for dep in node.depends_on)
            if not deps_met:
                continue

            # Check if task belongs to selected branch
            if node.is_branch_node:
                # Branch node itself is always ready if deps met
                ready.append(node)
            elif node.branch != self.branch_selected and self.branch_selected is not None:
                # Skip tasks not in selected branch
                self.skipped.add(node.id)
                continue

            ready.append(node)

        return ready

    def execute_task(self, node: TaskNode) -> Dict:
        """Execute a single task."""
        self.logger.info(f"Executing: {node.name} ({node.module}.{node.action})")

        # For branch nodes, just select branch
        if node.is_branch_node:
            selected = self.select_branch(node)
            self.logger.info(f"Branch selected: {selected}")
            return {"status": "branch", "selected": selected}

        try:
            module = __import__(f"modules.{node.module}", fromlist=[""])
            func = getattr(module, node.action)

            params = node.params.copy()
            params["session"] = self.session
            params["logger"] = self.logger

            # Add branch context
            params["branch"] = self.branch_selected
            params["completed_tasks"] = list(self.completed)

            result = func(**params)
            return {"status": "success", "result": result}
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Module/action not found: {node.module}.{node.action}")
            return {"status": "failed", "error": str(e)}
        except Exception as e:
            self.logger.error(f"Task failed: {e}")
            return {"status": "failed", "error": str(e)}

    def execute(self) -> Dict[str, Any]:
        """
        Execute the task graph.
        """
        self.logger.banner("TASK GRAPH EXECUTION", style="bold cyan")

        # Find branch nodes
        branch_nodes = [n for n in self.graph.nodes if n.is_branch_node]

        # Handle branch selection first
        for node in branch_nodes:
            if node.id in self.completed:
                continue
            result = self.execute_task(node)
            if result.get("status") == "branch":
                self.branch_selected = result.get("selected")
                self.completed.add(node.id)
                self.results[node.id] = result

        # Execute remaining tasks
        while True:
            ready = self.get_ready_tasks()
            if not ready:
                break

            for node in ready:
                result = self.execute_task(node)

                if result["status"] == "success":
                    self.completed.add(node.id)
                    self.results[node.id] = result
                elif result["status"] == "failed":
                    self.failed.add(node.id)
                    self.results[node.id] = result
                    if node.critical:
                        self.logger.error(f"Critical task failed: {node.id}")
                        return {"status": "failed", "task": node.id, "error": result.get("error")}
                else:
                    self.skipped.add(node.id)

        # Determine final status
        failed_count = len(self.failed)
        completed_count = len(self.completed)
        total = len(self.graph.nodes)

        return {
            "status": "completed" if failed_count == 0 else "partial_success",
            "total_tasks": total,
            "completed": completed_count,
            "failed": failed_count,
            "skipped": len(self.skipped),
            "branch_selected": self.branch_selected,
            "results": self.results
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def build_and_execute_graph(
    session: Session,
    target: str,
    logger: Optional[ARDFLogger] = None,
    include_cloudflare_branches: bool = True,
) -> Dict[str, Any]:
    """
    Build and execute a task graph with dynamic branching.

    Args:
        session: Active ARDF session
        target: Target domain/IP
        logger: ARDFLogger instance
        include_cloudflare_branches: Add Cloudflare-specific branches

    Returns:
        Execution results
    """
    if logger is None:
        logger = get_logger("task_graph")

    builder = TaskGraphBuilder(logger)

    # Add Cloudflare branches if requested
    if include_cloudflare_branches:
        builder.add_cloudflare_branches(target)

    # Add additional tasks
    builder.add_task(
        id="report_final",
        name="Generate Final Report",
        module="report",
        action="generate_report",
        depends_on=["recon_main", "exploit_main", "bypass_cf", "origin_attack", "exploit_origin"],
        condition="always",
        confirmation_tier=1
    )

    graph = builder.build()
    executor = TaskGraphExecutor(graph, session, logger)

    return executor.execute()