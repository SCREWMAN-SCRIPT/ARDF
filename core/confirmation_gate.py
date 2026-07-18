"""
core/confirmation_gate.py
──────────────────────────
ConfirmationGate — human-in-the-loop checkpoint manager.

Every task marked confirm=True must pass through a gate
before execution. Gates can be:
  - Interactive (terminal prompt)
  - Non-interactive (CI/scripted mode — requires explicit opt-in)

Gates are NEVER bypassed silently. Any bypass must be
explicitly configured and logged with a warning.
"""

import time
import json
from datetime import datetime
from pathlib  import Path
from typing   import Dict, List, Optional

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Gate decision constants
# ─────────────────────────────────────────────────────────────

class GateDecision:
    APPROVED = "approved"
    DECLINED = "declined"
    TIMEOUT  = "timeout"
    SKIPPED  = "skipped"


# ─────────────────────────────────────────────────────────────
# ConfirmationGate
# ─────────────────────────────────────────────────────────────

class ConfirmationGate:
    """
    Human-in-the-loop checkpoint for mission tasks.

    Every sensitive task must pass through this gate
    before execution begins. All decisions are logged.
    """

    def __init__(
        self,
        logger:           Optional[ARDFLogger] = None,
        non_interactive:  bool = False,
        auto_approve:     bool = False,
        audit_path:       Optional[Path] = None,
        timeout_seconds:  int = 120,
    ):
        self.logger          = logger or get_logger("core.gate")
        self.non_interactive = non_interactive
        self.auto_approve    = auto_approve
        self.audit_path      = audit_path
        self.timeout_seconds = timeout_seconds
        self._decisions:     List[Dict] = []

        if auto_approve:
            self.logger.warning(
                "ConfirmationGate: AUTO-APPROVE enabled — "
                "all gates will be passed automatically. "
                "This mode is intended for authorised automated testing only."
            )

    # ── Public API ────────────────────────────────────────────

    def request(
        self,
        task_id:   str,
        task_name: str,
        target:    str,
        message:   str = "",
        tier:      int = 2,
    ) -> str:
        """
        Request human confirmation for a task.

        Args:
            task_id   : unique task identifier
            task_name : human-readable task name
            target    : assessment target
            message   : additional context for the operator
            tier      : confirmation tier (2=one-click, 3=typed CONFIRM)

        Returns:
            GateDecision constant (approved / declined / timeout)
        """
        self.logger.banner(
            f"CONFIRMATION REQUIRED — {task_name}",
            style="bold yellow",
        )

        if self.auto_approve:
            self.logger.warning(
                f"Gate AUTO-APPROVED for task: {task_name} "
                f"(auto_approve=True)"
            )
            decision = GateDecision.APPROVED
            self._record(task_id, task_name, target, tier, decision, "auto_approve")
            return decision

        if self.non_interactive:
            self.logger.warning(
                f"Gate DECLINED for task: {task_name} "
                f"(non_interactive=True, no auto_approve)"
            )
            decision = GateDecision.DECLINED
            self._record(task_id, task_name, target, tier, decision, "non_interactive_decline")
            return decision

        # Interactive confirmation
        if tier == 3:
            decision = self._tier3_gate(task_id, task_name, target, message)
        else:
            decision = self._tier2_gate(task_id, task_name, target, message)

        self._record(task_id, task_name, target, tier, decision, "interactive")
        return decision

    def request_batch(
        self,
        tasks: List[Dict],
        target: str,
    ) -> Dict[str, str]:
        """
        Request confirmation for multiple tasks at once.
        Returns dict of task_id → decision.
        """
        decisions = {}
        print(f"\n{'='*60}")
        print(f"  BATCH CONFIRMATION — {len(tasks)} tasks pending")
        print(f"  Target: {target}")
        print(f"{'='*60}")
        for i, task in enumerate(tasks, 1):
            print(f"  {i}. [{task.get('tags',[''])[0].upper()}] {task.get('name','Unknown')}")
        print(f"{'='*60}")
        choice = input("  Approve ALL? [yes/no/review]: ").strip().lower()
        print()

        if choice in ("yes", "y"):
            for task in tasks:
                tid = task["id"]
                decisions[tid] = GateDecision.APPROVED
                self._record(tid, task["name"], target, 2, GateDecision.APPROVED, "batch_approve")
                self.logger.info(f"Batch approved: {task['name']}")
        elif choice in ("review", "r"):
            for task in tasks:
                dec = self.request(
                    task_id   = task["id"],
                    task_name = task["name"],
                    target    = target,
                    message   = task.get("confirm_msg", ""),
                    tier      = 2,
                )
                decisions[task["id"]] = dec
        else:
            for task in tasks:
                tid = task["id"]
                decisions[tid] = GateDecision.DECLINED
                self._record(tid, task["name"], target, 2, GateDecision.DECLINED, "batch_decline")
                self.logger.info(f"Batch declined: {task['name']}")

        return decisions

    def get_audit_log(self) -> List[Dict]:
        """Return all gate decisions made in this session."""
        return self._decisions.copy()

    def save_audit_log(self, path: Optional[Path] = None):
        """Save gate decisions to an audit file."""
        out = path or self.audit_path
        if not out:
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self._decisions, indent=2, default=str),
            encoding="utf-8",
        )
        self.logger.info(f"Confirmation audit log saved → {out}")

    # ── Gate implementations ──────────────────────────────────

    def _tier2_gate(
        self,
        task_id:   str,
        task_name: str,
        target:    str,
        message:   str,
    ) -> str:
        """Tier 2 — single yes/no confirmation."""
        print(f"\n{'='*60}")
        print(f"  TASK CONFIRMATION")
        print(f"{'='*60}")
        print(f"  Task   : {task_name}")
        print(f"  Target : {target}")
        if message:
            print(f"  Info   : {message}")
        print(f"{'='*60}")
        print(f"  This action will run assessment tools against {target}")
        print(f"  Ensure you have written authorisation before proceeding.")
        print(f"{'='*60}")

        start = time.time()
        while True:
            if time.time() - start > self.timeout_seconds:
                print(f"\n  [TIMEOUT] No response in {self.timeout_seconds}s — declining")
                return GateDecision.TIMEOUT

            try:
                choice = input("  Proceed? [yes/no]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  [CANCELLED]")
                return GateDecision.DECLINED

            if choice in ("yes", "y"):
                print(f"  ✔ Approved: {task_name}\n")
                return GateDecision.APPROVED
            if choice in ("no", "n"):
                print(f"  ✘ Declined: {task_name}\n")
                return GateDecision.DECLINED
            print("  Please enter 'yes' or 'no'")

    def _tier3_gate(
        self,
        task_id:   str,
        task_name: str,
        target:    str,
        message:   str,
    ) -> str:
        """
        Tier 3 — typed CONFIRM required.
        Used for highest-impact operations.
        """
        print(f"\n{'='*60}")
        print(f"  HIGH-IMPACT TASK — TIER 3 CONFIRMATION REQUIRED")
        print(f"{'='*60}")
        print(f"  Task   : {task_name}")
        print(f"  Target : {target}")
        if message:
            print(f"  Info   : {message}")
        print(f"{'='*60}")
        print(f"  WARNING: This is a high-impact operation.")
        print(f"  Type CONFIRM (all caps) to proceed, or press Enter to cancel.")
        print(f"{'='*60}")

        start = time.time()
        while True:
            if time.time() - start > self.timeout_seconds:
                print(f"\n  [TIMEOUT] No response in {self.timeout_seconds}s — declining")
                return GateDecision.TIMEOUT

            try:
                choice = input("  Type CONFIRM to proceed: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  [CANCELLED]")
                return GateDecision.DECLINED

            if choice == "CONFIRM":
                print(f"  ✔ Confirmed: {task_name}\n")
                return GateDecision.APPROVED
            if choice == "":
                print(f"  ✘ Cancelled: {task_name}\n")
                return GateDecision.DECLINED
            print(f"  Type exactly: CONFIRM")

    # ── Audit ─────────────────────────────────────────────────

    def _record(
        self,
        task_id:  str,
        task_name:str,
        target:   str,
        tier:     int,
        decision: str,
        method:   str,
    ):
        """Record gate decision in audit log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "task_id":   task_id,
            "task_name": task_name,
            "target":    target,
            "tier":      tier,
            "decision":  decision,
            "method":    method,
        }
        self._decisions.append(entry)

        level = "success" if decision == GateDecision.APPROVED else "warning"
        msg   = (
            f"Gate {decision.upper()} | "
            f"task={task_name} | "
            f"target={target} | "
            f"tier={tier} | "
            f"method={method}"
        )
        if level == "success":
            self.logger.success(msg)
        else:
            self.logger.warning(msg)
