"""
playbook/executor.py
─────────────────────
PlaybookExecutor — converts a loaded playbook into a
mission plan and hands it to the orchestrator for execution.

All offensive phases still require human confirmation
through the ConfirmationGate before execution.
"""

import time
from pathlib import Path
from typing  import Dict, List, Optional

from playbook.loader    import PlaybookLoader
from playbook.validator import PlaybookValidator
from modules.session    import Session, new_session, Mode
from modules.logger     import get_logger, ARDFLogger


class PlaybookExecutor:
    """
    Converts a playbook dict into a mission plan.

    Usage
    ─────
        executor = PlaybookExecutor(session, logger)
        plan     = executor.build_plan(playbook)
    """

    def __init__(
        self,
        session: Session,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.session   = session
        self.logger    = logger or get_logger("playbook.executor")
        self.validator = PlaybookValidator(logger=self.logger)
        self.loader    = PlaybookLoader(logger=self.logger)

    # ── Public API ────────────────────────────────────────────

    def build_plan(self, playbook: Dict) -> Optional[Dict]:
        """
        Convert a playbook dict into an ARDF mission plan.

        Validates the playbook first — returns None if invalid.
        """
        # Validate
        valid, errors, warnings = self.validator.validate(playbook)

        if warnings:
            for w in warnings:
                self.logger.warning(f"Playbook warning: {w}")

        if not valid:
            for e in errors:
                self.logger.error(f"Playbook error: {e}")
            return None

        # Convert phases → task list
        phases = playbook.get("phases", [])
        mode   = playbook.get("mode", "red")

        # Use planner to convert playbook phases to task plan
        from ai.planner import MissionPlanner
        planner = MissionPlanner(session=self.session, logger=self.logger)
        plan    = planner.plan_from_playbook(phases=phases, mode=mode)

        # Inject playbook metadata
        plan["playbook_name"]    = playbook.get("name", "")
        plan["playbook_version"] = playbook.get("version", "1.0")
        plan["playbook_mode"]    = mode
        plan["objective"]        = playbook.get("description", f"{mode} playbook")
        plan["settings"]         = playbook.get("settings", {})
        plan["ai_decisions"]     = playbook.get("ai_decisions", {})

        self.logger.success(
            f"Playbook plan built | "
            f"name={playbook.get('name')} | "
            f"tasks={len(plan.get('tasks', []))} | "
            f"mode={mode}"
        )
        return plan

    def load_and_build(self, path_or_name: str) -> Optional[Dict]:
        """
        Load a playbook from disk and build its mission plan.
        Convenience method combining loader + build_plan.
        """
        try:
            playbook = self.loader.load(path_or_name)
            return self.build_plan(playbook)
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return None
        except Exception as e:
            self.logger.error(f"Playbook load failed: {e}")
            return None

    def list_playbooks(self) -> List[Dict]:
        """List all available playbooks."""
        return self.loader.list_available()
