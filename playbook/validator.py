"""
playbook/validator.py
──────────────────────
PlaybookValidator — validates playbook structure and content.
Ensures playbooks meet schema requirements before execution.
"""

from typing import Dict, List, Optional, Tuple
from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Required and optional fields
# ─────────────────────────────────────────────────────────────

REQUIRED_TOP_LEVEL = ["name", "version", "mode", "phases"]
VALID_MODES        = ["red", "blue", "purple", "osint", "full"]
REQUIRED_PHASE     = ["id", "name", "module", "function"]

VALID_MODULES = [
    "modules.recon",
    "modules.exploit",
    "modules.intel",
    "modules.report",
    "modules.defense.monitor",
    "modules.defense.hardening",
    "modules.defense.sigma_writer",
    "modules.defense.remediation",
    "modules.purple.purple_runner",
    "modules.purple.coverage_mapper",
]

VALID_ON_FAILURE = ["continue", "abort", "skip"]


class PlaybookValidator:
    """
    Validates playbook structure before execution.

    Returns a list of errors and warnings.
    A playbook with errors cannot be executed.
    A playbook with only warnings can proceed.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("playbook.validator")

    def validate(self, playbook: Dict) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a playbook dict.

        Returns:
            (valid, errors, warnings)
            valid   — True if playbook can be executed
            errors  — blocking issues
            warnings— non-blocking issues
        """
        errors:   List[str] = []
        warnings: List[str] = []

        # ── Top-level required fields ─────────────────────────
        for field in REQUIRED_TOP_LEVEL:
            if field not in playbook:
                errors.append(f"Missing required field: '{field}'")

        if errors:
            return False, errors, warnings

        # ── Mode validation ───────────────────────────────────
        mode = playbook.get("mode", "")
        if mode not in VALID_MODES:
            errors.append(
                f"Invalid mode: '{mode}'. "
                f"Must be one of: {VALID_MODES}"
            )

        # ── Phases validation ─────────────────────────────────
        phases = playbook.get("phases", [])
        if not phases:
            errors.append("Playbook has no phases defined")

        phase_ids = set()
        for i, phase in enumerate(phases):
            phase_errors, phase_warnings = self._validate_phase(
                phase, i, phase_ids
            )
            errors.extend(phase_errors)
            warnings.extend(phase_warnings)
            if "id" in phase:
                phase_ids.add(phase["id"])

        # ── Dependency validation ─────────────────────────────
        for phase in phases:
            for dep in phase.get("depends_on", []):
                if dep not in phase_ids:
                    errors.append(
                        f"Phase '{phase.get('id')}' depends on "
                        f"unknown phase '{dep}'"
                    )

        # ── Settings validation ───────────────────────────────
        settings = playbook.get("settings", {})
        max_hours = settings.get("max_duration_hours", 0)
        if max_hours and max_hours > 48:
            warnings.append(
                f"max_duration_hours={max_hours} is very long — "
                f"consider breaking into smaller playbooks"
            )

        valid = len(errors) == 0

        if valid:
            self.logger.success(
                f"Playbook '{playbook.get('name')}' valid | "
                f"phases={len(phases)} warnings={len(warnings)}"
            )
        else:
            self.logger.error(
                f"Playbook '{playbook.get('name')}' invalid | "
                f"errors={len(errors)}"
            )

        return valid, errors, warnings

    def _validate_phase(
        self,
        phase:     Dict,
        index:     int,
        known_ids: set,
    ) -> Tuple[List[str], List[str]]:
        errors:   List[str] = []
        warnings: List[str] = []
        label = phase.get("id", f"phase[{index}]")

        for field in REQUIRED_PHASE:
            if field not in phase:
                errors.append(f"Phase '{label}' missing required field: '{field}'")

        # Module must be in known list
        module = phase.get("module", "")
        if module and module not in VALID_MODULES:
            warnings.append(
                f"Phase '{label}' uses non-standard module: '{module}'"
            )

        # Duplicate ID check
        phase_id = phase.get("id")
        if phase_id and phase_id in known_ids:
            errors.append(f"Duplicate phase ID: '{phase_id}'")

        # on_failure validation
        on_failure = phase.get("on_failure", "continue")
        if on_failure not in VALID_ON_FAILURE:
            warnings.append(
                f"Phase '{label}' has unknown on_failure: '{on_failure}'"
            )

        # Timeout sanity
        timeout = phase.get("timeout_minutes", 0)
        if timeout and timeout > 480:
            warnings.append(
                f"Phase '{label}' timeout={timeout}m is very long"
            )

        return errors, warnings

    def print_report(
        self,
        valid:    bool,
        errors:   List[str],
        warnings: List[str],
    ):
        """Print validation report to console."""
        from rich.console import Console
        from rich.panel   import Panel
        con = Console()

        lines = []
        if errors:
            lines.append("[bold red]ERRORS (must fix):[/]")
            for e in errors:
                lines.append(f"  [red]✘[/] {e}")
        if warnings:
            lines.append("[bold yellow]WARNINGS:[/]")
            for w in warnings:
                lines.append(f"  [yellow]⚠[/] {w}")
        if valid and not warnings:
            lines.append("[bold green]✔ Playbook is valid[/]")

        status = "[bold green]VALID[/]" if valid else "[bold red]INVALID[/]"
        con.print(Panel(
            "\n".join(lines) if lines else "[green]All checks passed[/]",
            title=f"Playbook Validation — {status}",
            border_style="dim",
        ))
