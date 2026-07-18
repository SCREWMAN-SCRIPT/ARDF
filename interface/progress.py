"""
interface/progress.py
──────────────────────
Live mission progress display using Rich.
"""

import time
from typing import Dict, List, Optional

from rich.console    import Console
from rich.live       import Live
from rich.table      import Table
from rich.panel      import Panel
from rich.progress   import (
    Progress, SpinnerColumn, TextColumn,
    BarColumn, TaskProgressColumn, TimeElapsedColumn,
)
from rich.layout     import Layout
from rich.text       import Text

console = Console()


class ProgressDisplay:
    """
    Live terminal progress display for mission execution.
    Shows task status, finding counts, and risk score in real time.
    """

    def __init__(self):
        self._events:      List[Dict] = []
        self._start_time:  float      = time.time()
        self._live:        Optional[Live] = None

    def on_event(self, event: Dict):
        """Callback for orchestrator progress events."""
        self._events.append(event)
        self._render_event(event)

    def _render_event(self, event: Dict):
        """Print a single progress event to console."""
        status    = event.get("task_status", "")
        task_name = event.get("task_name", "")
        findings  = event.get("findings_count", 0)
        risk      = event.get("risk_score", 0)
        duration  = event.get("duration", "")

        colour = {
            "completed": "green",
            "failed":    "red",
            "skipped":   "yellow",
            "running":   "cyan",
        }.get(status, "white")

        icon = {
            "completed": "✔",
            "failed":    "✘",
            "skipped":   "⊘",
            "running":   "►",
        }.get(status, "·")

        console.print(
            f"  [{colour}]{icon}[/] "
            f"[white]{task_name:<35}[/] "
            f"[{colour}]{status:<10}[/] "
            f"[dim]findings={findings} risk={risk:.0f} {duration}[/]"
        )

    def print_task_header(self, total_tasks: int, target: str):
        """Print the task execution header."""
        console.print()
        console.print(
            Panel(
                f"[bold cyan]Target:[/] {target}   "
                f"[bold cyan]Tasks:[/] {total_tasks}",
                title="[bold]Executing Mission[/]",
                border_style="dim",
            )
        )
        console.print(
            f"  [dim]{'Task':<35} {'Status':<10} Info[/]"
        )
        console.print(f"  [dim]{'─'*60}[/]")

    def print_finding(self, title: str, severity: str, host: str):
        """Print a new finding notification."""
        colours = {
            "critical": "bold red",
            "high":     "bold orange1",
            "medium":   "bold yellow",
            "low":      "bold blue",
            "info":     "dim",
        }
        colour = colours.get(severity.lower(), "white")
        icons  = {
            "critical": "🔴", "high": "🟠",
            "medium": "🟡", "low": "🔵", "info": "⚪",
        }
        icon = icons.get(severity.lower(), "·")
        console.print(
            f"  {icon} [{colour}]{severity.upper():<10}[/] "
            f"[white]{title[:50]}[/] "
            f"[dim]{host}[/]"
        )
