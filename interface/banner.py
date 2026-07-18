"""
interface/banner.py
────────────────────
ASCII banner and startup display for ARDF.
"""

from datetime import datetime
from typing   import Dict, Optional

from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text
from rich.table   import Table
from rich.rule    import Rule

console = Console()

BANNER = r"""
    ___    ____  ____  ______
   /   |  / __ \/ __ \/ ____/
  / /| | / /_/ / / / / /_
 / ___ |/ _, _/ /_/ / __/
/_/  |_/_/ |_/_____/_/

"""

VERSION    = "1.0.0"
CODENAME   = "NightHawk"
BUILD_DATE = "2025"


def print_banner(mode: str = "red"):
    """Print the ARDF startup banner."""
    mode_colours = {
        "red":    "bold red",
        "blue":   "bold blue",
        "purple": "bold magenta",
        "osint":  "bold cyan",
    }
    colour = mode_colours.get(mode, "bold white")

    console.print(Text(BANNER, style=colour))

    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="dim")
    info_table.add_column(style="white")

    info_table.add_row("Version",  f"v{VERSION} — {CODENAME}")
    info_table.add_row("Mode",     mode.upper())
    info_table.add_row("Engine",   "Qwen2.5 / tinyllama (local)")
    info_table.add_row("Started",  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    console.print(
        Panel(
            info_table,
            title="[bold cyan]ARDF — Autonomous Red/Blue Defense Framework[/]",
            border_style="dim",
            padding=(1, 2),
        )
    )
    console.print()


def print_summary(metrics: Dict):
    """Print a mission summary table."""
    console.print(Rule("[bold green]MISSION SUMMARY[/]"))

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(style="dim", width=24)
    t.add_column(style="white")

    t.add_row("Target",       metrics.get("target", "—"))
    t.add_row("Status",       _colour_status(metrics.get("status", "—")))
    t.add_row("Duration",     metrics.get("duration", "—"))
    t.add_row("Findings",     str(metrics.get("findings", {}).get("total", 0)))
    t.add_row("  Critical",   f"[red]{metrics.get('findings',{}).get('critical',0)}[/]")
    t.add_row("  High",       f"[orange1]{metrics.get('findings',{}).get('high',0)}[/]")
    t.add_row("Risk Score",   str(metrics.get("risk_score", 0)))
    t.add_row("Modules Run",  ", ".join(metrics.get("modules_run", [])) or "—")

    console.print(t)
    console.print()


def _colour_status(status: str) -> str:
    colours = {
        "completed": "[bold green]completed[/]",
        "failed":    "[bold red]failed[/]",
        "aborted":   "[bold red]aborted[/]",
        "running":   "[bold yellow]running[/]",
        "paused":    "[bold yellow]paused[/]",
    }
    return colours.get(status.lower(), status)
