"""
interface/chat.py
──────────────────
Natural language command interface for ARDF.

Accepts plain-English objectives from the operator,
routes them through the AI planner, and hands the
resulting mission to the orchestrator.

All offensive tasks still require explicit confirmation
before execution — the chat interface does not bypass gates.
"""

import sys
from typing import Callable, Dict, List, Optional

from rich.console import Console
from rich.prompt  import Prompt
from rich.rule    import Rule
from rich.panel   import Panel
from rich.text    import Text

from modules.session import Session, new_session, Mode
from modules.logger  import get_logger, ARDFLogger

console = Console()


# ─────────────────────────────────────────────────────────────
# Built-in command registry
# ─────────────────────────────────────────────────────────────

BUILT_IN_HELP = """
[bold cyan]ARDF Natural Language Interface[/]

[dim]Built-in commands:[/]
  [white]help[/]                 Show this help
  [white]status[/]               Show current session status
  [white]findings[/]             List current findings summary
  [white]sessions[/]             List all sessions
  [white]quit / exit[/]          Exit ARDF

[dim]Example objectives:[/]
  [white]run a passive recon on example.com[/]
  [white]do a full web audit against target.com[/]
  [white]enumerate subdomains of company.org passively[/]
  [white]check example.com for SSL/TLS weaknesses[/]
  [white]generate a report for the current session[/]
  [white]run the blue team monitors[/]
  [white]run a purple team exercise on 10.0.0.1[/]

[dim]Modes are detected from your objective automatically.[/]
[dim]All active testing requires explicit confirmation before execution.[/]
"""


class ChatInterface:
    """
    Interactive natural language terminal interface.

    Operator types objectives in plain English.
    The AI planner converts them to mission plans.
    The orchestrator executes with confirmation gates.
    """

    def __init__(
        self,
        session:        Optional[Session] = None,
        logger:         Optional[ARDFLogger] = None,
        on_objective:   Optional[Callable[[str, Session], None]] = None,
    ):
        self.session      = session
        self.logger       = logger or get_logger("interface.chat")
        self.on_objective = on_objective
        self._history:    List[str] = []
        self._running:    bool = True

    # ── Public API ────────────────────────────────────────────

    def run(self):
        """Start the interactive chat loop."""
        console.print()
        console.print(Rule("[bold cyan]ARDF Command Interface[/]"))
        console.print(
            "[dim]Type your objective in plain English, or 'help' for commands.[/]"
        )
        if self.session:
            console.print(
                f"[dim]Active session: [white]{self.session.meta.session_id}[/] "
                f"target=[white]{self.session.meta.target}[/][/]"
            )
        console.print()

        while self._running:
            try:
                raw = Prompt.ask("[bold cyan]ardf[/]").strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Use 'quit' to exit.[/]")
                continue

            if not raw:
                continue

            self._history.append(raw)
            self._handle(raw)

    def handle_single(self, objective: str) -> bool:
        """
        Handle a single objective without entering the loop.
        Returns True if handled successfully.
        """
        return self._handle(objective)

    # ── Command routing ───────────────────────────────────────

    def _handle(self, raw: str) -> bool:
        """Route input to built-in command or AI objective handler."""
        lower = raw.lower().strip()

        # Built-in commands
        if lower in ("help", "?", "h"):
            console.print(Panel(BUILT_IN_HELP, border_style="dim"))
            return True

        if lower in ("quit", "exit", "q"):
            self._running = False
            console.print("[dim]Goodbye.[/]")
            return True

        if lower == "status":
            self._print_status()
            return True

        if lower == "findings":
            self._print_findings()
            return True

        if lower == "sessions":
            self._print_sessions()
            return True

        if lower.startswith("set target "):
            target = raw[len("set target "):].strip()
            self._set_target(target)
            return True

        if lower.startswith("set mode "):
            mode = raw[len("set mode "):].strip()
            self._set_mode(mode)
            return True

        # Everything else → treat as an objective
        return self._handle_objective(raw)

    # ── Objective handling ────────────────────────────────────

    def _handle_objective(self, objective: str) -> bool:
        """
        Handle a natural language objective.

        If a session exists, runs against it.
        If no session, extracts target from objective and creates one.
        """
        console.print(f"\n[dim]Objective:[/] [white]{objective}[/]")

        # Ensure we have a session
        if not self.session:
            target = self._extract_target(objective)
            if not target:
                console.print(
                    "[yellow]No active session. Please specify a target:[/]"
                )
                target = Prompt.ask("  Target").strip()
                if not target:
                    console.print("[red]No target provided — cancelled.[/]")
                    return False
            self._create_session(target, objective)

        if not self.session:
            console.print("[red]Failed to create session.[/]")
            return False

        # Delegate to registered callback (orchestrator)
        if self.on_objective:
            try:
                console.print(
                    f"[dim]Planning mission for: "
                    f"[white]{self.session.meta.target}[/][/]\n"
                )
                self.on_objective(objective, self.session)
                return True
            except Exception as e:
                self.logger.error(f"Objective handler failed: {e}")
                console.print(f"[red]Error: {e}[/]")
                return False

        # No callback — just acknowledge
        console.print(
            "[yellow]No execution handler registered. "
            "Use run_ardf.py to start ARDF with full orchestration.[/]"
        )
        return True

    # ── Session management ────────────────────────────────────

    def _create_session(self, target: str, objective: str):
        """Create a new session for the given target."""
        mode_str = self._detect_mode(objective)
        try:
            mode = Mode(mode_str)
        except ValueError:
            mode = Mode.FULL

        self.session = new_session(
            target = target,
            mode   = mode,
            name   = f"{target}_{mode_str}",
        )
        console.print(
            f"[green]Session created:[/] [white]{self.session.meta.session_id}[/] "
            f"target=[white]{target}[/] mode=[white]{mode_str}[/]"
        )

    def _set_target(self, target: str):
        """Switch or create session for a new target."""
        self._create_session(target, "")
        console.print(f"[green]Target set:[/] [white]{target}[/]")

    def _set_mode(self, mode_str: str):
        """Update session mode."""
        if not self.session:
            console.print("[yellow]No active session.[/]")
            return
        try:
            self.session.meta.mode = Mode(mode_str.lower())
            self.session.save()
            console.print(f"[green]Mode set:[/] [white]{mode_str}[/]")
        except ValueError:
            console.print(f"[red]Unknown mode: {mode_str}. Use: red / blue / full[/]")

    # ── Display helpers ───────────────────────────────────────

    def _print_status(self):
        """Print current session status."""
        if not self.session:
            console.print("[yellow]No active session.[/]")
            return
        m = self.session.meta
        console.print(Panel(
            f"[dim]Session ID:[/]  [white]{m.session_id}[/]\n"
            f"[dim]Target:[/]      [white]{m.target}[/]\n"
            f"[dim]Mode:[/]        [white]{m.mode.value}[/]\n"
            f"[dim]Status:[/]      [white]{m.status.value}[/]\n"
            f"[dim]Findings:[/]    [white]{m.findings_count}[/]\n"
            f"[dim]Risk Score:[/]  [white]{m.risk_score}[/]\n"
            f"[dim]Modules:[/]     [white]{', '.join(m.modules_done) or 'none'}[/]",
            title="[bold]Session Status[/]",
            border_style="dim",
        ))

    def _print_findings(self):
        """Print findings summary."""
        if not self.session:
            console.print("[yellow]No active session.[/]")
            return
        summary = self.session.findings_summary()
        console.print(Panel(
            "\n".join(
                f"[dim]{sev:<10}[/] [white]{cnt}[/]"
                for sev, cnt in summary.items()
                if cnt > 0
            ) or "[dim]No findings yet.[/]",
            title="[bold]Findings Summary[/]",
            border_style="dim",
        ))

    def _print_sessions(self):
        """Print all sessions."""
        from modules.session import get_manager
        sessions = get_manager().list_sessions()
        if not sessions:
            console.print("[dim]No sessions found.[/]")
            return
        from rich.table import Table
        t = Table(title="Sessions", border_style="dim")
        t.add_column("ID",       style="cyan",  no_wrap=True)
        t.add_column("Target",   style="white")
        t.add_column("Mode",     style="magenta")
        t.add_column("Status",   style="yellow")
        t.add_column("Findings", justify="right")
        t.add_column("Risk",     justify="right")
        for s in sessions[:20]:
            t.add_row(
                s.get("session_id","")[:20],
                s.get("target",""),
                s.get("mode",""),
                s.get("status",""),
                str(s.get("findings_count",0)),
                str(s.get("risk_score",0)),
            )
        console.print(t)

    # ── Utilities ─────────────────────────────────────────────

    def _extract_target(self, objective: str) -> Optional[str]:
        """Extract a target hostname or IP from an objective string."""
        import re
        # Domain pattern
        domain = re.search(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
            objective,
        )
        if domain:
            return domain.group(0)
        # IP pattern
        ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", objective)
        if ip:
            return ip.group(0)
        return None

    def _detect_mode(self, objective: str) -> str:
        obj = objective.lower()
        if any(k in obj for k in ("purple", "detect", "blue team")):
            return "purple"
        if any(k in obj for k in ("passive", "osint", "footprint")):
            return "red"
        if any(k in obj for k in ("harden", "monitor", "blue", "defend")):
            return "blue"
        return "full"
