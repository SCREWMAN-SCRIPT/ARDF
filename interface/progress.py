"""
interface/progress.py
─────────────────────
Progress display for ARDF.

Enhanced with new phase display for SQLi and brute-force validation.
"""

import os
import sys
import time
import json
from typing import Any, Dict, List, Optional
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session


class ProgressDisplay:
    """Display progress with workflow state awareness."""

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("progress")
        self._last_state = None
        self._start_time = time.time()
        self._width = self._get_terminal_width()

    def _get_terminal_width(self) -> int:
        try:
            import shutil
            return shutil.get_terminal_size().columns
        except Exception:
            return 80

    def _get_cf_status(self) -> Dict:
        status = {"detected": False, "bypassed": False, "origin": None}
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            try:
                data = json.loads(recon_path.read_text())
                cf = data.get("cloudflare", {})
                status["detected"] = cf.get("detected", False)
            except Exception:
                pass
        bypass_path = self.session.dir("bypass") / "bypass_report.json"
        if bypass_path.exists():
            try:
                data = json.loads(bypass_path.read_text())
                status["bypassed"] = data.get("bypass_achieved", False)
                candidates = data.get("origin_candidates", [])
                if candidates:
                    status["origin"] = candidates[0]
            except Exception:
                pass
        return status

    def _get_workflow_state(self) -> Dict:
        state_path = self.session.dir("core") / "workflow_state.json"
        if state_path.exists():
            try:
                return json.loads(state_path.read_text())
            except Exception:
                pass
        return {}

    def _format_status(self, status: str) -> str:
        colors = {
            "pending": "\033[90m",
            "running": "\033[36m",
            "completed": "\033[32m",
            "failed": "\033[31m",
            "bypassing": "\033[33m",
            "waiting": "\033[93m",
            "paused": "\033[35m",
            "cancelled": "\033[31m"
        }
        color = colors.get(status, "\033[37m")
        return f"{color}{status}\033[0m"

    def display_header(self) -> None:
        target = self.session.meta.target
        mode = self.session.meta.mode.value.upper()
        cf_status = self._get_cf_status()

        print("\033[2J\033[H")
        print("\033[1m" + "=" * self._width + "\033[0m")
        print(f"\033[1mARDF Mission Progress\033[0m")
        print(f"  Target: \033[33m{target}\033[0m")
        print(f"  Mode: \033[36m{mode}\033[0m")
        print(f"  Cloudflare: {'🔴 Detected' if cf_status.get('detected') else '✅ Not detected'}")
        if cf_status.get('detected'):
            bypassed = cf_status.get('bypassed', False)
            print(f"  Bypass: {'✅ Achieved' if bypassed else '⏳ Pending'}")
            if cf_status.get('origin'):
                print(f"  Origin IP: \033[32m{cf_status['origin']}\033[0m")
        print("\033[1m" + "=" * self._width + "\033[0m")

    def display_phases(self, current_phase: str = None) -> None:
        phases = [
            "Initial",
            "Reconnaissance",
            "Bypass",
            "Exploitation",
            "SQLi Validation",
            "Brute-Force Validation",
            "Post-Exploit",
            "Reporting"
        ]
        phase_map = {
            "initial": 0,
            "reconnaissance": 1,
            "bypass": 2,
            "exploitation": 3,
            "sqli_validation": 4,
            "bruteforce_validation": 5,
            "post_exploit": 6,
            "reporting": 7
        }

        current_idx = phase_map.get(current_phase.lower(), 0) if current_phase else 0

        print("\n\033[1mWorkflow Phases:\033[0m")
        for i, phase in enumerate(phases):
            if i < current_idx:
                status = "✅"
                color = "\033[32m"
            elif i == current_idx:
                status = "▶"
                color = "\033[36m"
            else:
                status = "⏳"
                color = "\033[90m"
            print(f"  {color}{status} {phase}\033[0m")

    def display_tasks(self) -> None:
        state = self._get_workflow_state()
        completed = state.get("completed_tasks", [])
        failed = state.get("failed_tasks", [])
        current = state.get("current_task")
        total = len(completed) + len(failed) + (1 if current else 0)

        print(f"\n\033[1mTasks:\033[0m")
        print(f"  Completed: \033[32m{len(completed)}\033[0m")
        print(f"  Failed: \033[31m{len(failed)}\033[0m")
        if current:
            print(f"  Current: \033[36m{current}\033[0m")

        if total > 0:
            done = len(completed)
            pct = int(done / total * 100)
            bar_len = min(40, self._width - 20)
            filled = int(bar_len * pct / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"  [{bar}] {pct}%")

    def display_findings(self) -> None:
        findings = self.session.get_findings()
        if not findings:
            return

        counts = {}
        for f in findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1

        print("\n\033[1mFindings by Severity:\033[0m")
        sev_colors = {
            "critical": "\033[31m",
            "high": "\033[33m",
            "medium": "\033[93m",
            "low": "\033[36m",
            "info": "\033[37m"
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = counts.get(sev, 0)
            color = sev_colors.get(sev, "\033[37m")
            print(f"  {color}{sev.upper()}: {count}\033[0m")

    def display(self, current_phase: str = None) -> None:
        self.display_header()
        self.display_phases(current_phase)
        self.display_tasks()
        self.display_findings()

    def live_update(self, interval: float = 2.0) -> None:
        try:
            while True:
                state = self._get_workflow_state()
                phase = state.get("phase", "unknown")
                status = state.get("status", "pending")

                if status in ("completed", "failed", "cancelled"):
                    self.display(phase)
                    print(f"\n\033[1mMission {status}\033[0m")
                    break

                self.display(phase)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\033[33mProgress display interrupted\033[0m")


def show_progress(
    session: Session,
    logger: Optional[ARDFLogger] = None,
    live: bool = False,
    interval: float = 2.0
) -> None:
    if logger is None:
        logger = get_logger("progress")
    display = ProgressDisplay(session, logger)
    if live:
        display.live_update(interval)
    else:
        display.display()