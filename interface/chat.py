"""
interface/chat.py
─────────────────
Interactive chat interface for ARDF.

Enhanced with Cloudflare-aware commands:
  - /bypass - Run Cloudflare bypass
  - /workflow - View current workflow state
  - /origin - Show discovered origin IPs
  - /cf-status - Check Cloudflare status
  - /adapt - Adapt workflow based on findings

Supports natural language commands with Cloudflare awareness.
"""

import os
import sys
import json
import time
import readline
import subprocess
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, SessionMode


# ─────────────────────────────────────────────────────────────
# Chat Interface
# ─────────────────────────────────────────────────────────────

class ChatInterface:
    """
    Interactive chat interface with Cloudflare-aware commands.
    """

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        history_file: Optional[Path] = None
    ):
        self.session = session
        self.logger = logger or get_logger("chat")
        self.history_file = history_file or Path.home() / ".ardf_chat_history"
        self.running = True
        self.context = {}
        self.commands = {
            "/help": self._cmd_help,
            "/bypass": self._cmd_bypass,
            "/workflow": self._cmd_workflow,
            "/origin": self._cmd_origin,
            "/cf-status": self._cmd_cf_status,
            "/adapt": self._cmd_adapt,
            "/findings": self._cmd_findings,
            "/report": self._cmd_report,
            "/status": self._cmd_status,
            "/config": self._cmd_config,
            "/clear": self._cmd_clear,
            "/exit": self._cmd_exit,
            "/quit": self._cmd_exit,
        }
        self._load_history()

    def _load_history(self) -> None:
        """Load command history."""
        if self.history_file.exists():
            try:
                readline.read_history_file(str(self.history_file))
            except Exception:
                pass

    def _save_history(self) -> None:
        """Save command history."""
        try:
            readline.write_history_file(str(self.history_file))
        except Exception:
            pass

    def _prompt(self) -> str:
        """Generate prompt string."""
        target = self.session.meta.target
        mode = self.session.meta.mode.value.upper()
        # Check if Cloudflare detected
        cf_status = self._get_cf_status()
        cf_indicator = " 🔥" if cf_status.get("detected") else ""
        return f"\033[36mardf({mode}){cf_indicator}\033[0m:\033[33m{target}\033[0m> "

    def _get_cf_status(self) -> Dict:
        """Get Cloudflare status from session."""
        status = {"detected": False, "bypassed": False, "origin": None}
        
        # Check recon data
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            try:
                data = json.loads(recon_path.read_text())
                cf = data.get("cloudflare", {})
                status["detected"] = cf.get("detected", False)
                status["version"] = cf.get("version")
            except Exception:
                pass
        
        # Check bypass data
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

    # ── Commands ─────────────────────────────────────────────

    def _cmd_help(self, args: List[str]) -> None:
        """Show help."""
        help_text = """
\033[1mARDF Chat Commands\033[0m

\033[36mCloudflare Commands:\033[0m
  /bypass               - Run Cloudflare bypass techniques
  /origin               - Show discovered origin IPs
  /cf-status            - Show Cloudflare detection status

\033[36mWorkflow Commands:\033[0m
  /workflow             - Show current workflow state
  /adapt                - Adapt workflow based on findings

\033[36mGeneral Commands:\033[0m
  /findings [count]     - Show recent findings
  /report               - Generate HTML report
  /status               - Show session status
  /config [key]         - Show configuration
  /clear                - Clear screen
  /exit, /quit          - Exit chat

\033[36mNatural Language:\033[0m
  You can also type natural language objectives:
  - "bypass Cloudflare for target.com"
  - "run adaptive workflow"
  - "show origin IPs"
  - "generate report"
"""
        print(help_text)

    def _cmd_bypass(self, args: List[str]) -> None:
        """Run Cloudflare bypass."""
        target = self.session.meta.target
        print(f"\033[33mRunning Cloudflare bypass for {target}...\033[0m")
        
        from modules.bypass import run_bypass
        try:
            result = run_bypass(target, self.session, self.logger)
            if result.get("bypass_achieved"):
                print(f"\033[32m✅ Bypass successful!\033[0m")
                print(f"  Origin candidates: {', '.join(result.get('origin_candidates', [])[:3])}")
                print(f"  Best candidate: {result.get('best_candidate', 'N/A')}")
                print(f"  Techniques succeeded: {', '.join([t for t, r in result.get('techniques', {}).items() if r.get('success')])}")
            else:
                print("\033[31m❌ Bypass failed. No origin candidates found.\033[0m")
                print("  Consider: social engineering, phishing, or supply chain attacks.")
        except Exception as e:
            print(f"\033[31mError: {e}\033[0m")

    def _cmd_workflow(self, args: List[str]) -> None:
        """Show current workflow state."""
        state_path = self.session.dir("core") / "workflow_state.json"
        if not state_path.exists():
            print("\033[33mNo workflow state found. Run a mission first.\033[0m")
            return

        try:
            data = json.loads(state_path.read_text())
            print("\033[1mWorkflow State\033[0m")
            print(f"  Status: {data.get('status', 'unknown')}")
            print(f"  Phase: {data.get('phase', 'unknown')}")
            print(f"  Bypass: {data.get('bypass_status', 'not_attempted')}")
            print(f"  Origin IP: {data.get('origin_ip', 'N/A')}")
            print(f"  WAF Type: {data.get('waf_type', 'N/A')}")
            print(f"  Completed: {len(data.get('completed_tasks', []))} tasks")
            print(f"  Failed: {len(data.get('failed_tasks', []))} tasks")
            if data.get('errors'):
                print(f"  Errors: {data['errors'][-3:]}")
        except Exception as e:
            print(f"\033[31mError reading workflow state: {e}\033[0m")

    def _cmd_origin(self, args: List[str]) -> None:
        """Show discovered origin IPs."""
        status = self._get_cf_status()
        if status.get("origin"):
            print(f"\033[32mOrigin IP: {status['origin']}\033[0m")
        else:
            # Check bypass report for all candidates
            bypass_path = self.session.dir("bypass") / "bypass_report.json"
            if bypass_path.exists():
                try:
                    data = json.loads(bypass_path.read_text())
                    candidates = data.get("origin_candidates", [])
                    if candidates:
                        print(f"\033[32mOrigin candidates:\033[0m")
                        for i, ip in enumerate(candidates[:10], 1):
                            print(f"  {i}. {ip}")
                        if len(candidates) > 10:
                            print(f"  ... and {len(candidates) - 10} more")
                    else:
                        print("\033[33mNo origin candidates found.\033[0m")
                except Exception:
                    print("\033[33mNo origin data available.\033[0m")
            else:
                print("\033[33mRun /bypass first to discover origin IPs.\033[0m")

    def _cmd_cf_status(self, args: List[str]) -> None:
        """Show Cloudflare detection status."""
        status = self._get_cf_status()
        
        print("\033[1mCloudflare Status\033[0m")
        print(f"  Detected: {'✅' if status.get('detected') else '❌'}")
        if status.get('version'):
            print(f"  Version: {status['version']}")
        print(f"  Bypassed: {'✅' if status.get('bypassed') else '❌'}")
        print(f"  Origin IP: {status.get('origin', 'N/A')}")

        # Check if we have bypass data
        bypass_path = self.session.dir("bypass") / "bypass_report.json"
        if bypass_path.exists():
            try:
                data = json.loads(bypass_path.read_text())
                techs = data.get("techniques", {})
                print(f"\n  \033[1mTechnique Results:\033[0m")
                for name, result in techs.items():
                    status_icon = "✅" if result.get("success") else "❌"
                    ip = result.get("origin_ip", "")
                    print(f"    {status_icon} {name}: {ip or 'failed'}")
            except Exception:
                pass

    def _cmd_adapt(self, args: List[str]) -> None:
        """Adapt workflow based on findings."""
        print("\033[33mAdapting workflow based on current findings...\033[0m")

        # Load tactical decision
        decision_path = self.session.dir("ai") / "tactical_decision.json"
        if decision_path.exists():
            try:
                data = json.loads(decision_path.read_text())
                print("\033[1mTactical Decision:\033[0m")
                print(f"  Recommendation: {data.get('decision', {}).get('recommendation', 'N/A')}")
                
                # Show bypass suggestions
                bypass_suggest = data.get("decision", {}).get("bypass", {})
                if bypass_suggest:
                    print(f"\n  \033[1mBypass Suggestions:\033[0m")
                    print(f"    Estimated success: {bypass_suggest.get('estimated_success_rate', 0) * 100:.0f}%")
                    print(f"    Priority order: {', '.join(bypass_suggest.get('priority_order', [])[:5])}")
            except Exception:
                pass
        
        print("\033[33mUse /workflow to see current state and /bypass to attempt bypass.\033[0m")

    def _cmd_findings(self, args: List[str]) -> None:
        """Show recent findings."""
        count = 10
        if args:
            try:
                count = int(args[0])
            except ValueError:
                pass

        findings = self.session.get_findings()[-count:]
        if not findings:
            print("\033[33mNo findings yet.\033[0m")
            return

        print(f"\033[1mRecent {len(findings)} findings:\033[0m")
        for f in findings:
            sev_colors = {
                "critical": "\033[31m",
                "high": "\033[33m",
                "medium": "\033[93m",
                "low": "\033[36m",
                "info": "\033[37m"
            }
            color = sev_colors.get(f.severity.value, "\033[37m")
            print(f"  {color}[{f.severity.value.upper()}]\033[0m {f.title[:60]}")
            if f.host:
                print(f"    Host: {f.host}")
            if f.cve:
                print(f"    CVE: {f.cve}")

    def _cmd_report(self, args: List[str]) -> None:
        """Generate report."""
        print("\033[33mGenerating report...\033[0m")
        from modules.report import generate_report
        try:
            report_path = generate_report(
                session=self.session,
                logger=self.logger,
                open_browser=False,
                purple_mode=self.session.meta.mode.value == "purple"
            )
            print(f"\033[32m✅ Report generated: {report_path}\033[0m")
        except Exception as e:
            print(f"\033[31mError generating report: {e}\033[0m")

    def _cmd_status(self, args: List[str]) -> None:
        """Show session status."""
        meta = self.session.meta
        print("\033[1mSession Status\033[0m")
        print(f"  ID: {meta.session_id}")
        print(f"  Target: {meta.target}")
        print(f"  Mode: {meta.mode.value.upper()}")
        print(f"  Status: {meta.status.value}")
        print(f"  Findings: {meta.findings_count}")
        print(f"  Risk Score: {meta.risk_score:.0f}")
        print(f"  Modules: {', '.join(meta.modules_done) or 'None'}")
        print(f"  Created: {meta.created_at}")

    def _cmd_config(self, args: List[str]) -> None:
        """Show configuration."""
        config_path = Path("config/ardf.yaml")
        if not config_path.exists():
            print("\033[33mConfig file not found.\033[0m")
            return

        try:
            import yaml
            data = yaml.safe_load(config_path.read_text())
            
            if args:
                # Show specific key
                key = args[0]
                parts = key.split(".")
                value = data
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        break
                if value is not None:
                    print(f"\033[36m{key}\033[0m = {json.dumps(value, indent=2)}")
                else:
                    print(f"\033[33mKey '{key}' not found.\033[0m")
            else:
                # Show relevant sections
                relevant = ["recon", "bypass", "workflow", "redteam", "cloudflare"]
                print("\033[1mConfiguration (relevant sections):\033[0m")
                for section in relevant:
                    if section in data:
                        print(f"\n  \033[36m{section}:\033[0m")
                        print(json.dumps(data[section], indent=4))
        except Exception as e:
            print(f"\033[31mError reading config: {e}\033[0m")

    def _cmd_clear(self, args: List[str]) -> None:
        """Clear screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _cmd_exit(self, args: List[str]) -> None:
        """Exit chat."""
        self.running = False
        print("\033[36mGoodbye!\033[0m")

    # ── Natural language handling ────────────────────────────

    def _handle_natural_language(self, text: str) -> bool:
        """Handle natural language commands."""
        text_lower = text.lower()

        if "bypass" in text_lower and ("cloudflare" in text_lower or "cf" in text_lower):
            self._cmd_bypass([])
            return True

        if "workflow" in text_lower:
            self._cmd_workflow([])
            return True

        if "origin" in text_lower or "origin ip" in text_lower:
            self._cmd_origin([])
            return True

        if "cf status" in text_lower or "cloudflare status" in text_lower:
            self._cmd_cf_status([])
            return True

        if "adapt" in text_lower:
            self._cmd_adapt([])
            return True

        if "report" in text_lower or "generate report" in text_lower:
            self._cmd_report([])
            return True

        if "findings" in text_lower:
            self._cmd_findings([])
            return True

        if "status" in text_lower:
            self._cmd_status([])
            return True

        if "help" in text_lower:
            self._cmd_help([])
            return True

        return False

    # ── Run ──────────────────────────────────────────────────

    def run(self) -> None:
        """Run the chat interface."""
        print("\033[36m" + r"""
   ___  ____  ______   ____
  / _ \/ __ \/ ____/  / __ \____  __
 /  __/ / / / / __   / / / / __ \/ /
/ /__/ /_/ / /_/ /  / /_/ / /_/ / /
\___/\____/\____/  /_____/\____/_/
                                   \033[0m")
        print("\033[1mARDF Chat Interface\033[0m")
        print("Type \033[36m/help\033[0m for commands or use natural language.")
        print("Type \033[36m/exit\033[0m to quit.\n")

        while self.running:
            try:
                user_input = input(self._prompt()).strip()
                if not user_input:
                    continue

                self._save_history()

                # Handle commands
                if user_input.startswith("/"):
                    parts = user_input.split()
                    cmd = parts[0].lower()
                    args = parts[1:] if len(parts) > 1 else []

                    if cmd in self.commands:
                        self.commands[cmd](args)
                    else:
                        print(f"\033[33mUnknown command: {cmd}\033[0m")
                        print("Type /help for available commands")
                else:
                    # Natural language
                    if not self._handle_natural_language(user_input):
                        print("\033[33mCould not understand. Try /help or be more specific.\033[0m")

            except KeyboardInterrupt:
                print("\n")
                self._cmd_exit([])
            except EOFError:
                print("\n")
                self._cmd_exit([])
            except Exception as e:
                print(f"\033[31mError: {e}\033[0m")


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_chat(
    session: Session,
    logger: Optional[ARDFLogger] = None
) -> None:
    """
    Run the chat interface.
    """
    if logger is None:
        logger = get_logger("chat")
    chat = ChatInterface(session, logger)
    chat.run()