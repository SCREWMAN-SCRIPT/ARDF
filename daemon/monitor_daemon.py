"""
daemon/monitor_daemon.py
─────────────────────────
MonitorDaemon — continuous background monitoring service.

Runs passive, read-only security monitors on a schedule.
Detects changes against a baseline and alerts on new findings.

All monitoring is READ-ONLY. No active scanning. No tool execution.
No outbound connections to the target. Only local system observation.
"""

import json
import time
import signal
import threading
from datetime  import datetime
from pathlib   import Path
from typing    import Dict, List, Optional, Callable

from modules.session import Session
from modules.logger  import get_logger, ARDFLogger
from daemon.alerter  import Alerter


class MonitorDaemon:
    """
    Background daemon that runs security monitors on a schedule.
    Reads local system state only — no active target scanning.
    """

    def __init__(
        self,
        session:        Session,
        interval_secs:  int = 300,
        logger:         Optional[ARDFLogger] = None,
        on_alert:       Optional[Callable] = None,
    ):
        self.session       = session
        self.interval      = interval_secs
        self.logger        = logger or get_logger("daemon.monitor")
        self.alerter       = Alerter(session=session, logger=self.logger, on_alert=on_alert)
        self._running      = False
        self._thread:      Optional[threading.Thread] = None
        self._stop_event   = threading.Event()
        self._baseline:    Dict = {}
        self._cycle_count: int  = 0
        self._state_path   = session.dir("logs") / "daemon_state.json"

        # Register signal handlers for clean shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    # ── Public API ────────────────────────────────────────────

    def start(self, blocking: bool = True):
        """Start the monitoring daemon."""
        self.logger.banner("MONITOR DAEMON STARTED", style="bold green")
        self.logger.info(
            f"Session={self.session.meta.session_id} | "
            f"Target={self.session.meta.target} | "
            f"Interval={self.interval}s"
        )
        self._running   = True
        self._stop_event.clear()

        # Capture initial baseline
        self._capture_baseline()

        if blocking:
            self._run_loop()
        else:
            self._thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="ardf-monitor",
            )
            self._thread.start()
            self.logger.success("Monitor daemon running in background")

    def stop(self):
        """Signal the daemon to stop after the current cycle."""
        self.logger.info("Monitor daemon stop requested")
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self._save_state()
        self.logger.success("Monitor daemon stopped")

    def status(self) -> Dict:
        """Return current daemon status."""
        return {
            "running":      self._running,
            "cycle_count":  self._cycle_count,
            "interval_secs":self.interval,
            "session_id":   self.session.meta.session_id,
            "target":       self.session.meta.target,
            "findings":     self.session.meta.findings_count,
            "alerts_sent":  self.alerter.alert_count,
        }

    # ── Main loop ─────────────────────────────────────────────

    def _run_loop(self):
        """Main monitoring loop."""
        while self._running and not self._stop_event.is_set():
            cycle_start = time.time()
            self._cycle_count += 1

            self.logger.info(
                f"Monitor cycle {self._cycle_count} | "
                f"{datetime.utcnow().strftime('%H:%M:%S UTC')}"
            )

            try:
                self._run_cycle()
            except Exception as e:
                self.logger.error(f"Monitor cycle failed: {e}")

            # Save state after each cycle
            self._save_state()

            # Wait for next cycle or stop signal
            elapsed = time.time() - cycle_start
            wait    = max(0, self.interval - elapsed)

            self.logger.debug(
                f"Cycle {self._cycle_count} complete in {elapsed:.1f}s | "
                f"next in {wait:.0f}s"
            )
            self._stop_event.wait(timeout=wait)

    def _run_cycle(self):
        """Run one monitoring cycle."""
        from modules.defense.monitor import SecurityMonitor
        monitor = SecurityMonitor(session=self.session, logger=self.logger)

        # Run read-only monitors
        results = {}
        monitors_to_run = [
            ("open_ports",        monitor.monitor_open_ports),
            ("failed_logins",     monitor.monitor_failed_logins),
            ("firewall_rules",    monitor.monitor_firewall),
            ("log_anomalies",     monitor.monitor_logs),
        ]

        # Run full set every 6th cycle only (less frequent)
        if self._cycle_count % 6 == 0:
            monitors_to_run += [
                ("processes",         monitor.monitor_processes),
                ("suid_files",        monitor.monitor_suid_files),
                ("patch_level",       monitor.monitor_patch_level),
            ]

        for name, fn in monitors_to_run:
            try:
                result       = fn()
                results[name]= result
                if result.anomalies:
                    self.alerter.send(
                        title    = f"Monitor anomaly: {name}",
                        anomalies= result.anomalies,
                        cycle    = self._cycle_count,
                    )
            except Exception as e:
                self.logger.debug(f"Monitor {name} error: {e}")

        # Delta detection against baseline
        self._check_deltas(results)

    def _capture_baseline(self):
        """Capture initial system state as baseline."""
        from modules.defense.monitor import SecurityMonitor
        monitor = SecurityMonitor(session=self.session, logger=self.logger)
        monitor.set_baseline()
        self._baseline = {
            "timestamp": datetime.utcnow().isoformat(),
            "captured":  True,
        }
        self.logger.success("Monitoring baseline captured")

    def _check_deltas(self, results: Dict):
        """Compare current state to baseline and flag changes."""
        from modules.defense.monitor import SecurityMonitor
        monitor = SecurityMonitor(session=self.session, logger=self.logger)
        try:
            delta = monitor.get_delta()
            if delta.get("new_ports"):
                self.alerter.send(
                    title    = "New open ports detected",
                    anomalies= [
                        {
                            "type":    "new_port",
                            "port":    p,
                            "severity":"high",
                            "reason":  f"Port {p} opened since baseline",
                        }
                        for p in delta["new_ports"]
                    ],
                    cycle=self._cycle_count,
                )
        except Exception as e:
            self.logger.debug(f"Delta check error: {e}")

    # ── State persistence ─────────────────────────────────────

    def _save_state(self):
        try:
            state = {
                "cycle_count":  self._cycle_count,
                "last_run":     datetime.utcnow().isoformat(),
                "running":      self._running,
                "alerts_sent":  self.alerter.alert_count,
            }
            self._state_path.write_text(
                json.dumps(state, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _handle_signal(self, signum, frame):
        """Handle OS signals for clean shutdown."""
        self.logger.info(f"Signal {signum} received — stopping daemon")
        self.stop()
