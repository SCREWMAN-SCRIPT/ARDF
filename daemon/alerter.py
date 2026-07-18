"""
daemon/alerter.py
──────────────────
Alerter — sends notifications when monitor anomalies are detected.

Alert channels
──────────────
  console   Rich terminal output (always enabled)
  file      JSON alert log (always enabled)
  callback  Custom callback function (optional)

All alerts are logged to session findings for report inclusion.
"""

import json
import time
from datetime import datetime
from pathlib  import Path
from typing   import Callable, Dict, List, Optional

from modules.session import Session, Finding, SeverityLevel
from modules.logger  import get_logger, ARDFLogger


class Alerter:
    """
    Sends and logs alerts from monitor anomalies.

    Every alert is:
      1. Printed to the console
      2. Written to the alert log file
      3. Added as a session finding
      4. Passed to the optional callback
    """

    def __init__(
        self,
        session:   Session,
        logger:    Optional[ARDFLogger] = None,
        on_alert:  Optional[Callable[[Dict], None]] = None,
        alert_path:Optional[Path] = None,
    ):
        self.session     = session
        self.logger      = logger or get_logger("daemon.alerter")
        self.on_alert    = on_alert
        self.alert_path  = alert_path or (
            session.dir("logs") / "alerts.jsonl"
        )
        self.alert_count = 0
        self._alerts:    List[Dict] = []

    # ── Public API ────────────────────────────────────────────

    def send(
        self,
        title:     str,
        anomalies: List[Dict],
        cycle:     int = 0,
    ):
        """
        Send alerts for a list of anomalies.

        Each anomaly becomes one alert entry and one session finding.
        """
        for anomaly in anomalies:
            alert = self._build_alert(title, anomaly, cycle)
            self._emit(alert)

    def send_delta(self, delta: Dict, cycle: int = 0):
        """Send alerts for a delta report (new ports, processes, etc)."""
        for port in delta.get("new_ports", []):
            self.send(
                title     = f"New open port detected: {port}",
                anomalies = [{
                    "type":    "new_port",
                    "port":    port,
                    "severity":"high",
                    "reason":  f"Port {port} opened since monitoring baseline",
                }],
                cycle=cycle,
            )

        for proc in delta.get("new_processes", [])[:5]:
            self.send(
                title     = f"New process detected: {proc.get('cmd','?')[:60]}",
                anomalies = [{
                    "type":    "new_process",
                    "pid":     proc.get("pid"),
                    "cmd":     proc.get("cmd","")[:200],
                    "severity":"low",
                    "reason":  f"New process since baseline: {proc.get('cmd','')[:60]}",
                }],
                cycle=cycle,
            )

    def get_all(self) -> List[Dict]:
        """Return all alerts sent in this session."""
        return self._alerts.copy()

    # ── Internal ──────────────────────────────────────────────

    def _build_alert(
        self,
        title:   str,
        anomaly: Dict,
        cycle:   int,
    ) -> Dict:
        sev_map = {
            "critical": "critical",
            "high":     "high",
            "medium":   "medium",
            "low":      "low",
        }
        severity = sev_map.get(
            anomaly.get("severity", "low").lower(), "low"
        )
        return {
            "alert_id":    f"alert_{self.alert_count + 1:04d}",
            "timestamp":   datetime.utcnow().isoformat(),
            "cycle":       cycle,
            "title":       title,
            "severity":    severity,
            "type":        anomaly.get("type", "unknown"),
            "reason":      anomaly.get("reason", ""),
            "detail":      anomaly,
            "target":      self.session.meta.target,
            "session_id":  self.session.meta.session_id,
        }

    def _emit(self, alert: Dict):
        """Emit alert to all channels."""
        self.alert_count += 1
        self._alerts.append(alert)

        # 1. Console
        self._print_alert(alert)

        # 2. File log
        self._write_alert(alert)

        # 3. Session finding
        self._create_finding(alert)

        # 4. Custom callback
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:
                self.logger.debug(f"Alert callback error: {e}")

    def _print_alert(self, alert: Dict):
        """Print alert to console using logger."""
        icons = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
        }
        icon = icons.get(alert["severity"], "⚪")
        self.logger.warning(
            f"{icon} ALERT [{alert['severity'].upper()}] "
            f"{alert['title']} — {alert['reason']}"
        )

    def _write_alert(self, alert: Dict):
        """Append alert to JSONL log file."""
        try:
            self.alert_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.alert_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception as e:
            self.logger.debug(f"Alert write error: {e}")

    def _create_finding(self, alert: Dict):
        """Add alert as a session finding."""
        sev_map = {
            "critical": SeverityLevel.CRITICAL,
            "high":     SeverityLevel.HIGH,
            "medium":   SeverityLevel.MEDIUM,
            "low":      SeverityLevel.LOW,
        }
        sev = sev_map.get(alert["severity"], SeverityLevel.LOW)
        try:
            self.session.add_finding(Finding(
                source      = "daemon.monitor",
                title       = f"[Alert] {alert['title']}",
                description = alert["reason"],
                severity    = sev,
                host        = self.session.meta.target,
                tags        = ["monitor", "daemon", "alert", alert["type"]],
                evidence    = json.dumps(alert["detail"], default=str)[:500],
            ))
        except Exception as e:
            self.logger.debug(f"Alert finding creation error: {e}")
