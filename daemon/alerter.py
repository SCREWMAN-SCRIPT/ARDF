"""
daemon/alerter.py
─────────────────
Alerter daemon for ARDF.

Enhanced with Cloudflare-aware alerts:
  - Alert on Cloudflare block events
  - Alert on rate limiting events
  - Alert on successful bypass
  - Alert on origin discovery
  - Threshold-based alerting

The alerter monitors findings and raises alerts
for critical events during the mission.
"""

import json
import time
from typing import Any, Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enumfrom modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# Alert Types
# ─────────────────────────────────────────────────────────────

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ALERT = "alert"
    CRITICAL = "critical"


class AlertType(Enum):
    CLOUDFLARE_DETECTED = "cloudflare_detected"
    CLOUDFLARE_BLOCK = "cloudflare_block"
    RATE_LIMITED = "rate_limited"
    BYPASS_SUCCESS = "bypass_success"
    BYPASS_FAILED = "bypass_failed"
    ORIGIN_FOUND = "origin_found"
    CRITICAL_VULN = "critical_vulnerability"
    EXPLOIT_SUCCESS = "exploit_success"
    MISSION_COMPLETE = "mission_complete"
    TASK_FAILED = "task_failed"


@dataclass
class Alert:
    """An alert raised by the system."""
    type: AlertType
    severity: AlertSeverity
    message: str
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False


# ─────────────────────────────────────────────────────────────
# Alerter Class
# ─────────────────────────────────────────────────────────────

class Alerter:
    """
    Alert monitoring with Cloudflare awareness.
    """

    def __init__(
        self,
        session: Session,
        logger: Optional[ARDFLogger] = None,
        alert_file: Optional[Path] = None
    ):
        self.session = session
        self.logger = logger or get_logger("alerter")
        self.alert_file = alert_file or session.dir("logs") / "alerts.jsonl"
        self.alert_file.parent.mkdir(parents=True, exist_ok=True)
        self.alerts: List[Alert] = []
        self._last_check = 0
        self._alerted_events: set = set()

    # ── Alert generation ─────────────────────────────────────

    def raise_alert(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        message: str,
        source: str = "",
        context: Dict = None
    ) -> Alert:
        """Raise a new alert."""
        alert = Alert(
            type=alert_type,
            severity=severity,
            message=message,
            source=source,
            context=context or {}
        )
        self.alerts.append(alert)
        self._save_alert(alert)

        # Log based on severity
        sev_log = {
            AlertSeverity.INFO: self.logger.info,
            AlertSeverity.WARNING: self.logger.warning,
            AlertSeverity.ALERT: self.logger.finding,
            AlertSeverity.CRITICAL: self.logger.critical
        }
        log_func = sev_log.get(severity, self.logger.info)
        log_func(f"[{alert_type.value}] {message}")

        return alert

    def _save_alert(self, alert: Alert) -> None:
        """Save alert to file."""
        try:
            with open(self.alert_file, "a") as f:
                f.write(json.dumps({
                    "type": alert.type.value,
                    "severity": alert.severity.value,
                    "message": alert.message,
                    "timestamp": alert.timestamp,
                    "source": alert.source,
                    "context": alert.context
                }) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to save alert: {e}")

    # ── Cloudflare-specific alerts ──────────────────────────

    def check_cloudflare(self, findings: List[Finding]) -> None:
        """Check findings for Cloudflare-related events."""
        for f in findings:
            # Check for Cloudflare detection
            if "cloudflare" in f.tags and "detected" in f.title.lower():
                self.raise_alert(
                    AlertType.CLOUDFLARE_DETECTED,
                    AlertSeverity.WARNING,
                    f"Cloudflare detected on {f.host}",
                    source="recon",
                    context={"host": f.host, "evidence": f.evidence[:100]}
                )

            # Check for Cloudflare block
            if "cloudflare" in f.tags and "block" in f.title.lower():
                self.raise_alert(
                    AlertType.CLOUDFLARE_BLOCK,
                    AlertSeverity.ALERT,
                    f"Cloudflare blocking access to {f.host}",
                    source="exploit",
                    context={"host": f.host, "evidence": f.evidence[:100]}
                )

            # Check for origin discovery
            if "origin" in f.tags and "candidate" in f.title.lower():
                self.raise_alert(
                    AlertType.ORIGIN_FOUND,
                    AlertSeverity.ALERT,
                    f"Origin IP discovered: {f.host}",
                    source="bypass",
                    context={"host": f.host, "evidence": f.evidence[:100]}
                )

            # Check for bypass success
            if "cloudflare" in f.tags and "bypass" in f.tags and "success" in f.title.lower():
                self.raise_alert(
                    AlertType.BYPASS_SUCCESS,
                    AlertSeverity.INFO,
                    f"Cloudflare bypass successful for {f.host}",
                    source="bypass",
                    context={"host": f.host}
                )

    def check_rate_limiting(self, findings: List[Finding]) -> None:
        """Check for rate limiting events."""
        for f in findings:
            if "rate" in f.tags and ("limit" in f.title.lower() or "429" in f.title.lower()):
                self.raise_alert(
                    AlertType.RATE_LIMITED,
                    AlertSeverity.WARNING,
                    f"Rate limiting detected on {f.host}",
                    source="exploit",
                    context={"host": f.host, "evidence": f.evidence[:100]}
                )

    def check_critical_vulnerabilities(self, findings: List[Finding]) -> None:
        """Alert on critical vulnerabilities."""
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                # Avoid duplicate alerts for same CVE
                alert_key = f"{f.cve or f.title}"
                if alert_key in self._alerted_events:
                    continue
                self._alerted_events.add(alert_key)

                self.raise_alert(
                    AlertType.CRITICAL_VULN,
                    AlertSeverity.CRITICAL,
                    f"Critical vulnerability: {f.title[:80]}",
                    source=f.source,
                    context={
                        "host": f.host,
                        "cve": f.cve,
                        "remediation": f.remediation,
                        "evidence": f.evidence[:100]
                    }
                )

    def check_task_status(self) -> None:
        """Check workflow task status."""
        state_path = self.session.dir("core") / "workflow_state.json"
        if not state_path.exists():
            return

        try:
            data = json.loads(state_path.read_text())
            failed = data.get("failed_tasks", [])
            completed = data.get("completed_tasks", [])

            # Alert on task failures
            for task in failed:
                if task not in self._alerted_events:
                    self._alerted_events.add(task)
                    self.raise_alert(
                        AlertType.TASK_FAILED,
                        AlertSeverity.WARNING,
                        f"Task failed: {task}",
                        source="orchestrator",
                        context={"task": task}
                    )

            # Alert on mission complete
            if data.get("status") == "completed" and "mission_complete" not in self._alerted_events:
                self._alerted_events.add("mission_complete")
                findings = self.session.get_findings()
                vuln_count = len([f for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)])
                self.raise_alert(
                    AlertType.MISSION_COMPLETE,
                    AlertSeverity.INFO,
                    f"Mission complete: {len(completed)} tasks, {vuln_count} high/critical findings",
                    source="orchestrator",
                    context={"completed": len(completed), "vulnerabilities": vuln_count}
                )

        except Exception as e:
            self.logger.warning(f"Error checking task status: {e}")

    # ── Main check loop ──────────────────────────────────────

    def check(self, findings: Optional[List[Finding]] = None) -> None:
        """Run all alert checks."""
        if findings is None:
            findings = self.session.get_findings()

        # Only check new findings since last check
        new_findings = []
        if self._last_check > 0:
            for f in findings:
                if f.timestamp > self._last_check:
                    new_findings.append(f)
        else:
            new_findings = findings

        if not new_findings:
            return

        self._last_check = time.time()

        # Cloudflare checks
        self.check_cloudflare(new_findings)

        # Rate limiting checks
        self.check_rate_limiting(new_findings)

        # Critical vulnerability checks
        self.check_critical_vulnerabilities(new_findings)

        # Task status checks
        self.check_task_status()

    def run_daemon(self, interval: float = 30.0) -> None:
        """
        Run alerter as a daemon.
        """
        self.logger.info("Starting alerter daemon...")
        try:
            while True:
                self.check()
                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Alerter daemon stopped")

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[AlertType] = None,
        limit: int = 50
    ) -> List[Alert]:
        """Get filtered alerts."""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.type == alert_type]
        return alerts[-limit:]

    def resolve_alert(self, alert_id: int) -> None:
        """Mark an alert as resolved."""
        if 0 <= alert_id < len(self.alerts):
            self.alerts[alert_id].resolved = True


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def run_alerter(
    session: Session,
    logger: Optional[ARDFLogger] = None,
    daemon: bool = False,
    interval: float = 30.0
) -> None:
    """
    Run the alerter.

    Args:
        session: Active ARDF session
        logger: ARDFLogger instance
        daemon: Run as daemon
        interval: Check interval in seconds
    """
    if logger is None:
        logger = get_logger("alerter")

    alerter = Alerter(session, logger)
    
    if daemon:
        alerter.run_daemon(interval)
    else:
        alerter.check()