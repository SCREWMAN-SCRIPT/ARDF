"""
daemon/alerter.py
─────────────────
Alerter daemon for ARDF.

Enhanced with new alert types for SQLi and brute-force findings.
"""

import json
import time
from typing import Any, Dict, List, Optional
from pathlib import Path
from enum import Enum

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


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
    # NEW
    SQLI_FOUND = "sqli_found"
    SQLI_CONFIRMED = "sqli_confirmed"
    BRUTEFORCE_FOUND = "bruteforce_found"
    DEFAULT_CREDS_FOUND = "default_creds_found"


class Alert:
    def __init__(self, alert_type: AlertType, severity: AlertSeverity, message: str,
                 source: str = "", context: Dict = None):
        self.type = alert_type
        self.severity = severity
        self.message = message
        self.timestamp = time.time()
        self.source = source
        self.context = context or {}
        self.resolved = False


class Alerter:
    """Alert monitoring with Cloudflare and validation awareness."""

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("alerter")
        self.alert_file = session.dir("logs") / "alerts.jsonl"
        self.alert_file.parent.mkdir(parents=True, exist_ok=True)
        self.alerts: List[Alert] = []
        self._last_check = 0
        self._alerted_events: set = set()

    def raise_alert(self, alert_type: AlertType, severity: AlertSeverity,
                    message: str, source: str = "", context: Dict = None) -> Alert:
        alert = Alert(alert_type, severity, message, source, context)
        self.alerts.append(alert)
        self._save_alert(alert)

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

    # ── NEW: SQLi Alerts ──────────────────────────────────────

    def check_sqli(self, findings: List[Finding]) -> None:
        for f in findings:
            if "sqli" in f.tags or "injection" in f.tags:
                if "confirmed" in f.tags:
                    self.raise_alert(
                        AlertType.SQLI_CONFIRMED,
                        AlertSeverity.CRITICAL,
                        f"SQL injection confirmed: {f.title[:60]}",
                        source="validate.sqli",
                        context={"host": f.host, "cve": f.cve}
                    )
                elif "validated" in f.tags:
                    self.raise_alert(
                        AlertType.SQLI_FOUND,
                        AlertSeverity.ALERT,
                        f"SQL injection detected: {f.title[:60]}",
                        source="validate.sqli",
                        context={"host": f.host}
                    )

    # ── NEW: Brute-Force Alerts ───────────────────────────────

    def check_bruteforce(self, findings: List[Finding]) -> None:
        for f in findings:
            if "bruteforce" in f.tags:
                if "credentials" in f.tags:
                    self.raise_alert(
                        AlertType.BRUTEFORCE_FOUND,
                        AlertSeverity.CRITICAL,
                        f"Credentials found: {f.title[:60]}",
                        source="validate.auth",
                        context={"host": f.host}
                    )
                elif "default-creds" in f.tags:
                    self.raise_alert(
                        AlertType.DEFAULT_CREDS_FOUND,
                        AlertSeverity.CRITICAL,
                        f"Default credentials found: {f.title[:60]}",
                        source="validate.auth",
                        context={"host": f.host}
                    )

    # ── Existing Alert Methods ────────────────────────────────

    def check_cloudflare(self, findings: List[Finding]) -> None:
        for f in findings:
            if "cloudflare" in f.tags and "detected" in f.title.lower():
                self.raise_alert(
                    AlertType.CLOUDFLARE_DETECTED,
                    AlertSeverity.WARNING,
                    f"Cloudflare detected on {f.host}",
                    source="recon",
                    context={"host": f.host}
                )
            if "origin" in f.tags and "candidate" in f.title.lower():
                self.raise_alert(
                    AlertType.ORIGIN_FOUND,
                    AlertSeverity.ALERT,
                    f"Origin IP discovered: {f.host}",
                    source="bypass",
                    context={"host": f.host}
                )

    def check_critical_vulnerabilities(self, findings: List[Finding]) -> None:
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                alert_key = f"{f.cve or f.title}"
                if alert_key in self._alerted_events:
                    continue
                self._alerted_events.add(alert_key)
                self.raise_alert(
                    AlertType.CRITICAL_VULN,
                    AlertSeverity.CRITICAL,
                    f"Critical vulnerability: {f.title[:80]}",
                    source=f.source,
                    context={"host": f.host, "cve": f.cve}
                )

    def check_task_status(self) -> None:
        state_path = self.session.dir("core") / "workflow_state.json"
        if not state_path.exists():
            return

        try:
            data = json.loads(state_path.read_text())
            failed = data.get("failed_tasks", [])
            completed = data.get("completed_tasks", [])

            for task in failed:
                if task not in self._alerted_events:
                    self._alerted_events.add(task)
                    self.raise_alert(
                        AlertType.TASK_FAILED,
                        AlertSeverity.WARNING,
                        f"Task failed: {task}",
                        source="orchestrator"
                    )

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

    def check(self, findings: Optional[List[Finding]] = None) -> None:
        if findings is None:
            findings = self.session.get_findings()

        if self._last_check > 0:
            new_findings = [f for f in findings if f.timestamp > self._last_check]
        else:
            new_findings = findings

        if not new_findings:
            return

        self._last_check = time.time()

        # Run all checks
        self.check_cloudflare(new_findings)
        self.check_sqli(new_findings)
        self.check_bruteforce(new_findings)
        self.check_critical_vulnerabilities(new_findings)
        self.check_task_status()

    def run_daemon(self, interval: float = 30.0) -> None:
        self.logger.info("Starting alerter daemon...")
        try:
            while True:
                self.check()
                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Alerter daemon stopped")

    def get_alerts(self, severity: Optional[AlertSeverity] = None,
                   alert_type: Optional[AlertType] = None,
                   limit: int = 50) -> List[Alert]:
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.type == alert_type]
        return alerts[-limit:]


def run_alerter(session: Session, logger: Optional[ARDFLogger] = None,
                daemon: bool = False, interval: float = 30.0) -> None:
    if logger is None:
        logger = get_logger("alerter")
    alerter = Alerter(session, logger)
    if daemon:
        alerter.run_daemon(interval)
    else:
        alerter.check()