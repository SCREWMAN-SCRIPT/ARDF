"""
ARDF Daemon Layer
──────────────────
Background services for continuous monitoring and scheduling.

Components
──────────
  monitor_daemon   Continuous background monitoring service
  scheduler        Cron-style mission scheduler
  alerter          Delta finding alerter
"""

from daemon.alerter import Alerter

__all__ = ["Alerter"]
