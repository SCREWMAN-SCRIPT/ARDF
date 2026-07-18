"""
daemon/scheduler.py
────────────────────
Scheduler — cron-style mission scheduler for ARDF.

Schedules recurring passive recon and monitoring jobs
against defined targets on a time interval.

All scheduled jobs are passive/read-only by default.
Any active testing requires explicit human confirmation
even when scheduled — the confirmation gate is never bypassed
by the scheduler.
"""

import json
import time
import threading
from datetime import datetime
from pathlib  import Path
from typing   import Callable, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Scheduled job
# ─────────────────────────────────────────────────────────────

class ScheduledJob:
    """A single recurring job definition."""

    def __init__(
        self,
        job_id:       str,
        target:       str,
        job_type:     str,
        interval_hrs: float,
        fn:           Callable,
        enabled:      bool = True,
    ):
        self.job_id       = job_id
        self.target       = target
        self.job_type     = job_type
        self.interval_hrs = interval_hrs
        self.fn           = fn
        self.enabled      = enabled
        self.last_run:    Optional[float] = None
        self.run_count:   int             = 0
        self.last_error:  Optional[str]   = None

    @property
    def next_run(self) -> Optional[float]:
        if self.last_run is None:
            return time.time()
        return self.last_run + (self.interval_hrs * 3600)

    @property
    def is_due(self) -> bool:
        if not self.enabled:
            return False
        if self.next_run is None:
            return True
        return time.time() >= self.next_run

    def to_dict(self) -> Dict:
        return {
            "job_id":       self.job_id,
            "target":       self.target,
            "job_type":     self.job_type,
            "interval_hrs": self.interval_hrs,
            "enabled":      self.enabled,
            "run_count":    self.run_count,
            "last_run":     datetime.fromtimestamp(self.last_run).isoformat()
                            if self.last_run else None,
            "next_run":     datetime.fromtimestamp(self.next_run).isoformat()
                            if self.next_run else None,
            "last_error":   self.last_error,
        }


# ─────────────────────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────────────────────

class Scheduler:
    """
    Cron-style job scheduler for recurring ARDF tasks.

    Supported job types (all passive/read-only by default):
      passive_recon  — subdomain enum, OSINT
      intel          — CVE enrichment, IOC extraction
      monitor        — local system monitoring
      report         — report regeneration

    Active jobs (recon depth=normal/depth, exploit) are
    never scheduled automatically — they require explicit
    human initiation each time.
    """

    PASSIVE_JOB_TYPES = {"passive_recon", "intel", "monitor", "report"}

    def __init__(
        self,
        state_path: Optional[Path] = None,
        logger:     Optional[ARDFLogger] = None,
    ):
        self.logger      = logger or get_logger("daemon.scheduler")
        self.state_path  = state_path or Path("logs/scheduler_state.json")
        self._jobs:      Dict[str, ScheduledJob] = {}
        self._running    = False
        self._thread:    Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._load_state()

    # ── Public API ────────────────────────────────────────────

    def add_job(
        self,
        job_id:       str,
        target:       str,
        job_type:     str,
        interval_hrs: float,
        fn:           Callable,
        enabled:      bool = True,
    ) -> ScheduledJob:
        """Register a new scheduled job."""
        if job_type not in self.PASSIVE_JOB_TYPES:
            raise ValueError(
                f"Job type '{job_type}' is not allowed for scheduling. "
                f"Only passive jobs can be scheduled: {self.PASSIVE_JOB_TYPES}"
            )

        job = ScheduledJob(
            job_id       = job_id,
            target       = target,
            job_type     = job_type,
            interval_hrs = interval_hrs,
            fn           = fn,
            enabled      = enabled,
        )
        self._jobs[job_id] = job
        self.logger.info(
            f"Job registered: {job_id} | "
            f"type={job_type} | "
            f"target={target} | "
            f"interval={interval_hrs}h"
        )
        self._save_state()
        return job

    def remove_job(self, job_id: str):
        """Remove a scheduled job."""
        if job_id in self._jobs:
            del self._jobs[job_id]
            self.logger.info(f"Job removed: {job_id}")
            self._save_state()

    def enable_job(self, job_id: str):
        if job_id in self._jobs:
            self._jobs[job_id].enabled = True
            self._save_state()

    def disable_job(self, job_id: str):
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
            self._save_state()

    def list_jobs(self) -> List[Dict]:
        return [j.to_dict() for j in self._jobs.values()]

    def start(self, blocking: bool = False):
        """Start the scheduler loop."""
        self._running = True
        self._stop_event.clear()
        self.logger.success(
            f"Scheduler started | jobs={len(self._jobs)}"
        )

        if blocking:
            self._run_loop()
        else:
            self._thread = threading.Thread(
                target = self._run_loop,
                daemon = True,
                name   = "ardf-scheduler",
            )
            self._thread.start()

    def stop(self):
        """Stop the scheduler."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._save_state()
        self.logger.info("Scheduler stopped")

    # ── Internal ──────────────────────────────────────────────

    def _run_loop(self):
        """Main scheduling loop — checks every 60 seconds."""
        while self._running and not self._stop_event.is_set():
            due = [j for j in self._jobs.values() if j.is_due]

            for job in due:
                self.logger.info(
                    f"Running scheduled job: {job.job_id} "
                    f"(type={job.job_type} target={job.target})"
                )
                try:
                    job.fn()
                    job.run_count += 1
                    job.last_run   = time.time()
                    job.last_error = None
                    self.logger.success(f"Job complete: {job.job_id}")
                except Exception as e:
                    job.last_error = str(e)
                    self.logger.error(f"Job {job.job_id} failed: {e}")
                finally:
                    self._save_state()

            self._stop_event.wait(timeout=60)

    def _save_state(self):
        """Persist scheduler state (metadata only, not callables)."""
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            state = {
                "jobs": [
                    {k: v for k, v in j.to_dict().items() if k != "fn"}
                    for j in self._jobs.values()
                ],
                "saved_at": datetime.utcnow().isoformat(),
            }
            self.state_path.write_text(
                json.dumps(state, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _load_state(self):
        """Load previously saved job metadata (no callables restored)."""
        if not self.state_path.exists():
            return
        try:
            state = json.loads(self.state_path.read_text())
            self.logger.debug(
                f"Scheduler state loaded from {self.state_path}"
            )
        except Exception:
            pass
